"""``merkl treasury init`` — the five-minute setup, without a ledger or a notary.

The XRPL calls are replaced by fakes that behave the way rippled does: the
faucet hands back real wallets, ``account_info`` reports an account that does not
exist and then one that does, and the three transactions return hashes. The
notary is an ``httpx.MockTransport``. Everything else — the keystore, the agent
keys, the seed file, the relay tokens, the bundle — is the real thing writing
real files, because *where the files land* is what this phase changed.

Two properties are checked over and over and are the point of the whole command:

* nothing it writes lands outside ``<home>`` and ``--agent-dir``;
* nothing it prints is a secret. Not a seed, not a PEM body, not a token.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from xrpl.wallet import Wallet

from merkl.adapters.notary.enrol import EnrolClient as RealEnrolClient
from merkl.adapters.xrpl import bootstrap as xrpl_bootstrap
from merkl.adapters.xrpl.bootstrap import Reserves, TreasuryKeys, TreasurySetup, TrustLine
from merkl.cli import treasury as treasury_cli
from merkl.cli.bundle import AGENT_KEY, AGENT_WALLET, NOTARY_API_KEY, RELAY_TOKEN, TRADER_CONFIG
from merkl.cli.home import notary_path, treasury_path, wallets_path
from merkl.cli.treasury import EXIT_NOT_ENROLLED, MAINNET_CONFIRMATION, TreasuryRecord
from merkl.core.rail import NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET

ENROLMENT_TOKEN = "enr_" + "a" * 43
SIGNER_TOKEN = "sgn_" + "b" * 43
API_KEY = "mk_live_thisisthenotarykey"
SIGNER_LIST_TX = "A" * 64
DISABLE_TX = "B" * 64

SECRETS_NEVER_PRINTED = ("BEGIN PRIVATE KEY", "sEd", SIGNER_TOKEN, API_KEY, "PRIVATE KEY-----")


class FakeRail:
    """What rippled would have said. No socket, no faucet, no fee."""

    def __init__(self, *, balances: tuple[int | None, ...] = (50_000_000,)) -> None:
        self.balances = list(balances)
        self.installed: list[TreasuryKeys] = []
        self.polls = 0

    async def read_reserves(self, url: str, **_: Any) -> Reserves:
        return Reserves(base=Decimal("1"), owner=Decimal("0.2"))

    async def create_wallets(
        self,
        *,
        policy_public_key: str,
        agent_count: int = 1,
        json_rpc_url: str = "",
        wallet_file: Any = None,
        network: str = NETWORK_XRPL_TESTNET,
        client: Any = None,
    ) -> TreasuryKeys:
        treasury = Wallet.create()
        agents = tuple(Wallet.create() for _ in range(agent_count))
        path = Path(wallet_file)
        xrpl_bootstrap._write_secret(
            path,
            {
                "network": json_rpc_url,
                "policy_network": network,
                "policy_address": "rPOLICY0000000000000000000000000000",
                "wallets": {
                    "treasury": {"seed": treasury.seed, "address": treasury.classic_address},
                    **{
                        f"agent-{i}": {"seed": w.seed, "address": w.classic_address}
                        for i, w in enumerate(agents)
                    },
                },
            },
        )
        return TreasuryKeys(
            treasury=treasury,
            agents=agents,
            policy_address="rPOLICY0000000000000000000000000000",
            wallet_file=path,
            network=network,
            created=True,
        )

    async def await_funding(
        self, address: str, required: int, url: str = "", *, on_poll: Any = None, **_: Any
    ) -> int:
        for balance in self.balances:
            self.polls += 1
            if balance is not None and balance >= required:
                return balance
            if on_poll is not None:
                on_poll(balance)
        return required  # pragma: no cover - the scripts always end funded

    async def install_signer_list(
        self,
        keys: TreasuryKeys,
        *,
        json_rpc_url: str = "",
        disable_master: bool = True,
        trust_lines: Any = (),
        client: Any = None,
    ) -> TreasurySetup:
        self.installed.append(keys)
        return TreasurySetup(
            treasury=keys.address,
            agents=keys.addresses(),
            policy_address=keys.policy_address,
            quorum=len(keys.agents) + 1,
            master_disabled=True,
            regular_key=None,
            signer_list_tx=SIGNER_LIST_TX,
            disable_master_tx=DISABLE_TX,
            wallet_file=str(keys.wallet_file),
            network=keys.network,
            trust_lines=tuple(trust_lines),
        )


class FakeNotary:
    """``enrol`` and ``ready``, and a switch to make either of them fail."""

    def __init__(self, *, enrol_status: int = 200, ready_status: int = 200) -> None:
        self.enrol_status = enrol_status
        self.ready_status = ready_status
        self.enrolments: list[dict[str, Any]] = []
        self.readies: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Answer for every ``EnrolClient`` the command builds, from here on.

        Always wrapping the *real* class rather than whatever is currently
        patched in, so a test that installs a second notary replaces the first
        instead of layering on top of it.
        """
        transport = httpx.MockTransport(self._handle)

        def factory(url: str, **kwargs: Any) -> Any:
            return RealEnrolClient(url, transport=transport)

        monkeypatch.setattr(treasury_cli, "EnrolClient", factory)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/enrol"):
            self.enrolments.append(body)
            if self.enrol_status != 200:
                return httpx.Response(self.enrol_status, json={"detail": "already spent"})
            return httpx.Response(
                200,
                json={
                    "signer_id": "sig_01",
                    "org_slug": "acme",
                    "treasury_url": "https://app.merkl.ai/acme/treasuries/" + body["treasury"],
                    "signer_token": SIGNER_TOKEN,
                    "notary_api_key": API_KEY,
                },
            )
        self.readies.append(body)
        if self.ready_status != 200:
            return httpx.Response(self.ready_status, json={"detail": "the notary is down"})
        return httpx.Response(200, json={"signer_id": "sig_01", "status": "ready"})


@pytest.fixture
def rail(monkeypatch: pytest.MonkeyPatch) -> FakeRail:
    fake = FakeRail()
    for name in ("read_reserves", "create_wallets", "await_funding", "install_signer_list"):
        monkeypatch.setattr(f"merkl.adapters.xrpl.{name}", getattr(fake, name))
    return fake


@pytest.fixture
def sealed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home, with ``Path.home()`` pointed somewhere this test can watch."""
    elsewhere = tmp_path / "not-the-home"
    elsewhere.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: elsewhere))
    monkeypatch.setenv("MERKL_SIGNER_PASSPHRASE", "treasury-init-test")
    return tmp_path / "home"


def assert_no_secrets(output: str) -> None:
    for fragment in SECRETS_NEVER_PRINTED:
        assert fragment not in output, f"{fragment!r} reached the terminal"


class TestTestnet:
    def test_everything_it_writes_is_under_the_home(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path
    ) -> None:
        assert treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET) == 0

        assert (sealed_home / "keystore").is_dir()
        assert wallets_path(sealed_home).exists()
        assert treasury_path(sealed_home).exists()
        assert (sealed_home / "agents" / "agent-0" / AGENT_KEY).exists()
        assert (sealed_home / "relay" / "relay-tokens.json").exists()
        assert list((tmp_path / "not-the-home").iterdir()) == [], "nothing landed in ~"

    def test_the_bundle_lands_where_it_was_asked_to(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path
    ) -> None:
        agent_dir = tmp_path / "merkl-agent"
        assert (
            treasury_cli.init_command(
                home=sealed_home, network=NETWORK_XRPL_TESTNET, agent_dir=agent_dir
            )
            == 0
        )
        assert (agent_dir / TRADER_CONFIG).exists()
        assert (agent_dir / AGENT_KEY).stat().st_mode & 0o777 == 0o600
        assert (agent_dir / AGENT_WALLET).stat().st_mode & 0o777 == 0o600
        assert (agent_dir / RELAY_TOKEN).stat().st_mode & 0o777 == 0o600

    def test_without_an_agent_dir_it_goes_under_the_home(
        self, rail: FakeRail, sealed_home: Path
    ) -> None:
        treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET)
        assert (sealed_home / "agents" / "agent-0" / "bundle" / TRADER_CONFIG).exists()

    def test_it_prints_no_secret_of_any_kind(
        self, rail: FakeRail, sealed_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET)
        captured = capsys.readouterr()
        assert_no_secrets(captured.out + captured.err)

        seeds = json.loads(wallets_path(sealed_home).read_text())["wallets"]
        for entry in seeds.values():
            assert entry["seed"] not in captured.out

    def test_the_last_lines_name_the_treasury_the_key_and_the_bundle(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        agent_dir = tmp_path / "merkl-agent"
        treasury_cli.init_command(
            home=sealed_home, network=NETWORK_XRPL_TESTNET, agent_dir=agent_dir
        )
        out = capsys.readouterr().out
        record = TreasuryRecord.read(treasury_path(sealed_home))
        assert record is not None
        assert f"treasury        {record.treasury}" in out
        assert f"signer key      {record.signer_public_key}" in out
        assert f"agent bundle    {agent_dir}" in out

    def test_two_agents_get_a_key_a_wallet_and_a_token_each(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path
    ) -> None:
        agent_dir = tmp_path / "merkl-agent"
        treasury_cli.init_command(
            home=sealed_home, network=NETWORK_XRPL_TESTNET, agents=2, agent_dir=agent_dir
        )
        first = json.loads((agent_dir / "agent-0" / AGENT_WALLET).read_text())
        second = json.loads((agent_dir / "agent-1" / AGENT_WALLET).read_text())
        assert list(first["wallets"]) == ["agent-0"]
        assert list(second["wallets"]) == ["agent-1"]
        assert first["wallets"]["agent-0"] != second["wallets"]["agent-1"]

        tokens = json.loads((sealed_home / "relay" / "relay-tokens.json").read_text())
        assert sorted(t["id"] for t in tokens["tokens"]) == ["agent-0", "agent-1"]

    def test_two_agents_with_no_agent_dir_each_get_their_own_folder(
        self, rail: FakeRail, sealed_home: Path
    ) -> None:
        treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET, agents=2)
        for agent_id in ("agent-0", "agent-1"):
            bundle = sealed_home / "agents" / agent_id / "bundle"
            assert (bundle / TRADER_CONFIG).exists()
            assert json.loads((bundle / AGENT_WALLET).read_text())["wallets"] == {
                agent_id: json.loads((bundle / AGENT_WALLET).read_text())["wallets"][agent_id]
            }

    def test_the_treasury_record_holds_public_facts_and_no_seed(
        self, rail: FakeRail, sealed_home: Path
    ) -> None:
        treasury_cli.init_command(
            home=sealed_home, network=NETWORK_XRPL_TESTNET, trust=("RLUSD.rISSUER",)
        )
        record = TreasuryRecord.read(treasury_path(sealed_home))
        assert record is not None
        assert record.installed
        assert record.signer_list_tx == SIGNER_LIST_TX
        assert record.disable_master_tx == DISABLE_TX
        assert record.trust_lines == ({"currency": "RLUSD", "issuer": "rISSUER"},)
        assert "seed" not in treasury_path(sealed_home).read_text()

    def test_a_trust_line_that_is_not_code_dot_issuer_stops_before_anything_happens(
        self, rail: FakeRail, sealed_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert treasury_cli.init_command(home=sealed_home, trust=("RLUSD",)) == 2
        assert "wants CODE.issuer" in capsys.readouterr().err
        assert rail.installed == []


class TestMainnet:
    def test_it_prints_the_minimum_and_waits_for_the_money(
        self, rail: FakeRail, sealed_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rail.balances = [None, 1_000_000, 3_000_000]
        code = treasury_cli.init_command(
            home=sealed_home,
            network=NETWORK_XRPL_MAINNET,
            confirm=MAINNET_CONFIRMATION,
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "fund at least         2.2 XRP" in out
        assert "the account does not exist yet" in out
        assert "1000000 drops so far" in out
        assert rail.polls == 3

    def test_the_sentence_is_asked_for_when_no_flag_gave_it(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        typed = []

        def prompt(question: str) -> str:
            typed.append(question)
            return MAINNET_CONFIRMATION

        monkeypatch.setattr("builtins.input", prompt)
        assert treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_MAINNET) == 0
        assert typed and MAINNET_CONFIRMATION in typed[0]

    def test_anything_else_typed_submits_nothing(
        self,
        rail: FakeRail,
        sealed_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr("builtins.input", lambda _q: "yes")
        assert treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_MAINNET) == 5
        assert "not confirmed" in capsys.readouterr().err
        assert rail.installed == [], "the master key is still on"

    def test_a_confirm_flag_that_is_not_the_sentence_is_not_a_confirmation(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("builtins.input", lambda _q: "no")
        assert (
            treasury_cli.init_command(
                home=sealed_home, network=NETWORK_XRPL_MAINNET, confirm="disable the master key"
            )
            == 5
        )
        assert rail.installed == []

    def test_non_interactive_without_the_sentence_exits_five_before_any_key_exists(
        self, rail: FakeRail, sealed_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = treasury_cli.init_command(
            home=sealed_home, network=NETWORK_XRPL_MAINNET, interactive=False
        )
        assert code == 5
        assert "there is nobody here to ask" in capsys.readouterr().err
        assert not sealed_home.exists(), "it refused before touching the keystore"

    def test_a_node_that_will_not_report_its_reserves_stops_the_run(
        self,
        sealed_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        async def broken(url: str, **_: Any) -> Reserves:
            raise TimeoutError("no answer")

        monkeypatch.setattr("merkl.adapters.xrpl.read_reserves", broken)
        code = treasury_cli.init_command(
            home=sealed_home, network=NETWORK_XRPL_MAINNET, confirm=MAINNET_CONFIRMATION
        )
        assert code == 3
        assert "could not read the network's reserves" in capsys.readouterr().err

    def test_the_operator_wallet_file_flow_still_works(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path
    ) -> None:
        """``--wallet-file`` names the seeds; init writes nowhere else for them."""
        seeds = tmp_path / "mine" / "xrpl-mainnet.wallets.json"
        code = treasury_cli.init_command(
            home=sealed_home,
            network=NETWORK_XRPL_MAINNET,
            wallet_file=seeds,
            confirm=MAINNET_CONFIRMATION,
        )
        assert code == 0
        assert seeds.exists()
        assert not wallets_path(sealed_home).exists(), "it did not also write the default"


class TestEnrolment:
    def test_enrol_happens_before_a_single_transaction(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The page needs an address to show while the customer is still watching."""
        notary = FakeNotary()
        order: list[str] = []

        original = rail.install_signer_list

        async def watched(*args: Any, **kwargs: Any) -> TreasurySetup:
            order.append("install")
            return await original(*args, **kwargs)

        monkeypatch.setattr("merkl.adapters.xrpl.install_signer_list", watched)
        answer = notary._handle

        def watching(request: httpx.Request) -> httpx.Response:
            order.append("enrol" if request.url.path.endswith("/enrol") else "ready")
            return answer(request)

        notary._handle = watching  # type: ignore[method-assign]
        notary.install(monkeypatch)

        code = treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n"
        )
        assert code == 0
        assert order == ["enrol", "install", "ready"]

    def test_the_enrol_body_describes_what_was_just_created(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notary = FakeNotary()
        notary.install(monkeypatch)
        treasury_cli.init_command(
            home=sealed_home, agents=2, enrol=ENROLMENT_TOKEN, notary="http://n"
        )

        body = notary.enrolments[0]
        record = TreasuryRecord.read(treasury_path(sealed_home))
        assert record is not None
        assert body["treasury"] == record.treasury
        assert body["network"] == NETWORK_XRPL_TESTNET
        assert body["signer_public_key"] == record.signer_public_key
        assert [a["id"] for a in body["agents"]] == ["agent-0", "agent-1"]
        assert all(len(a["public_key"]) == 64 for a in body["agents"])
        assert body["required_drops"] == "2200000"

    def test_the_ready_body_carries_the_read_back(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notary = FakeNotary()
        notary.install(monkeypatch)
        treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n", trust=("RLUSD.rISSUER",)
        )
        body = notary.readies[0]
        assert body["signer_list_tx"] == SIGNER_LIST_TX
        assert body["disable_master_tx"] == DISABLE_TX
        assert body["trust_lines"] == [{"currency": "RLUSD", "issuer": "rISSUER"}]
        assert body["relay_token"] is None, "a self-hosted signer is not pushed to"
        assert body["agent_bundle"] is None

    def test_notary_json_lands_at_0600_and_names_the_network(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FakeNotary().install(monkeypatch)
        treasury_cli.init_command(home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n")

        path = notary_path(sealed_home)
        assert path.stat().st_mode & 0o777 == 0o600
        record = json.loads(path.read_text())
        assert record["signer_id"] == "sig_01"
        assert record["network"] == NETWORK_XRPL_TESTNET

    def test_the_bundle_carries_the_api_key_enrolment_minted(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FakeNotary().install(monkeypatch)
        agent_dir = tmp_path / "merkl-agent"
        treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n", agent_dir=agent_dir
        )
        assert (agent_dir / NOTARY_API_KEY).read_text().strip() == API_KEY
        assert (agent_dir / NOTARY_API_KEY).stat().st_mode & 0o777 == 0o600

    def test_a_managed_signer_sends_the_bundle_and_a_relay_token_instead(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        notary = FakeNotary()
        notary.install(monkeypatch)
        treasury_cli.init_command(
            home=sealed_home,
            enrol=ENROLMENT_TOKEN,
            notary="http://n",
            bundle_to_notary=True,
        )
        body = notary.readies[0]
        assert body["relay_token"].startswith("notary:")
        assert set(body["agent_bundle"]["files"]) >= {TRADER_CONFIG, AGENT_KEY, AGENT_WALLET}
        assert "signers/sig_01" in body["agent_bundle"]["files"][TRADER_CONFIG]

    def test_the_continue_line_points_at_the_treasury_page(
        self, rail: FakeRail, sealed_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        FakeNotary().install(monkeypatch)
        treasury_cli.init_command(home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n")
        assert "Continue at https://app.merkl.ai/acme/treasuries/" in capsys.readouterr().out


class TestWhenTheNotaryIsDown:
    def test_a_failed_ready_keeps_the_treasury_and_names_the_re_run(
        self,
        rail: FakeRail,
        sealed_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        notary = FakeNotary(ready_status=502)
        notary.install(monkeypatch)

        code = treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n"
        )

        assert code == EXIT_NOT_ENROLLED
        err = capsys.readouterr().err
        assert "nothing on the ledger needs redoing" in err
        assert f"merkl treasury enrol --enrol {ENROLMENT_TOKEN} --notary http://n" in err
        record = TreasuryRecord.read(treasury_path(sealed_home))
        assert record is not None and record.installed

    def test_a_failed_enrol_still_installs_the_treasury(
        self,
        rail: FakeRail,
        sealed_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        FakeNotary(enrol_status=409).install(monkeypatch)

        code = treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n"
        )

        assert code == EXIT_NOT_ENROLLED
        assert rail.installed, "the ledger work happened anyway"
        assert not notary_path(sealed_home).exists()
        assert "merkl treasury enrol" in capsys.readouterr().err

    def test_enrol_re_runs_both_calls_from_what_is_on_disk(
        self, rail: FakeRail, sealed_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FakeNotary(enrol_status=503).install(monkeypatch)
        agent_dir = tmp_path / "merkl-agent"
        treasury_cli.init_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n", agent_dir=agent_dir
        )
        assert not (agent_dir / NOTARY_API_KEY).exists()

        working = FakeNotary()
        working.install(monkeypatch)
        code = treasury_cli.enrol_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n", agent_dir=agent_dir
        )

        record = TreasuryRecord.read(treasury_path(sealed_home))
        assert record is not None
        assert code == 0
        assert working.enrolments[0]["treasury"] == record.treasury
        assert working.readies[0]["signer_list_tx"] == SIGNER_LIST_TX
        assert (agent_dir / NOTARY_API_KEY).read_text().strip() == API_KEY
        assert notary_path(sealed_home).exists()

    def test_enrol_with_no_treasury_on_disk_says_so(
        self, sealed_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = treasury_cli.enrol_command(
            home=sealed_home, enrol=ENROLMENT_TOKEN, notary="http://n"
        )
        assert code == 2
        assert "run `merkl treasury init` first" in capsys.readouterr().err


def test_a_re_run_against_an_existing_home_keeps_the_agent_keys(
    rail: FakeRail, sealed_home: Path
) -> None:
    """A regenerated request key would leave the published policy naming a stranger."""
    treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET)
    first = TreasuryRecord.read(treasury_path(sealed_home))

    treasury_cli.init_command(home=sealed_home, network=NETWORK_XRPL_TESTNET)
    second = TreasuryRecord.read(treasury_path(sealed_home))

    assert first is not None and second is not None
    assert first.agents[0].public_key == second.agents[0].public_key


def test_the_trust_line_vocabulary_is_the_notarys(rail: FakeRail) -> None:
    assert treasury_cli._line_content(TrustLine(code="RLUSD", issuer="rX")) == {
        "currency": "RLUSD",
        "issuer": "rX",
    }
