"""``merkl signer serve`` when a notary is on file, and ``signer bootstrap``.

``serve`` binds a socket and never returns, so everything here stops just before
it: what is worth checking is which policy the command decided to serve, whether
it refused, and whether a follower was wired to the router that will hold the
lock. ``serve`` itself is exercised for real by ``tests/docker``.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from merkl.adapters.notary.enrol import NotaryRecord
from merkl.cli import signer as signer_cli
from merkl.cli.home import notary_path, policy_path
from merkl.core.policy.document import SignedPolicy
from merkl.demo.rig import build_policy, sign_policy
from merkl.signer.keystore import PASSPHRASE_ENV

SIGNER_TOKEN = "sgn_" + "b" * 43


def a_record(home: Path, *, network: str | None = None) -> NotaryRecord:
    record = NotaryRecord(
        url="https://api.merkl.ai",
        signer_id="sig_01",
        signer_token=SIGNER_TOKEN,
        org_slug="acme",
        treasury_url="https://app.merkl.ai/acme/treasuries/rTREASURY",
        network=network,
    )
    record.write(notary_path(home))
    return record


def write_policy(path: Path, **overrides: Any) -> SignedPolicy:
    document = build_policy(**overrides)
    signed = sign_policy(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(signed.to_content()))
    return signed


class FakeNotary:
    """Every route the follower pulls on, and a record of what it asked for.

    Installed for *every* test in this file, because a follower the command
    builds and nobody redirected would open a real connection to api.merkl.ai
    from a daemon thread — which is slow, rude and not a test of anything.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.policy: SignedPolicy | None = None
        self.status = 200
        self.started: list[Any] = []

    def publish(self, policy: SignedPolicy) -> None:
        self.policy = policy

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if self.status != 200:
            return httpx.Response(self.status, json={"detail": "no"})
        if request.url.path == "/v1/signer/policy":
            if self.policy is None:
                return httpx.Response(200, json={"policy": None})
            return httpx.Response(
                200,
                json={
                    "policy": {
                        "signed_document": self.policy.to_content(),
                        "policy_hash": self.policy.policy_hash,
                        "version": self.policy.document.version,
                    }
                },
            )
        return httpx.Response(204)


@pytest.fixture
def notary(monkeypatch: pytest.MonkeyPatch) -> FakeNotary:
    """A follower that answers from here, sleeps for nothing, and starts no thread."""
    from merkl.adapters.notary import follower as follower_module

    fake = FakeNotary()
    real = follower_module.NotaryFollower

    def factory(record: NotaryRecord, **kwargs: Any) -> Any:
        kwargs.setdefault("transport", httpx.MockTransport(fake.handle))
        kwargs.setdefault("sleep", lambda _seconds: None)
        built = real(record, **kwargs)
        built.start = lambda: fake.started.append(built)  # type: ignore[method-assign]
        return built

    monkeypatch.setattr(follower_module, "NotaryFollower", factory)
    return fake


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch, notary: FakeNotary) -> list[dict[str, Any]]:
    """Capture the call to ``serve`` instead of binding anything."""
    calls: list[dict[str, Any]] = []

    def fake_serve(engine: Any, **kwargs: Any) -> None:
        calls.append({"engine": engine, **kwargs})

    monkeypatch.setattr(signer_cli, "serve", fake_serve)
    monkeypatch.setenv(PASSPHRASE_ENV, "serve-follow-test")
    return calls


class TestThePolicyDefault:
    def test_it_reads_the_policy_out_of_the_home_when_no_flag_says(
        self, tmp_path: Path, served: list[dict[str, Any]]
    ) -> None:
        home = tmp_path / "home"
        signed = write_policy(policy_path(home))
        assert signer_cli.serve_command(home=home) == 0
        assert served[0]["engine"].policy_hash == signed.policy_hash

    def test_a_flag_still_wins(self, tmp_path: Path, served: list[dict[str, Any]]) -> None:
        home = tmp_path / "home"
        write_policy(policy_path(home))
        elsewhere = write_policy(tmp_path / "elsewhere.json", per_tx_cap="7.00")
        assert signer_cli.serve_command(home=home, policy_path=tmp_path / "elsewhere.json") == 0
        assert served[0]["engine"].policy_hash == elsewhere.policy_hash

    def test_no_policy_and_no_notary_is_the_same_refusal_as_before(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert signer_cli.serve_command(home=tmp_path / "home") == 2
        assert "cannot read the policy" in capsys.readouterr().err

    def test_the_router_it_serves_with_is_the_one_the_follower_holds(
        self, tmp_path: Path, served: list[dict[str, Any]]
    ) -> None:
        """One router, one lock: a second would let two calls read the same window."""
        home = tmp_path / "home"
        write_policy(policy_path(home))
        a_record(home)
        signer_cli.serve_command(home=home)
        router = served[0]["router"]
        assert router is not None
        assert router.dispatch_local("health", {})["status"] == "ok"


class TestFollowingTheNotary:
    def test_a_signer_with_no_policy_waits_for_the_notary_to_have_one(
        self, tmp_path: Path, served: list[dict[str, Any]], notary: FakeNotary
    ) -> None:
        home = tmp_path / "home"
        a_record(home)
        published = sign_policy(build_policy())
        notary.publish(published)

        assert signer_cli.serve_command(home=home) == 0
        assert served[0]["engine"].policy_hash == published.policy_hash
        assert policy_path(home).exists(), "and it kept a copy for the next boot"
        assert notary.started, "and it kept following after it booted"

    def test_a_policy_already_on_disk_is_served_without_asking(
        self, tmp_path: Path, served: list[dict[str, Any]], notary: FakeNotary
    ) -> None:
        home = tmp_path / "home"
        a_record(home)
        signed = write_policy(policy_path(home))
        notary.status = 500

        assert signer_cli.serve_command(home=home) == 0
        assert served[0]["engine"].policy_hash == signed.policy_hash
        assert notary.paths == [], (
            "a notary that is down must not stop a signer that has its policy"
        )

    def test_the_boot_banner_names_the_notary(
        self, tmp_path: Path, served: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        a_record(home)
        write_policy(policy_path(home))
        signer_cli.serve_command(home=home)
        assert "notary       https://api.merkl.ai" in capsys.readouterr().out

    def test_a_mangled_notary_file_stops_the_boot_rather_than_being_ignored(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        notary_path(home).parent.mkdir(parents=True, exist_ok=True)
        notary_path(home).write_text("{not json")
        assert signer_cli.serve_command(home=home) == 2
        assert "not valid JSON" in capsys.readouterr().err


class TestTheNetworkCheck:
    def test_the_enrolled_network_refuses_a_policy_for_the_other_chain(
        self, tmp_path: Path, served: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No --rail-endpoint in a container; notary.json is what knows the chain."""
        home = tmp_path / "home"
        a_record(home, network="xrpl-testnet")
        document = dataclasses.replace(build_policy(rail="xrpl"), network="xrpl-mainnet")
        path = policy_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sign_policy(document).to_content()))

        assert signer_cli.serve_command(home=home) == 4
        err = capsys.readouterr().err
        assert "enrolled on xrpl-testnet" in err
        assert "governs xrpl-mainnet" in err
        assert served == []

    def test_the_same_chain_is_served(self, tmp_path: Path, served: list[dict[str, Any]]) -> None:
        home = tmp_path / "home"
        a_record(home, network="xrpl-testnet")
        document = dataclasses.replace(build_policy(rail="xrpl"), network="xrpl-testnet")
        path = policy_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sign_policy(document).to_content()))

        assert signer_cli.serve_command(home=home) == 0

    def test_an_explicit_endpoint_still_has_the_last_word(
        self, tmp_path: Path, served: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        a_record(home, network="xrpl-testnet")
        document = dataclasses.replace(build_policy(rail="xrpl"), network="xrpl-testnet")
        path = policy_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sign_policy(document).to_content()))

        code = signer_cli.serve_command(home=home, rail_endpoint="https://xrplcluster.com")
        assert code == 4
        assert "is on xrpl-mainnet" in capsys.readouterr().err


class TestBootstrap:
    def test_mainnet_without_the_sentence_exits_five_and_serves_nothing(
        self, tmp_path: Path, served: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = signer_cli.bootstrap_command(home=tmp_path / "home", network="xrpl-mainnet")
        assert code == 5
        assert "there is nobody here to ask" in capsys.readouterr().err
        assert served == []

    def test_a_failed_setup_is_not_followed_by_a_serve(
        self, tmp_path: Path, served: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("merkl.cli.treasury.init_command", lambda **_kwargs: 3, raising=True)
        assert signer_cli.bootstrap_command(home=tmp_path / "home", network="xrpl-testnet") == 3
        assert served == []

    def test_it_sets_up_and_then_serves_the_same_home(
        self, tmp_path: Path, served: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        seen: dict[str, Any] = {}

        def fake_init(**kwargs: Any) -> int:
            seen.update(kwargs)
            write_policy(policy_path(home))
            return 0

        monkeypatch.setattr("merkl.cli.treasury.init_command", fake_init)
        assert (
            signer_cli.bootstrap_command(
                home=home, network="xrpl-testnet", enrol="enr_x", notary="http://n", agents=2
            )
            == 0
        )
        assert seen["interactive"] is False, "a container has no terminal to prompt at"
        assert seen["home"] == home
        assert seen["agents"] == 2
        assert seen["enrol"] == "enr_x"
        assert len(served) == 1


class TestTokenEnv:
    def test_it_prints_the_two_finished_lines(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from merkl.cli.home import treasury_path
        from merkl.cli.treasury import TreasuryRecord

        home = tmp_path / "home"
        TreasuryRecord(
            treasury="rTREASURY0000000000000000000000000",
            network="xrpl-testnet",
            json_rpc_url="",
            signer_public_key="ab" * 32,
            agents=(),
            required_drops="0",
        ).write(treasury_path(home))

        assert signer_cli.token_command("add", "notary", home=home, as_env=True) == 0

        lines = capsys.readouterr().out.strip().splitlines()
        assert lines[0].startswith("MERKL_SIGNER_TOKEN=notary:")
        bearer = lines[0].split("=", 1)[1]
        assert lines[1] == (
            'SIGNER_RELAY_TOKENS={"rTREASURY0000000000000000000000000": "' + bearer + '"}'
        )
        assert json.loads(lines[1].split("=", 1)[1]) == {
            "rTREASURY0000000000000000000000000": bearer
        }

    def test_without_a_treasury_on_disk_it_says_so_rather_than_guessing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert signer_cli.token_command("add", "notary", home=tmp_path / "home", as_env=True) == 0
        assert '"<treasury>"' in capsys.readouterr().out

    def test_the_ordinary_form_is_unchanged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert signer_cli.token_command("add", "ci", home=tmp_path / "home") == 0
        out = capsys.readouterr().out
        assert "This is the only time it is shown" in out
        assert "MERKL_SIGNER_TOKEN" not in out
