"""The agent bundle — five files, four of them ``0600``, one of them runnable.

The strongest thing that can be said about a generated config is that the
program it configures reads it, so that is what is checked here: the filled-in
``trader.toml`` goes through the trader's own ``config.parse`` and comes back
with the values ``init`` put in it. Everything else about a bundle is about
modes and about what is *not* in it — the treasury's seed, above all.
"""

from __future__ import annotations

import json
import stat
import tomllib
from pathlib import Path

import pytest

from examples.trader import config as trader_config
from merkl.cli.bundle import (
    AGENT_KEY,
    AGENT_WALLET,
    NOTARY_API_KEY,
    POLICY_VERSION_PLACEHOLDER,
    RELAY_TOKEN,
    TRADER_CONFIG,
    BundleError,
    build_bundle,
    fill_template,
    generate_agent_key,
    read_agent_key,
    template_path,
)

FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"
TREASURY = "rTREASURY0000000000000000000000000"
AGENT_ADDRESS = "rAGENT00000000000000000000000000000"
NOTARY = "https://api.merkl.ai"


def a_bundle(**overrides: object) -> object:
    fields: dict[str, object] = {
        "agent_id": "agent-0",
        "treasury": TREASURY,
        "agent_key_pem": FAKE_PEM,
        "agent_wallet": {"seed": "sEDNOTAREALSEED", "address": AGENT_ADDRESS},
        "network": "xrpl-testnet",
        "json_rpc_url": "https://s.altnet.rippletest.net:51234",
        "websocket_url": "wss://s.altnet.rippletest.net:51233",
        "notary_url": NOTARY,
        "relay_token": "agent-0:abc123",
        "notary_api_key": "mk_live_notarealkey",
    }
    fields.update(overrides)
    return build_bundle(**fields)  # type: ignore[arg-type]


class TestTheTemplate:
    def test_it_is_the_example_the_repository_ships(self) -> None:
        assert template_path().exists()
        assert "[agent]" in template_path().read_text()

    def test_a_substitution_keeps_the_comments(self) -> None:
        filled = fill_template(
            '# why this matters\n[agent]\nagent_id = "x"\n',
            {("agent", "agent_id"): 'agent_id = "y"'},
        )
        assert "# why this matters" in filled
        assert 'agent_id = "y"' in filled

    def test_a_key_the_template_does_not_have_is_a_failure_not_a_no_op(self) -> None:
        with pytest.raises(BundleError, match="no \\[.'agent', 'nope'.\\] to fill in"):
            fill_template("[agent]\n", {("agent", "nope"): "nope = 1"})

    def test_the_same_key_under_a_different_table_is_not_a_match(self) -> None:
        with pytest.raises(BundleError):
            fill_template('[agent]\nurl = "a"\n', {("signer", "url"): 'url = "b"'})


class TestTheFilledConfig:
    def test_the_trader_reads_its_own_generated_config(self) -> None:
        bundle = a_bundle()
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]

        assert settings.agent.agent_id == "agent-0"
        assert settings.treasury.address == TREASURY
        assert settings.treasury.wallet_name == "agent-0"
        assert settings.rail.json_rpc_url == "https://s.altnet.rippletest.net:51234"
        assert settings.signer.url == "http://127.0.0.1:8787"
        assert settings.notary.url == NOTARY

    def test_the_policy_version_says_it_is_not_set_yet(self) -> None:
        """The signer refuses an intent naming the wrong version; a guess is worse."""
        bundle = a_bundle()
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.treasury.policy_version == POLICY_VERSION_PLACEHOLDER

    def test_every_path_in_it_is_relative_to_the_bundle(self) -> None:
        bundle = a_bundle()
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.agent.key_file == Path(AGENT_KEY)
        assert settings.treasury.wallet_file == Path(AGENT_WALLET)
        assert settings.signer.token_file == Path(RELAY_TOKEN)
        assert settings.notary.api_key_file == Path(NOTARY_API_KEY)

    def test_an_enrolled_bundle_names_a_key_file_rather_than_an_environment_variable(
        self,
    ) -> None:
        bundle = a_bundle()
        assert 'api_key_file = "notary-api-key.txt"' in bundle.files[TRADER_CONFIG]  # type: ignore[attr-defined]
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.notary.api_key_env is None, "the model's own key is untouched"
        assert settings.model.api_key_env == "ANTHROPIC_API_KEY"

    def test_without_a_notary_key_the_environment_variable_stays(self) -> None:
        bundle = a_bundle(notary_api_key=None)
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.notary.api_key_file is None
        assert settings.notary.api_key_env == "MERKL_API_KEY"
        assert NOTARY_API_KEY not in bundle.files  # type: ignore[operator]

    def test_a_managed_signer_gets_its_public_url_instead_of_loopback(self) -> None:
        bundle = a_bundle(signer_url="https://api.merkl.ai/signers/sig_01")
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.signer.url == "https://api.merkl.ai/signers/sig_01"

    def test_without_a_relay_token_the_token_file_is_commented_out(self) -> None:
        bundle = a_bundle(relay_token=None)
        settings = trader_config.parse(tomllib.loads(bundle.files[TRADER_CONFIG]))  # type: ignore[attr-defined]
        assert settings.signer.token_file is None
        assert RELAY_TOKEN not in bundle.files  # type: ignore[operator]


class TestTheWallet:
    def test_it_holds_this_agent_and_nothing_else(self) -> None:
        bundle = a_bundle()
        document = json.loads(bundle.files[AGENT_WALLET])  # type: ignore[attr-defined]
        assert list(document["wallets"]) == ["agent-0"]
        assert document["wallets"]["agent-0"]["address"] == AGENT_ADDRESS

    def test_the_treasury_seed_is_never_in_a_bundle(self) -> None:
        bundle = a_bundle()
        blob = json.dumps(bundle.files)  # type: ignore[arg-type]
        assert "treasury" not in json.loads(bundle.files[AGENT_WALLET])["wallets"]  # type: ignore[attr-defined]
        assert "sEDTREASURY" not in blob


class TestWritingItOut:
    def test_every_secret_lands_at_0600(self, tmp_path: Path) -> None:
        directory = a_bundle().write(tmp_path / "merkl-agent")  # type: ignore[attr-defined]
        for name in (AGENT_KEY, AGENT_WALLET, RELAY_TOKEN, NOTARY_API_KEY):
            mode = (directory / name).stat().st_mode
            assert mode & 0o777 == 0o600, name
            assert not mode & (stat.S_IRWXG | stat.S_IRWXO), name

    def test_the_config_is_readable_because_it_holds_no_secret(self, tmp_path: Path) -> None:
        directory = a_bundle().write(tmp_path / "merkl-agent")  # type: ignore[attr-defined]
        assert (directory / TRADER_CONFIG).stat().st_mode & 0o004

    def test_writing_twice_replaces_rather_than_appends(self, tmp_path: Path) -> None:
        target = tmp_path / "merkl-agent"
        a_bundle().write(target)  # type: ignore[attr-defined]
        a_bundle(agent_id="agent-0", treasury="rSECOND").write(target)  # type: ignore[attr-defined]
        assert 'address = "rSECOND"' in (target / TRADER_CONFIG).read_text()


class TestTheAgentKey:
    def test_it_is_written_0600_and_reads_back_as_the_same_key(self, tmp_path: Path) -> None:
        path = tmp_path / "agent-ed25519.pem"
        pem, public = generate_agent_key(path)

        assert path.stat().st_mode & 0o777 == 0o600
        assert len(public) == 64
        assert path.read_text() == pem
        assert read_agent_key(path) == (pem, public)

    def test_two_agents_never_share_a_key(self, tmp_path: Path) -> None:
        first = generate_agent_key(tmp_path / "a.pem")[1]
        second = generate_agent_key(tmp_path / "b.pem")[1]
        assert first != second

    def test_something_that_is_not_an_ed25519_key_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.pem"
        path.write_text("-----BEGIN PRIVATE KEY-----\n")
        with pytest.raises((BundleError, ValueError)):
            read_agent_key(path)
