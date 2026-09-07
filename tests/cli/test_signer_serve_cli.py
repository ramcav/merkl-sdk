"""``merkl signer serve`` — what it refuses to start on, and why.

Everything here stops *before* `serve()` binds a socket: the interesting part of
this command is the sequence of refusals in front of the server, not the server.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from merkl.cli.signer import serve_command
from merkl.core.intent import IssuedCurrency
from merkl.core.policy.document import AgentSection, AssetLimit, PolicyDocument, SignedPolicy
from merkl.core.vectors import fixtures
from merkl.signer.keystore import KEY_FILE, PASSPHRASE_ENV, PASSPHRASE_FILE, DevKeystore

ADMIN = fixtures.ed25519_key("serve-cli-admin")
AGENT_KEY = fixtures.ed25519_public_hex(fixtures.ed25519_key("serve-cli-agent"))
RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")


def signed_policy(tmp_path: Path, **overrides: object) -> Path:
    fields: dict[str, object] = {
        "version": "2026.03.0",
        "treasury": "rSERVETREASURY000000000000000000000",
        "rail": "xrpl",
        "agents": (
            AgentSection(
                agent_id="agent-serve",
                public_key=AGENT_KEY,
                allowlist_destinations=("rSUPPLIER0000000000000000000000000",),
                allowlist_assets=(RLUSD,),
                per_tx_cap=(AssetLimit(asset=RLUSD, amount="100.00"),),
            ),
        ),
        "admin_public_key": fixtures.ed25519_public_hex(ADMIN),
    }
    fields.update(overrides)
    document = PolicyDocument(**fields)  # type: ignore[arg-type]
    signed = SignedPolicy(
        document=document,
        signature=ADMIN.sign(document.pre_image()).hex(),
        signer_public_key=fixtures.ed25519_public_hex(ADMIN),
    )
    path = tmp_path / "policy.signed.json"
    path.write_text(json.dumps(signed.to_content()))
    return path


class TestNetworkAgreement:
    def test_a_mainnet_endpoint_under_a_testnet_policy_refuses_to_start(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        policy = signed_policy(tmp_path, network="xrpl-testnet")
        code = serve_command(
            policy_path=policy,
            home=tmp_path / "home",
            rail_endpoint="https://xrplcluster.com",
        )
        assert code == 4
        err = capsys.readouterr().err
        assert "is on xrpl-mainnet" in err
        assert "governs xrpl-testnet" in err
        assert not (tmp_path / "home").exists(), "it refused before touching the keystore"

    def test_a_devnet_endpoint_under_a_testnet_policy_refuses_to_start(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        policy = signed_policy(tmp_path, network="xrpl-testnet")
        code = serve_command(
            policy_path=policy,
            home=tmp_path / "home",
            rail_endpoint="https://s.devnet.rippletest.net:51234",
        )
        assert code == 4
        assert "xrpl-other" in capsys.readouterr().err

    def test_an_endpoint_nobody_recognises_is_not_an_opinion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A private rippled must stay usable; refusing there would prove nothing."""
        from merkl.cli import signer as signer_cli

        policy = signed_policy(tmp_path, network="xrpl-testnet")
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)
        monkeypatch.setenv(PASSPHRASE_ENV, "serve-cli")
        assert (
            serve_command(
                policy_path=policy,
                home=tmp_path / "home",
                rail_endpoint="http://localhost:5005",
            )
            == 0
        )

    def test_a_policy_that_names_no_network_accepts_any_endpoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from merkl.cli import signer as signer_cli

        policy = signed_policy(tmp_path)
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)
        monkeypatch.setenv(PASSPHRASE_ENV, "serve-cli")
        assert (
            serve_command(
                policy_path=policy,
                home=tmp_path / "home",
                rail_endpoint="https://xrplcluster.com",
            )
            == 0
        )

    def test_the_environment_supplies_the_endpoint_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        policy = signed_policy(tmp_path, network="xrpl-mainnet")
        monkeypatch.setenv("MERKL_RAIL_ENDPOINT", "https://s.altnet.rippletest.net:51234")
        assert serve_command(policy_path=policy, home=tmp_path / "home") == 4
        assert "xrpl-testnet" in capsys.readouterr().err


class TestKeystorePassphrase:
    """The phase-7 quirk: a keystore made with an explicit passphrase."""

    def test_it_never_writes_a_passphrase_beside_a_key_it_cannot_open(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        DevKeystore(home / "keystore", passphrase="the-real-one")
        assert not (home / "keystore" / PASSPHRASE_FILE).exists()

        code = serve_command(policy_path=signed_policy(tmp_path), home=home)

        assert code == 5
        err = capsys.readouterr().err
        assert "exists but nothing says how to open it" in err
        assert PASSPHRASE_ENV in err
        assert not (home / "keystore" / PASSPHRASE_FILE).exists(), "nothing was written"

    def test_the_environment_opens_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from merkl.cli import signer as signer_cli

        home = tmp_path / "home"
        expected = DevKeystore(home / "keystore", passphrase="the-real-one").public_key()
        monkeypatch.setenv(PASSPHRASE_ENV, "the-real-one")
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 0
        assert DevKeystore(home / "keystore", passphrase="the-real-one").public_key() == expected

    def test_a_prompt_opens_it_when_there_is_a_terminal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from merkl.cli import signer as signer_cli

        home = tmp_path / "home"
        DevKeystore(home / "keystore", passphrase="the-real-one")
        monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
        monkeypatch.setattr(signer_cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(signer_cli.getpass, "getpass", lambda _prompt: "the-real-one")
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 0
        assert not (home / "keystore" / PASSPHRASE_FILE).exists()

    def test_a_wrong_prompt_answer_says_so_precisely(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from merkl.cli import signer as signer_cli

        home = tmp_path / "home"
        DevKeystore(home / "keystore", passphrase="the-real-one")
        monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
        monkeypatch.setattr(signer_cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(signer_cli.getpass, "getpass", lambda _prompt: "not-it")

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 5
        assert "did not open with the passphrase given" in capsys.readouterr().err

    def test_a_first_boot_still_creates_both_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from merkl.cli import signer as signer_cli

        home = tmp_path / "home"
        monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 0
        assert (home / "keystore" / KEY_FILE).exists()
        assert (home / "keystore" / PASSPHRASE_FILE).exists()


def test_a_policy_carrying_an_unenforceable_rule_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A signed policy from before the rule existed still cannot be served."""
    path = signed_policy(tmp_path)
    content = json.loads(path.read_text())
    content["document"]["agents"][0]["per_tx_cap"].append(
        {"asset": {"code": "RLUSD", "issuer": RLUSD.issuer}, "amount": "1.00"}
    )
    path.write_text(json.dumps(content))

    assert serve_command(policy_path=path, home=tmp_path / "home") == 2
    assert "cannot be enforced" in capsys.readouterr().err


class TestStrayPassphraseFile:
    """The one this fix cannot undo: a stray file an earlier signer already wrote."""

    def test_the_error_names_the_file_rather_than_blaming_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        DevKeystore(home / "keystore", passphrase="the-real-one")
        # Exactly what a pre-0.2.0 `merkl signer serve` left behind.
        (home / "keystore" / PASSPHRASE_FILE).write_text("a-generated-one-that-opens-nothing\n")
        monkeypatch.delenv(PASSPHRASE_ENV, raising=False)

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 5

        err = capsys.readouterr().err
        assert str(home / "keystore" / PASSPHRASE_FILE) in err
        assert "delete it" in err
        assert PASSPHRASE_ENV in err

    def test_the_environment_still_wins_over_a_stray_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from merkl.cli import signer as signer_cli

        home = tmp_path / "home"
        DevKeystore(home / "keystore", passphrase="the-real-one")
        (home / "keystore" / PASSPHRASE_FILE).write_text("a-generated-one-that-opens-nothing\n")
        monkeypatch.setenv(PASSPHRASE_ENV, "the-real-one")
        monkeypatch.setattr(signer_cli, "serve", lambda *a, **k: None)

        assert serve_command(policy_path=signed_policy(tmp_path), home=home) == 0
