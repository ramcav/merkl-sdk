"""``merkl policy sign`` and ``merkl policy show`` — the non-browser admin path."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from merkl.cli.policy import show_command, sign_command
from merkl.core.policy.approvals import verify_policy_signature
from merkl.core.policy.document import AgentSection, AssetLimit, PolicyDocument, SignedPolicy
from merkl.core.vectors import fixtures


def _write_key(tmp_path: Path, key: Ed25519PrivateKey, name: str = "admin.key") -> Path:
    path = tmp_path / name
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    path.write_text(seed.hex())
    path.chmod(0o600)
    return path


def _bare_document(admin_key_hex: str, **overrides: object) -> PolicyDocument:
    fields: dict[str, object] = {
        "version": "2026.03.0",
        "treasury": "rCLITREASURY00000000000000000000000",
        "rail": "xrpl",
        "agents": (
            AgentSection(
                agent_id="agent-cli",
                public_key=fixtures.ed25519_public_hex(fixtures.ed25519_key("cli-test-agent")),
                allowlist_assets=("XRP",),
                per_tx_cap=(AssetLimit(asset="XRP", amount="100"),),
            ),
        ),
        "admin_public_key": admin_key_hex,
    }
    fields.update(overrides)
    return PolicyDocument(**fields)  # type: ignore[arg-type]


class TestSignCommand:
    def test_signs_a_bare_document_with_the_new_assertion_shape(
        self, tmp_path: Path, capsys
    ) -> None:
        admin = fixtures.ed25519_key("cli-test-admin")
        document = _bare_document(fixtures.ed25519_public_hex(admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))
        key_path = _write_key(tmp_path, admin)
        out_path = tmp_path / "signed.json"

        code = sign_command(doc_path, key_path=key_path, out=out_path)
        assert code == 0
        signed = SignedPolicy.from_content(json.loads(out_path.read_text()))
        assert isinstance(signed.signature, dict)
        assert signed.signature["approver_id"] == "admin"
        assert signed.signature["credential_type"] == "ed25519"
        assert verify_policy_signature(signed)

    def test_writes_to_stdout_without_out(self, tmp_path: Path, capsys) -> None:
        admin = fixtures.ed25519_key("cli-test-admin-2")
        document = _bare_document(fixtures.ed25519_public_hex(admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))
        key_path = _write_key(tmp_path, admin)

        code = sign_command(doc_path, key_path=key_path)
        assert code == 0
        out = capsys.readouterr().out
        signed = SignedPolicy.from_content(json.loads(out))
        assert verify_policy_signature(signed)

    def test_a_missing_document_is_an_error(self, tmp_path: Path, capsys) -> None:
        key_path = _write_key(tmp_path, fixtures.ed25519_key("cli-test-admin-3"))
        assert sign_command(tmp_path / "nope.json", key_path=key_path) == 2

    def test_signing_with_a_key_the_document_does_not_name_still_produces_output(
        self, tmp_path: Path, capsys
    ) -> None:
        signer = fixtures.ed25519_key("cli-test-admin-4")
        document_admin = fixtures.ed25519_key("cli-test-other-admin")
        document = _bare_document(fixtures.ed25519_public_hex(document_admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))
        key_path = _write_key(tmp_path, signer)
        out_path = tmp_path / "signed.json"

        code = sign_command(doc_path, key_path=key_path, out=out_path)
        assert code == 0
        err = capsys.readouterr().err
        assert "does not name the signing key" in err
        signed = SignedPolicy.from_content(json.loads(out_path.read_text()))
        assert not verify_policy_signature(signed)
        assert verify_policy_signature(
            signed, admin_public_key=fixtures.ed25519_public_hex(signer)
        )


class TestShowCommand:
    def test_shows_a_bare_document(self, tmp_path: Path, capsys) -> None:
        admin = fixtures.ed25519_key("cli-test-admin-5")
        document = _bare_document(fixtures.ed25519_public_hex(admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))

        assert show_command(doc_path) == 0
        out = capsys.readouterr().out
        assert "agent-cli" in out
        assert "not signed" in out

    def test_shows_a_signed_document_and_says_whether_it_verifies(
        self, tmp_path: Path, capsys
    ) -> None:
        admin = fixtures.ed25519_key("cli-test-admin-6")
        document = _bare_document(fixtures.ed25519_public_hex(admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))
        key_path = _write_key(tmp_path, admin)
        signed_path = tmp_path / "signed.json"
        assert sign_command(doc_path, key_path=key_path, out=signed_path) == 0
        capsys.readouterr()

        assert show_command(signed_path) == 0
        out = capsys.readouterr().out
        assert "verifies" in out
        assert "DOES NOT VERIFY" not in out

    def test_json_output(self, tmp_path: Path, capsys) -> None:
        admin = fixtures.ed25519_key("cli-test-admin-7")
        document = _bare_document(fixtures.ed25519_public_hex(admin))
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps(document.to_content()))

        assert show_command(doc_path, as_json=True) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["policy_hash"] == document.policy_hash()

    def test_a_malformed_document_is_an_error(self, tmp_path: Path, capsys) -> None:
        doc_path = tmp_path / "document.json"
        doc_path.write_text(json.dumps({"nonsense": True}))
        assert show_command(doc_path) == 2
