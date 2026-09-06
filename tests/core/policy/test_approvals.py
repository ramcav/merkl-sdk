"""Approval assertions, driven by the committed vectors and then pushed further.

The vectors are the contract with the JavaScript verifier, so the first job is to
prove the Python implementation agrees with them exactly. The rest of the file
covers the cases a vector file cannot hold cheaply — a freshly signed passkey
assertion, a mismatched credential type, quorum arithmetic.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from merkl.core.policy.approvals import (
    ApprovalAssertion,
    ApprovalError,
    verify_assertion,
    verify_quorum,
)
from merkl.core.policy.document import ApproverCredential
from merkl.core.vectors import VECTORS_DIR, fixtures

VECTORS = json.loads((VECTORS_DIR / "approvals.json").read_text())
CHALLENGE = fixtures.WEBAUTHN_CHALLENGE


def credential_of(case: dict) -> ApproverCredential:
    return ApproverCredential.from_content(case["credential"])


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_assertion_vectors(case: dict) -> None:
    check = verify_assertion(
        ApprovalAssertion.from_content(case["assertion"]),
        bytes.fromhex(case["challenge"]),
        credential_of(case),
    )
    assert check.valid is case["expected_valid"], check.detail


@pytest.mark.parametrize("case", VECTORS["quorum_cases"], ids=lambda c: c["name"])
def test_quorum_vectors(case: dict) -> None:
    result = verify_quorum(
        [ApprovalAssertion.from_content(a) for a in case["assertions"]],
        bytes.fromhex(case["challenge"]),
        [ApproverCredential.from_content(a) for a in case["approvers"]],
        case["quorum"],
    )
    assert result.reached is case["expected_reached"]
    assert list(result.accepted) == case["expected_accepted"]


class TestWebAuthn:
    def _fresh(
        self,
        challenge: bytes,
        *,
        origin: str = fixtures.WEBAUTHN_ORIGIN,
        flags: int = 0x05,
    ):
        key = fixtures.p256_key(fixtures.WEBAUTHN_SCALAR)
        client_data = fixtures.client_data_json(challenge, origin)
        auth_data = fixtures.authenticator_data(fixtures.WEBAUTHN_RP_ID, flags=flags)
        signature = key.sign(
            fixtures.webauthn_message(auth_data, client_data), ec.ECDSA(hashes.SHA256())
        )
        return ApprovalAssertion(
            approver_id=fixtures.WEBAUTHN_APPROVER_ID,
            credential_type="webauthn",
            signature=signature.hex(),
            client_data_json=client_data.hex(),
            authenticator_data=auth_data.hex(),
            signed_at="2026-01-02T03:20:11Z",
        )

    def test_a_freshly_signed_assertion_verifies(self) -> None:
        challenge = hashlib.sha256(b"a different escalation").digest()
        check = verify_assertion(
            self._fresh(challenge), challenge, fixtures.webauthn_credential()
        )
        assert check.valid, check.detail

    def test_a_reserialized_client_data_json_breaks_the_signature(self) -> None:
        """The bytes are what was signed; pretty-printing them is not the same document."""
        challenge = hashlib.sha256(b"reserialize me").digest()
        assertion = self._fresh(challenge)
        raw = bytes.fromhex(assertion.client_data_json)
        rewritten = json.dumps(json.loads(raw), indent=2).encode()
        tampered = dataclasses.replace(assertion, client_data_json=rewritten.hex())
        check = verify_assertion(tampered, challenge, fixtures.webauthn_credential())
        assert not check.valid

    def test_a_type_other_than_webauthn_get_is_refused(self) -> None:
        challenge = hashlib.sha256(b"registration not assertion").digest()
        assertion = self._fresh(challenge)
        client_data = json.loads(bytes.fromhex(assertion.client_data_json))
        client_data["type"] = "webauthn.create"
        tampered = dataclasses.replace(
            assertion,
            client_data_json=json.dumps(client_data, separators=(",", ":")).encode().hex(),
        )
        check = verify_assertion(tampered, challenge, fixtures.webauthn_credential())
        assert not check.valid
        assert "webauthn.get" in check.detail

    def test_truncated_authenticator_data_is_refused(self) -> None:
        assertion = dataclasses.replace(
            fixtures.webauthn_assertion(), authenticator_data=("ab" * 10)
        )
        check = verify_assertion(assertion, CHALLENGE, fixtures.webauthn_credential())
        assert not check.valid
        assert "37" in check.detail


class TestShape:
    def test_an_ed25519_assertion_carries_no_webauthn_members(self) -> None:
        with pytest.raises(ApprovalError, match="neither"):
            ApprovalAssertion(
                approver_id="alice",
                credential_type="ed25519",
                signature="ab" * 64,
                signed_at="2026-01-02T03:20:11Z",
                client_data_json="ab",
            )

    def test_a_webauthn_assertion_carries_both(self) -> None:
        with pytest.raises(ApprovalError, match="client_data_json"):
            ApprovalAssertion(
                approver_id="alice",
                credential_type="webauthn",
                signature="ab" * 70,
                signed_at="2026-01-02T03:20:11Z",
            )

    def test_the_assertion_round_trips_through_its_committed_form(self) -> None:
        assertion = fixtures.webauthn_assertion()
        assert ApprovalAssertion.from_content(assertion.to_content()) == assertion

    def test_an_unknown_member_is_rejected(self) -> None:
        content = fixtures.webauthn_assertion().to_content()
        content["extra"] = "x"
        with pytest.raises(ApprovalError, match="unknown members"):
            ApprovalAssertion.from_content(content)


class TestQuorum:
    def _party(self, label: str) -> tuple[ApproverCredential, ApprovalAssertion]:
        key = fixtures.ed25519_key(label)
        credential = ApproverCredential(
            id=label, credential_type="ed25519", public_key=fixtures.ed25519_public_hex(key)
        )
        assertion = fixtures.ed25519_assertion(
            approver_id=label, key=key, challenge=CHALLENGE, signed_at="2026-01-02T03:20:11Z"
        )
        return credential, assertion

    def test_a_mixed_quorum_of_a_passkey_and_a_key_counts(self) -> None:
        credential, assertion = self._party("quorum-alice")
        result = verify_quorum(
            [assertion, fixtures.webauthn_assertion()],
            CHALLENGE,
            [credential, fixtures.webauthn_credential()],
            2,
        )
        assert result.reached
        assert set(result.accepted) == {"quorum-alice", fixtures.WEBAUTHN_APPROVER_ID}

    def test_the_challenge_must_be_thirty_two_bytes(self) -> None:
        credential, assertion = self._party("quorum-bob")
        with pytest.raises(ApprovalError, match="32 bytes"):
            verify_assertion(assertion, b"short", credential)

    def test_rejections_are_reported_rather_than_swallowed(self) -> None:
        credential, _ = self._party("quorum-carol")
        _, other = self._party("quorum-dave")
        result = verify_quorum(
            [dataclasses.replace(other, approver_id="quorum-carol")],
            CHALLENGE,
            [credential],
            1,
        )
        assert not result.reached
        assert len(result.rejected) == 1
