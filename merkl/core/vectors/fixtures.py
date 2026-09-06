"""Deterministic credentials for the test vectors.

**These keys are public and worthless.** They exist so that the committed
fixtures are byte-identical on every machine and so a second implementation of
the verifier has real signatures to check. Never use anything in this module for
anything that holds money.

Ed25519 is deterministic, so an Ed25519 fixture can be signed on the fly and the
vectors still regenerate identically. ECDSA is not: a P-256 signature includes a
random nonce, so signing a WebAuthn fixture at generation time would produce a
different file on every run. The WebAuthn vector is therefore a *frozen
quadruple* — key, clientDataJSON, authenticatorData and signature, all constants,
computed once and checked by :func:`check_webauthn_fixture` every time the
vectors are built. If any of the four ever stops verifying, the generator fails
rather than writing a fixture that lies.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from merkl.core.crypto import b64url_encode
from merkl.core.intent import IssuedCurrency
from merkl.core.policy.approvals import ADMIN_APPROVER_ID, ApprovalAssertion
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    CREDENTIAL_WEBAUTHN,
    AdminCredential,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    PolicyDocument,
)

FLAG_UP_UV: Final = 0x05
"""User present + user verified — what a passkey with a PIN or biometric sets."""


def ed25519_key(seed_label: str) -> ed25519.Ed25519PrivateKey:
    """A private key derived from a label. Deterministic, and only ever a fixture."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"merkl-vector-key/" + seed_label.encode()).digest()
    )


def ed25519_public_hex(key: ed25519.Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def ed25519_assertion(
    *, approver_id: str, key: ed25519.Ed25519PrivateKey, challenge: bytes, signed_at: str
) -> ApprovalAssertion:
    """An Ed25519 approval: the signature is over the raw 32-byte challenge."""
    return ApprovalAssertion(
        approver_id=approver_id,
        credential_type=CREDENTIAL_ED25519,
        signature=key.sign(challenge).hex(),
        signed_at=signed_at,
    )


def client_data_json(challenge: bytes, origin: str) -> bytes:
    """The exact clientDataJSON bytes a browser would hand back.

    Compact separators and this member order: the bytes are what is signed, so
    re-serializing the parsed object is how a verifier breaks a valid assertion.
    """
    return json.dumps(
        {
            "type": "webauthn.get",
            "challenge": b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()


def authenticator_data(rp_id: str, *, flags: int = FLAG_UP_UV, sign_count: int = 1) -> bytes:
    """rpIdHash ‖ flags ‖ signature counter — the 37 bytes every assertion carries."""
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")


def webauthn_message(auth_data: bytes, client_data: bytes) -> bytes:
    """What a WebAuthn authenticator actually signs."""
    return auth_data + hashlib.sha256(client_data).digest()


def p256_key(scalar: int) -> ec.EllipticCurvePrivateKey:
    """A P-256 private key from a fixed scalar. Deterministic; a fixture only."""
    return ec.derive_private_key(scalar, ec.SECP256R1())


def p256_public_hex(key: ec.EllipticCurvePrivateKey) -> str:
    """The uncompressed SEC1 point in hex, which is how a policy stores a passkey."""
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


def sign_webauthn(
    key: ec.EllipticCurvePrivateKey, auth_data: bytes, client_data: bytes
) -> str:
    """Sign a WebAuthn message. Randomized — use only where determinism is not needed."""
    return key.sign(webauthn_message(auth_data, client_data), ec.ECDSA(hashes.SHA256())).hex()


# --------------------------------------------------------------------------- #
# The frozen WebAuthn quadruple
# --------------------------------------------------------------------------- #

P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

WEBAUTHN_SCALAR: Final = (
    int.from_bytes(hashlib.sha256(b"merkl-vector-key/passkey").digest(), "big") % (P256_ORDER - 1)
) + 1
WEBAUTHN_RP_ID: Final = "app.merkl.ai"
WEBAUTHN_ORIGIN: Final = "https://app.merkl.ai"
WEBAUTHN_APPROVER_ID: Final = "alice@example.com"
WEBAUTHN_SIGNED_AT: Final = "2026-01-02T03:20:11Z"
WEBAUTHN_CHALLENGE: Final = hashlib.sha256(b"merkl-webauthn-vector-challenge").digest()

WEBAUTHN_SIGNATURE: Final = (
    "30450220025ef7f0f0dc1f7eb89356439860ae1b983df07a1913ec5095411eb618b82001"
    "022100bb6a98902b404809dd1be1425c64e217754aa677d5e251b11d991554ef087244"
)
"""Computed once with the key above; frozen so the vectors never change under CI."""


def webauthn_credential() -> ApproverCredential:
    return ApproverCredential(
        id=WEBAUTHN_APPROVER_ID,
        credential_type=CREDENTIAL_WEBAUTHN,
        public_key=p256_public_hex(p256_key(WEBAUTHN_SCALAR)),
        origins=(WEBAUTHN_ORIGIN,),
        rp_id=WEBAUTHN_RP_ID,
        user_verification=True,
    )


def webauthn_assertion() -> ApprovalAssertion:
    return ApprovalAssertion(
        approver_id=WEBAUTHN_APPROVER_ID,
        credential_type=CREDENTIAL_WEBAUTHN,
        signature=WEBAUTHN_SIGNATURE,
        client_data_json=client_data_json(WEBAUTHN_CHALLENGE, WEBAUTHN_ORIGIN).hex(),
        authenticator_data=authenticator_data(WEBAUTHN_RP_ID).hex(),
        signed_at=WEBAUTHN_SIGNED_AT,
    )


def check_webauthn_fixture() -> None:
    """Fail loudly if the frozen quadruple no longer verifies."""
    from merkl.core.policy.approvals import verify_assertion

    check = verify_assertion(webauthn_assertion(), WEBAUTHN_CHALLENGE, webauthn_credential())
    if not check.valid:
        raise AssertionError(f"the frozen webauthn fixture no longer verifies: {check.detail}")


# --------------------------------------------------------------------------- #
# A policy document signed by a WebAuthn admin (plan D16, extended)
# --------------------------------------------------------------------------- #
#
# Self-contained on purpose: this document exists only so an admin-signature
# vector has a real `policy_hash` to sign, and it must never move out from
# under the frozen signature below just because the receipts fixture's own
# policy changed shape. Same "frozen quadruple" reasoning as the approvals
# fixture above — ECDSA signing is randomized, so the signature is computed
# once and checked by :func:`check_admin_webauthn_fixture` forever after.

ADMIN_WEBAUTHN_SCALAR: Final = (
    int.from_bytes(hashlib.sha256(b"merkl-vector-key/admin-passkey").digest(), "big")
    % (P256_ORDER - 1)
) + 1
ADMIN_RP_ID: Final = "admin.merkl.ai"
ADMIN_ORIGIN: Final = "https://admin.merkl.ai"
ADMIN_SIGNED_AT: Final = "2026-02-01T09:00:00Z"

ADMIN_VECTOR_TREASURY: Final = "rADMINVECTORTREASURY0000000000000000"
ADMIN_VECTOR_DESTINATION: Final = "rADMINVECTORDEST00000000000000000000"
ADMIN_VECTOR_ISSUER: Final = "rADMINVECTORISSUER000000000000000000"

ADMIN_WEBAUTHN_SIGNATURE: Final = (
    "304502207e34f127e51e3965dc887437c12a776583b710241cfa24e241eb75ef7df7771b"
    "022100f3c697019a4ca0d16765a2db430dec1dccfca288270ba6c2406a44319433b94a"
)
"""Computed once with the admin passkey above; frozen so the vectors never change under CI."""


def admin_test_document(**overrides: Any) -> PolicyDocument:
    """A minimal, fully deterministic policy document, for admin-signature vectors only."""
    fields: dict[str, Any] = {
        "version": "2026.02.0",
        "treasury": ADMIN_VECTOR_TREASURY,
        "rail": "xrpl",
        "agents": (
            AgentSection(
                agent_id="agent-admin-vector",
                public_key=ed25519_public_hex(ed25519_key("admin-vector-agent")),
                allowlist_destinations=(ADMIN_VECTOR_DESTINATION,),
                allowlist_assets=(
                    IssuedCurrency(code="RLUSD", issuer=ADMIN_VECTOR_ISSUER),
                ),
                per_tx_cap=(
                    AssetLimit(
                        asset=IssuedCurrency(code="RLUSD", issuer=ADMIN_VECTOR_ISSUER),
                        amount="500.00",
                    ),
                ),
            ),
        ),
        "admin_public_key": ed25519_public_hex(ed25519_key("admin-vector-legacy-admin")),
    }
    fields.update(overrides)
    return PolicyDocument(**fields)


def admin_webauthn_credential() -> AdminCredential:
    return AdminCredential(
        credential_type=CREDENTIAL_WEBAUTHN,
        public_key=p256_public_hex(p256_key(ADMIN_WEBAUTHN_SCALAR)),
        origins=(ADMIN_ORIGIN,),
        rp_id=ADMIN_RP_ID,
        user_verification=True,
    )


def admin_webauthn_document() -> PolicyDocument:
    """The document the frozen admin WebAuthn signature was actually made over."""
    return admin_test_document(admin_public_key=None, admin=admin_webauthn_credential())


def admin_webauthn_assertion(*, signature: str = ADMIN_WEBAUTHN_SIGNATURE) -> ApprovalAssertion:
    digest = bytes.fromhex(admin_webauthn_document().policy_hash())
    return ApprovalAssertion(
        approver_id=ADMIN_APPROVER_ID,
        credential_type=CREDENTIAL_WEBAUTHN,
        signature=signature,
        client_data_json=client_data_json(digest, ADMIN_ORIGIN).hex(),
        authenticator_data=authenticator_data(ADMIN_RP_ID).hex(),
        signed_at=ADMIN_SIGNED_AT,
    )


def check_admin_webauthn_fixture() -> None:
    """Fail loudly if the frozen admin WebAuthn signature no longer verifies."""
    from merkl.core.policy.approvals import verify_assertion

    document = admin_webauthn_document()
    digest = bytes.fromhex(document.policy_hash())
    credential_with_id = ApproverCredential(
        id=ADMIN_APPROVER_ID,
        credential_type=CREDENTIAL_WEBAUTHN,
        public_key=admin_webauthn_credential().public_key,
        origins=(ADMIN_ORIGIN,),
        rp_id=ADMIN_RP_ID,
        user_verification=True,
    )
    check = verify_assertion(admin_webauthn_assertion(), digest, credential_with_id)
    if not check.valid:
        raise AssertionError(
            f"the frozen admin webauthn fixture no longer verifies: {check.detail}"
        )
