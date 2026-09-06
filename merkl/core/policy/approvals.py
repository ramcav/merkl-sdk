"""Approval assertions — what a human signature over an escalation looks like.

An escalation's challenge is ``LEFT_pre``: the authorization commitment computed
before the decision leaf was final (``docs/RECEIPT-SPEC.md`` section 3.2). An
approver signs those 32 bytes, and the assertion they produce is committed
verbatim in ``policy_decision.escalation.approvals[]``. Phase 1 left that array
opaque; this module pins its shape.

```json
{"approver_id": "alice@example.com",
 "credential_type": "webauthn",
 "signature": "<hex DER>",
 "client_data_json": "<hex of the raw clientDataJSON bytes>",
 "authenticator_data": "<hex>",
 "signed_at": "2026-01-02T03:20:11Z"}
```

Everything binary is lowercase hex, including ``client_data_json`` — the bytes
matter, not the text, and re-serializing the JSON would change the signature. The
*inner* ``challenge`` member of clientDataJSON stays base64url, because that is
what the WebAuthn spec puts there and the browser is not ours to change.

An Ed25519 assertion omits the two WebAuthn members and signs the raw challenge.

Nothing here trusts the assertion's own account of who signed: ``approver_id``
selects a credential from the policy document, and the signature is checked
against *that* key.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    drop_none,
    instant,
    token,
)
from merkl.core.crypto import CryptoError, b64url_decode, ed25519_verify, hex_bytes, p256_verify
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    CREDENTIAL_TYPES,
    CREDENTIAL_WEBAUTHN,
    AdminCredential,
    ApproverCredential,
    PolicyError,
    SignedPolicy,
)

WEBAUTHN_GET: Final = "webauthn.get"

ADMIN_APPROVER_ID: Final = "admin"
"""The fixed ``approver_id`` an admin's assertion-shaped signature carries.

There is one admin, not a roster, so nothing needs to select *which* credential
signed the way ``verify_quorum`` selects among approvers — but reusing
:class:`ApprovalAssertion` and :func:`verify_assertion` means the shape still
carries the field. Any other value is a signature that does not name the admin
role and is rejected before a key is even considered.
"""

FLAG_USER_PRESENT: Final = 0x01
FLAG_USER_VERIFIED: Final = 0x04

RP_ID_HASH_BYTES: Final = 32
AUTHENTICATOR_DATA_MIN_BYTES: Final = 37
"""32 bytes of rpIdHash, one flags byte, four of signature counter."""


class ApprovalError(ContentError):
    """Raised when an approval assertion is not well formed."""

    error_code = "approval_error"


@dataclasses.dataclass(frozen=True)
class ApprovalAssertion:
    """One approver's signature over an escalation challenge (plan D11)."""

    approver_id: str
    credential_type: str
    signature: str
    signed_at: str
    client_data_json: str | None = None
    authenticator_data: str | None = None

    def __post_init__(self) -> None:
        token(self.approver_id, "approval.approver_id", max_length=128)
        if self.credential_type not in CREDENTIAL_TYPES:
            raise ApprovalError(
                f"approval.credential_type must be one of {list(CREDENTIAL_TYPES)}, "
                f"got {self.credential_type!r}"
            )
        token(self.signature, "approval.signature", max_length=2048)
        instant(self.signed_at, "approval.signed_at")
        if self.credential_type == CREDENTIAL_WEBAUTHN:
            if self.client_data_json is None or self.authenticator_data is None:
                raise ApprovalError(
                    "a webauthn approval carries client_data_json and authenticator_data"
                )
            token(self.client_data_json, "approval.client_data_json", max_length=16384)
            token(self.authenticator_data, "approval.authenticator_data", max_length=8192)
        elif self.client_data_json is not None or self.authenticator_data is not None:
            raise ApprovalError(
                "an ed25519 approval carries neither client_data_json nor authenticator_data"
            )

    def to_content(self) -> JSONObject:
        """The canonical object committed in ``escalation.approvals[]``."""
        return drop_none(
            {
                "approver_id": self.approver_id,
                "credential_type": self.credential_type,
                "signature": self.signature,
                "client_data_json": self.client_data_json,
                "authenticator_data": self.authenticator_data,
                "signed_at": self.signed_at,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> ApprovalAssertion:
        if not isinstance(data, Mapping):
            raise ApprovalError(f"approval must be an object, got {type(data).__name__}")
        allowed = {
            "approver_id",
            "credential_type",
            "signature",
            "client_data_json",
            "authenticator_data",
            "signed_at",
        }
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ApprovalError(f"approval has unknown members: {unknown}")
        for key in ("approver_id", "credential_type", "signature", "signed_at"):
            if key not in data:
                raise ApprovalError(f"approval requires {key}")
        return cls(
            approver_id=data["approver_id"],
            credential_type=data["credential_type"],
            signature=data["signature"],
            signed_at=data["signed_at"],
            client_data_json=data.get("client_data_json"),
            authenticator_data=data.get("authenticator_data"),
        )


@dataclasses.dataclass(frozen=True)
class AssertionCheck:
    """Whether one assertion counted, and why it did not."""

    approver_id: str
    valid: bool
    detail: str = ""


def verify_assertion(
    assertion: ApprovalAssertion,
    challenge: bytes,
    credential: ApproverCredential,
) -> AssertionCheck:
    """Check one assertion against one credential and one challenge.

    Never raises for a bad signature or a mismatched origin: those are findings,
    and the caller reports them next to the approvals that did count. A malformed
    *credential* still raises, because that is a broken policy document rather
    than a failed approval.
    """
    if assertion.approver_id != credential.id:
        return AssertionCheck(
            assertion.approver_id,
            False,
            f"assertion names {assertion.approver_id!r}, credential is {credential.id!r}",
        )
    if assertion.credential_type != credential.credential_type:
        return AssertionCheck(
            assertion.approver_id,
            False,
            f"policy registers {credential.id} as {credential.credential_type}, "
            f"assertion is {assertion.credential_type}",
        )
    if len(challenge) != RP_ID_HASH_BYTES:
        raise ApprovalError(f"challenge must be 32 bytes, got {len(challenge)}")
    if assertion.credential_type == CREDENTIAL_ED25519:
        return _verify_ed25519(assertion, challenge, credential)
    return _verify_webauthn(assertion, challenge, credential)


def _verify_ed25519(
    assertion: ApprovalAssertion, challenge: bytes, credential: ApproverCredential
) -> AssertionCheck:
    try:
        ok = ed25519_verify(credential.public_key, assertion.signature, challenge)
    except ContentError as exc:
        return AssertionCheck(assertion.approver_id, False, str(exc))
    return AssertionCheck(
        assertion.approver_id,
        ok,
        "ed25519 signature over the challenge" if ok else "ed25519 signature does not verify",
    )


def _verify_webauthn(
    assertion: ApprovalAssertion, challenge: bytes, credential: ApproverCredential
) -> AssertionCheck:
    def no(detail: str) -> AssertionCheck:
        return AssertionCheck(assertion.approver_id, False, detail)

    try:
        client_data_bytes = hex_bytes(assertion.client_data_json, "approval.client_data_json")
        authenticator_data = hex_bytes(assertion.authenticator_data, "approval.authenticator_data")
    except ContentError as exc:
        return no(str(exc))

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return no(f"clientDataJSON is not JSON: {exc}")
    if not isinstance(client_data, dict):
        return no("clientDataJSON is not an object")

    if client_data.get("type") != WEBAUTHN_GET:
        return no(f"clientDataJSON type is {client_data.get('type')!r}, expected {WEBAUTHN_GET!r}")

    raw_challenge = client_data.get("challenge")
    if not isinstance(raw_challenge, str):
        return no("clientDataJSON has no challenge")
    try:
        signed_challenge = b64url_decode(raw_challenge, "clientDataJSON.challenge")
    except ContentError as exc:
        return no(str(exc))
    if signed_challenge != challenge:
        return no("the approver signed a different challenge")

    origin = client_data.get("origin")
    if credential.origins and (not isinstance(origin, str) or origin not in credential.origins):
        return no(f"origin {origin!r} is not one of the approver's allowed origins")

    if len(authenticator_data) < AUTHENTICATOR_DATA_MIN_BYTES:
        return no(f"authenticatorData is {len(authenticator_data)} bytes, expected at least 37")
    rp_id = credential.effective_rp_id
    if rp_id is None:  # pragma: no cover - the credential rejects this at construction
        return no("the approver's credential has no rp_id")
    if authenticator_data[:RP_ID_HASH_BYTES] != hashlib.sha256(rp_id.encode()).digest():
        return no(f"rpIdHash does not match {rp_id!r}")

    flags = authenticator_data[RP_ID_HASH_BYTES]
    if not flags & FLAG_USER_PRESENT:
        return no("the user-present flag is not set")
    if credential.user_verification and not flags & FLAG_USER_VERIFIED:
        return no("the policy requires user verification and the flag is not set")

    message = authenticator_data + hashlib.sha256(client_data_bytes).digest()
    try:
        ok = p256_verify(credential.public_key, assertion.signature, message)
    except ContentError as exc:
        return no(str(exc))
    return AssertionCheck(
        assertion.approver_id,
        ok,
        "webauthn assertion verified" if ok else "webauthn signature does not verify",
    )


@dataclasses.dataclass(frozen=True)
class QuorumResult:
    """How many distinct approvers signed, and what happened to the rest."""

    quorum: int
    checks: tuple[AssertionCheck, ...]
    accepted: tuple[str, ...]

    @property
    def reached(self) -> bool:
        return len(self.accepted) >= self.quorum

    @property
    def rejected(self) -> tuple[AssertionCheck, ...]:
        return tuple(c for c in self.checks if not c.valid)

    def detail(self) -> str:
        return f"{len(self.accepted)} of {self.quorum} approvals"


def verify_quorum(
    assertions: Sequence[ApprovalAssertion],
    challenge: bytes,
    approvers: Sequence[ApproverCredential],
    quorum: int,
) -> QuorumResult:
    """Count distinct valid approvers against the required quorum.

    Distinct is the point: five assertions from one approver are one approval.
    An approver the policy does not name contributes nothing, and a second
    assertion from an approver who already counted is ignored rather than
    rejected — replaying your own signature is not an attack, it is a retry.
    """
    by_id = {credential.id: credential for credential in approvers}
    checks: list[AssertionCheck] = []
    accepted: list[str] = []
    for assertion in assertions:
        credential = by_id.get(assertion.approver_id)
        if credential is None:
            checks.append(
                AssertionCheck(
                    assertion.approver_id,
                    False,
                    f"{assertion.approver_id!r} is not an approver in this policy",
                )
            )
            continue
        if assertion.approver_id in accepted:
            checks.append(
                AssertionCheck(assertion.approver_id, True, "duplicate assertion, already counted")
            )
            continue
        check = verify_assertion(assertion, challenge, credential)
        checks.append(check)
        if check.valid:
            accepted.append(assertion.approver_id)
    return QuorumResult(quorum=quorum, checks=tuple(checks), accepted=tuple(accepted))


def assertions_from_content(values: Sequence[Any]) -> tuple[ApprovalAssertion, ...]:
    """Parse the ``approvals[]`` array of a decision leaf back into assertions."""
    return tuple(ApprovalAssertion.from_content(v) for v in values)


# --------------------------------------------------------------------------- #
# Policy signatures (plan D16, extended) — the admin role reuses this module
# --------------------------------------------------------------------------- #


def verify_policy_signature(
    signed: SignedPolicy,
    *,
    admin_public_key: str | None = None,
    admin: AdminCredential | None = None,
) -> bool:
    """True when ``signed.signature`` is valid *and* made by the credential pinned.

    Two independent things vary, and this function is the one place both are
    decided:

    * **which credential is trusted.** ``admin`` pins a full credential,
      including a WebAuthn admin's ``origins`` — pass this when you hold the
      admin the signer last pinned (:class:`~merkl.signer.engine.SignerEngine`
      does). ``admin_public_key`` pins a legacy Ed25519 key only, the one shape
      this parameter has ever accepted. Passing neither trusts the document's
      own ``admin`` / ``admin_public_key`` member — the same thing an unpinned
      check has always done, and exactly what a forged document exploits by
      nominating itself, so a real ``policy_update`` should always pin one.
    * **which wire shape the signature is.** A ``str`` is the legacy scheme:
      Ed25519 over :meth:`PolicyDocument.pre_image`. A ``dict`` is an
      ``ApprovalAssertion``-shaped object — Ed25519 or WebAuthn — over the
      32-byte :meth:`PolicyDocument.policy_hash`, checked with the exact
      function an approver's assertion is checked with
      (:func:`verify_assertion`). One verification path for both roles: no
      second WebAuthn parser for the admin.
    """
    if admin is not None and admin_public_key is not None:
        raise PolicyError("pass admin or admin_public_key to verify_policy_signature, not both")
    if admin is not None:
        pinned = admin
    elif admin_public_key is not None:
        pinned = AdminCredential(credential_type=CREDENTIAL_ED25519, public_key=admin_public_key)
    else:
        pinned = signed.document.effective_admin

    if signed.signer_public_key != pinned.public_key:
        return False

    if isinstance(signed.signature, str):
        if pinned.credential_type != CREDENTIAL_ED25519:
            return False
        try:
            return ed25519_verify(
                signed.signer_public_key, signed.signature, signed.document.pre_image()
            )
        except CryptoError:
            return False

    try:
        assertion = ApprovalAssertion.from_content(signed.signature)
    except ApprovalError:
        return False
    if assertion.approver_id != ADMIN_APPROVER_ID:
        return False
    credential = ApproverCredential(
        id=ADMIN_APPROVER_ID,
        credential_type=pinned.credential_type,
        public_key=pinned.public_key,
        origins=pinned.origins,
        rp_id=pinned.rp_id,
        user_verification=pinned.user_verification,
    )
    try:
        check = verify_assertion(
            assertion, bytes.fromhex(signed.document.policy_hash()), credential
        )
    except (ApprovalError, ValueError):
        return False
    return check.valid
