"""Small builders so the receipt tests read as receipts, not as constructors.

The settled fixture is *internally consistent* on purpose: its anchor is the
receipt's own LEFT, its transaction hash re-derives from its signed blob, and its
policy signature verifies against the envelope's signer key. Phase 2 turned those
three into real checks, so a fixture that only looked plausible would now be a
fixture that fails.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from merkl.core.intent import Amount, Intent, IssuedCurrency
from merkl.core.rail import xrpl_tx_id
from merkl.core.receipt import (
    BalanceDelta,
    Instruction,
    PolicyDecision,
    PolicyRule,
    PolicySignature,
    Reasoning,
    Receipt,
    ReceiptLeaves,
    Result,
    Settlement,
    SignerAttestation,
    authorization_commitment,
)
from merkl.shared.hashing import SHA256Hash

TREASURY = "rTREASURY0000000000000000000000000"
DESTINATION = "rDESTINATION00000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")
POLICY_HASH = SHA256Hash.from_bytes(b"policy-document-v1").hex()

_SIGNER_SEED = bytes.fromhex("01" * 32)
_SIGNER_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(_SIGNER_SEED)
SIGNER_KEY = (
    _SIGNER_KEY.public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    .hex()
)


def sign_payload(payload: bytes) -> str:
    """The fixture policy key's signature over exactly these bytes."""
    return _SIGNER_KEY.sign(payload).hex()


def settled_leaves(partial: ReceiptLeaves, **overrides: Any) -> ReceiptLeaves:
    """Append leaves 4-6 to leaves 0-3, binding them to the LEFT those leaves make."""
    left = authorization_commitment(partial)
    payload = b"merkl-fixture-payload" + left.bytes + b"trailer"
    blob = (b"\x12\x00\x00" + left.bytes + b"signed").hex()
    settlement = Settlement(
        rail="xrpl",
        tx_hash=xrpl_tx_id(bytes.fromhex(blob)),
        ledger_index=94_211_337,
        close_time="2026-01-02T03:04:41Z",
        signed_tx_blob=blob,
        observed_anchor=left.hex(),
        settlement_proof_ref="proof-0001",
        policy_signature=PolicySignature(
            algorithm="ed25519",
            public_key=SIGNER_KEY,
            signature=sign_payload(payload),
            payload=payload.hex(),
        ),
    )
    fields: dict[str, Any] = {
        "settlement": settlement,
        "result": Result(
            outcome="settled",
            engine_result="tesSUCCESS",
            balance_deltas=(
                BalanceDelta(account=TREASURY, currency=RLUSD, value="-250.00"),
                BalanceDelta(account=DESTINATION, currency=RLUSD, value="250.00"),
            ),
        ),
        "reasoning": Reasoning(
            content_hash=digest("model trace"), source="claude-code", note="invoice matched"
        ),
    }
    fields.update(overrides)
    return ReceiptLeaves(
        instruction=partial.instruction,
        intent=partial.intent,
        policy_decision=partial.policy_decision,
        signer_attestation=partial.signer_attestation,
        **fields,
    )


def digest(label: str) -> str:
    return SHA256Hash.from_bytes(label.encode()).hex()


def make_intent(**overrides: Any) -> Intent:
    fields: dict[str, Any] = {
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": DESTINATION,
        "amount": Amount(value="250.00", currency=RLUSD),
        "policy_version": "2026.01.0",
        "agent_public_key": "ed02" * 16,
        "nonce": "0123456789abcdef",
        "expires_at": "2026-01-02T03:09:05Z",
    }
    fields.update(overrides)
    return Intent(**fields)


def make_authorization(**overrides: Any) -> ReceiptLeaves:
    """Leaves 0-3 — everything that exists before the rail is touched."""
    fields: dict[str, Any] = {
        "instruction": Instruction(
            source="human_input", content_hash=digest("pay the invoice"), ref="action-0001"
        ),
        "intent": make_intent(),
        "policy_decision": PolicyDecision(
            policy_hash=POLICY_HASH,
            rules=(
                PolicyRule(name="destination_allowlist", outcome="pass", detail="known supplier"),
                PolicyRule(name="per_tx_cap", outcome="pass", detail="250.00 under 1000 RLUSD"),
            ),
            outcome="allow",
            tier="instant",
        ),
        "signer_attestation": None,
    }
    fields.update(overrides)
    return ReceiptLeaves(**fields)


def make_leaves(**overrides: Any) -> ReceiptLeaves:
    head = {k: overrides.pop(k) for k in list(overrides) if k in _AUTHORIZATION_FIELDS}
    return settled_leaves(make_authorization(**head), **overrides)


_AUTHORIZATION_FIELDS = ("instruction", "intent", "policy_decision", "signer_attestation")


def make_receipt(**overrides: Any) -> Receipt:
    leaves = overrides.pop("leaves", None) or make_leaves()
    fields: dict[str, Any] = {
        "receipt_id": "01936b2e-2222-7000-8000-000000000001",
        "agent_id": "agent-fixture",
        "signer_public_key": SIGNER_KEY,
    }
    fields.update(overrides)
    return Receipt.build(leaves=leaves, **fields)


def attested() -> SignerAttestation:
    return SignerAttestation(
        document="Y2JvcitiYXNlNjQtYXR0ZXN0YXRpb24=", policy_public_key=SIGNER_KEY
    )
