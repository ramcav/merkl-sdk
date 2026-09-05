"""Small builders so the receipt tests read as receipts, not as constructors."""

from __future__ import annotations

from typing import Any

from merkl.core.intent import Amount, Intent, IssuedCurrency
from merkl.core.receipt import (
    BalanceDelta,
    Instruction,
    PolicyDecision,
    PolicyRule,
    Reasoning,
    Receipt,
    ReceiptLeaves,
    Result,
    Settlement,
    SignerAttestation,
)
from merkl.shared.hashing import SHA256Hash

TREASURY = "rTREASURY0000000000000000000000000"
DESTINATION = "rDESTINATION00000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")
POLICY_HASH = SHA256Hash.from_bytes(b"policy-document-v1").hex()
SIGNER_KEY = "ed01" * 16


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


def make_leaves(**overrides: Any) -> ReceiptLeaves:
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
        "settlement": Settlement(
            rail="xrpl",
            tx_hash="9A0F1C" + "0" * 58,
            ledger_index=94_211_337,
            close_time="2026-01-02T03:04:41Z",
            signed_tx_blob="12000022" + "ab" * 40,
            observed_anchor=digest("left-anchor"),
            settlement_proof_ref="proof-0001",
        ),
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
    return ReceiptLeaves(**fields)


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
