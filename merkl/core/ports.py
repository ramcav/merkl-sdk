"""Ports — the Protocols core declares and adapters implement (plan section 4).

Hexagonal, so the direction of every arrow points inward: ``merkl.core`` names
what it needs, and ``merkl.signer``, ``merkl.adapters`` and ``merkl.sdk``
implement it. Nothing here imports an adapter, and nothing here does I/O — these
are shapes, not implementations.

Ports are ``async`` because their implementations talk to ledgers and sockets.
The pure core never awaits anything; the orchestration in ``merkl.sdk`` does.

Two families of settlement exist. The *initiating* family, below, is the one
where Merkl moves the money: the transaction does not exist until the policy key
signs it. The *authorizing* family — card networks, where the money moves and
Merkl approves or declines — is a future port, and adding it touches
orchestration rather than this file.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from merkl.core.canonical import JSONValue
from merkl.core.intent import Intent
from merkl.core.policy.approvals import ApprovalAssertion
from merkl.core.policy.engine import Decision, RiskScore
from merkl.core.policy.state import Outflow
from merkl.core.rail import (
    AnchorCapability,
    PartialTx,
    SettlementProof,
    SettlementRef,
    Signature,
    SignedTx,
    UnsignedTx,
)
from merkl.core.receipt import Envelope, ReceiptLeaves


@runtime_checkable
class SettlementPort(Protocol):
    """A rail Merkl can initiate a payment on.

    ``prepare`` is called twice for one payment: once with the anchor placeholder,
    to get bytes the signer can inspect and sign, and once with the real
    commitment, to reproduce those bytes with LEFT written in. An adapter must
    make the second call byte-identical to the first except for the anchor — that
    equality is the caller's proof that the transaction it submits is the
    transaction the policy key authorized.
    """

    async def prepare(self, intent: Intent, commitment: str) -> UnsignedTx:
        """Build the rail's unsigned transaction with ``commitment`` in its anchor field."""
        ...

    async def agent_sign(self, unsigned: UnsignedTx) -> PartialTx:
        """Sign with the agent's key. One of the two signatures quorum requires."""
        ...

    async def attach_policy_signature(self, partial: PartialTx, sig: Signature) -> SignedTx:
        """Add the policy key's signature and produce the submittable blob."""
        ...

    async def submit(self, signed: SignedTx) -> SettlementRef:
        """Submit and wait for validation. Returns what the ledger recorded."""
        ...

    async def settlement_proof(self, ref: SettlementRef) -> SettlementProof | None:
        """Evidence captured at settlement time (plan D20), or None if unavailable."""
        ...

    async def history(self, treasury: str, since: str) -> Sequence[Outflow]:
        """Validated outflows since an instant — for state (D2) and reconciliation (D17)."""
        ...

    def anchor_capability(self) -> AnchorCapability:
        """How strongly this rail can carry a commitment."""
        ...


@runtime_checkable
class SignerPort(Protocol):
    """The process that holds the policy key and is the only policy authority.

    It never accepts a decision from the caller (plan D1). ``propose`` takes an
    intent and gives back a verdict; there is deliberately no argument through
    which a caller could suggest one.
    """

    async def public_key(self) -> str:
        """The policy public key, lowercase hex."""
        ...

    async def attestation(self) -> JSONValue:
        """The enclave attestation document, or ``None`` for a dev signer (plan D3)."""
        ...

    async def propose(self, request: JSONValue) -> JSONValue:
        """Evaluate a signed agent request (D15) and return a decision result."""
        ...

    async def approve(self, challenge: str, assertions: Sequence[ApprovalAssertion]) -> JSONValue:
        """Resolve an escalation with collected approvals (plan D11)."""
        ...

    async def health(self) -> JSONValue:
        """Liveness, the pinned policy, the state sequence, and whether it is attested."""
        ...


@runtime_checkable
class ReceiptStorePort(Protocol):
    """Where receipts are kept locally before, and regardless of, the notary."""

    async def put(self, envelope: Envelope, leaves: ReceiptLeaves) -> None: ...

    async def get(self, receipt_id: str) -> tuple[Envelope, ReceiptLeaves] | None: ...

    async def list(
        self, treasury: str, agent_id: str | None = None, since: str | None = None
    ) -> Sequence[Envelope]: ...


@runtime_checkable
class ApprovalPort(Protocol):
    """The queue humans answer. The signer verifies; this only relays (plan D11)."""

    async def enqueue(self, escalation: JSONValue) -> None: ...

    async def collect(self, challenge: str) -> Sequence[ApprovalAssertion]: ...


@runtime_checkable
class RiskPort(Protocol):
    """Destination risk. Called by the signer, never by the agent."""

    async def score(self, destination: str) -> RiskScore: ...


@runtime_checkable
class ClockPort(Protocol):
    """The only clock. Injected everywhere, so any moment can be replayed."""

    def now(self) -> str:
        """The current instant, as a canonical ``...Z`` string."""
        ...


__all__ = [
    "ApprovalPort",
    "ClockPort",
    "Decision",
    "ReceiptStorePort",
    "RiskPort",
    "SettlementPort",
    "SignerPort",
]
