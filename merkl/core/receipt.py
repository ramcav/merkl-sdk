"""Receipt v1 — seven leaves, two halves, one root.

A receipt is what a co-signed transaction leaves behind. Its seven leaves are
hashed in a fixed order and padded to eight by repeating the last one, which
splits the tree in half (plan D5):

* **LEFT** = leaves 0-3 (instruction, intent, policy_decision, signer_attestation).
  This is the *authorization commitment*: it exists before anything settles, it is
  what goes in the rail's anchor field, and it is what the policy key signs.
* **RIGHT** = leaves 4-7 (settlement, result, reasoning, reasoning again as
  padding). Appended after settlement.
* **ROOT** = ``SHA-256(LEFT || RIGHT)``.

Nothing here reaches the network, a clock or a key. Signature, attestation and
ledger checks belong to later phases and appear in the verification result as
named, deferred checks rather than as silence — see :data:`DEFERRED_CHECKS`.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    JSONValue,
    decimal_string,
    drop_none,
    ensure_canonical_content,
    hex_digest,
    instant,
    text,
    token,
)
from merkl.core.intent import CurrencyRef, Intent, currency_content, currency_from_content
from merkl.core.leaf import receipt_leaf
from merkl.core.merkle import MerkleProof, MerkleTree
from merkl.shared.errors import ValidationError
from merkl.shared.hashing import SHA256Hash, canonical_bytes

RECEIPT_VERSION: Final = "merkl-receipt-v1"

LEAF_NAMES: Final[tuple[str, ...]] = (
    "instruction",
    "intent",
    "policy_decision",
    "signer_attestation",
    "settlement",
    "result",
    "reasoning",
)
"""The seven leaves, in the order they are hashed. The order is part of the format."""

LEAF_COUNT: Final = len(LEAF_NAMES)
PADDED_LEAF_COUNT: Final = 8
REQUIRED_LEAVES: Final[tuple[str, ...]] = ("instruction", "intent", "policy_decision")
"""Leaves every receipt has, including a denied one (plan D14)."""

LEFT_LEAVES: Final = slice(0, 4)
RIGHT_LEAVES: Final = slice(4, 8)
HALF_LEVEL: Final = 2
"""Tree level at which LEFT and RIGHT live: ``subtree_root(2, 0)`` and ``(2, 1)``."""


class ReceiptError(ContentError):
    """Raised when a receipt, or part of one, is not well formed."""

    error_code = "receipt_error"


class InstructionSource(enum.StrEnum):
    """Where the instruction came from (plan D13)."""

    HUMAN_INPUT = "human_input"
    MANDATE = "mandate"
    SYSTEM = "system"


class PolicyOutcome(enum.StrEnum):
    """The signer's verdict on an intent."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class ResultOutcome(enum.StrEnum):
    """How the attempt ended."""

    SETTLED = "settled"
    DENIED = "denied"
    FAILED = "failed"
    EXPIRED = "expired"


def _member(data: Mapping[str, Any], key: str, owner: str) -> Any:
    if key not in data:
        raise ReceiptError(f"{owner} requires {key}")
    return data[key]


def _reject_unknown(data: Mapping[str, Any], allowed: set[str], owner: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ReceiptError(f"{owner} has unknown members: {unknown}")


def _object(data: Any, owner: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise ReceiptError(f"{owner} must be an object, got {type(data).__name__}")
    return data


# --------------------------------------------------------------------------- #
# Leaf 0 — instruction
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Instruction:
    """Leaf 0: what set this in motion, and who said it (plan D13).

    ``content_hash`` commits the instruction text without publishing it.
    ``ref`` points at the instruction's own action in the session (a
    ``human_input`` action id, in a Claude Code session).
    """

    source: str
    content_hash: str
    signature: str | None = None
    ref: str | None = None

    def __post_init__(self) -> None:
        if self.source not in tuple(InstructionSource):
            raise ReceiptError(
                f"instruction.source must be one of {[s.value for s in InstructionSource]}, "
                f"got {self.source!r}"
            )
        hex_digest(self.content_hash, "instruction.content_hash")
        if self.signature is not None:
            token(self.signature, "instruction.signature", max_length=2048)
        if self.ref is not None:
            token(self.ref, "instruction.ref", max_length=256)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "source": self.source,
                "content_hash": self.content_hash,
                "signature": self.signature,
                "ref": self.ref,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> Instruction:
        obj = _object(data, "instruction")
        _reject_unknown(obj, {"source", "content_hash", "signature", "ref"}, "instruction")
        return cls(
            source=_member(obj, "source", "instruction"),
            content_hash=_member(obj, "content_hash", "instruction"),
            signature=obj.get("signature"),
            ref=obj.get("ref"),
        )


# --------------------------------------------------------------------------- #
# Leaf 2 — policy decision
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PolicyRule:
    """One rule the signer evaluated, and what it said."""

    name: str
    outcome: str
    detail: str = ""

    def __post_init__(self) -> None:
        token(self.name, "rule.name", max_length=128)
        token(self.outcome, "rule.outcome", max_length=64)
        text(self.detail, "rule.detail")

    def to_content(self) -> JSONObject:
        return {"name": self.name, "outcome": self.outcome, "detail": self.detail}

    @classmethod
    def from_content(cls, data: Any) -> PolicyRule:
        obj = _object(data, "rule")
        _reject_unknown(obj, {"name", "outcome", "detail"}, "rule")
        return cls(
            name=_member(obj, "name", "rule"),
            outcome=_member(obj, "outcome", "rule"),
            detail=obj.get("detail", ""),
        )


@dataclasses.dataclass(frozen=True)
class Escalation:
    """An escalation and the approvals collected against it (plan D11).

    ``challenge`` is the digest the approvers sign — ``LEFT_pre``, the LEFT half
    computed before the decision leaf was final. Each entry of ``approvals`` is an
    opaque canonical JSON object; phase 2 pins the assertion shape (WebAuthn
    envelope or Ed25519 signature) and validates it. Until then core commits it
    verbatim and checks only that it is canonical content.
    """

    challenge: str
    expires_at: str
    quorum: int
    approvals: tuple[JSONObject, ...] = ()

    def __post_init__(self) -> None:
        hex_digest(self.challenge, "escalation.challenge")
        instant(self.expires_at, "escalation.expires_at")
        if isinstance(self.quorum, bool) or not isinstance(self.quorum, int) or self.quorum < 1:
            raise ReceiptError(f"escalation.quorum must be an integer >= 1, got {self.quorum!r}")
        for i, approval in enumerate(self.approvals):
            if not isinstance(approval, dict):
                raise ReceiptError(f"escalation.approvals[{i}] must be an object")
            ensure_canonical_content(approval, path=f"escalation.approvals[{i}]")

    def to_content(self) -> JSONObject:
        return {
            "challenge": self.challenge,
            "expires_at": self.expires_at,
            "quorum": self.quorum,
            "approvals": list(self.approvals),
        }

    @classmethod
    def from_content(cls, data: Any) -> Escalation:
        obj = _object(data, "escalation")
        _reject_unknown(obj, {"challenge", "expires_at", "quorum", "approvals"}, "escalation")
        approvals = obj.get("approvals", [])
        if not isinstance(approvals, list):
            raise ReceiptError("escalation.approvals must be an array")
        return cls(
            challenge=_member(obj, "challenge", "escalation"),
            expires_at=_member(obj, "expires_at", "escalation"),
            quorum=_member(obj, "quorum", "escalation"),
            approvals=tuple(approvals),
        )


@dataclasses.dataclass(frozen=True)
class PolicyDecision:
    """Leaf 2: the pinned policy, every rule it ran, and the verdict.

    The decision is the signer's alone (plan D1). ``policy_hash`` identifies the
    exact signed policy document that produced it, so the same inputs can be
    re-run against the same rules by anyone holding that document.
    """

    policy_hash: str
    rules: tuple[PolicyRule, ...]
    outcome: str
    tier: str
    escalation: Escalation | None = None

    def __post_init__(self) -> None:
        hex_digest(self.policy_hash, "policy_decision.policy_hash")
        if self.outcome not in tuple(PolicyOutcome):
            raise ReceiptError(
                f"policy_decision.outcome must be one of {[o.value for o in PolicyOutcome]}, "
                f"got {self.outcome!r}"
            )
        token(self.tier, "policy_decision.tier", max_length=64)
        for rule in self.rules:
            if not isinstance(rule, PolicyRule):
                raise ReceiptError("policy_decision.rules must contain PolicyRule values")

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "policy_hash": self.policy_hash,
                "rules": [rule.to_content() for rule in self.rules],
                "outcome": self.outcome,
                "tier": self.tier,
                "escalation": self.escalation.to_content() if self.escalation else None,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> PolicyDecision:
        obj = _object(data, "policy_decision")
        _reject_unknown(
            obj, {"policy_hash", "rules", "outcome", "tier", "escalation"}, "policy_decision"
        )
        rules = _member(obj, "rules", "policy_decision")
        if not isinstance(rules, list):
            raise ReceiptError("policy_decision.rules must be an array")
        escalation = obj.get("escalation")
        return cls(
            policy_hash=_member(obj, "policy_hash", "policy_decision"),
            rules=tuple(PolicyRule.from_content(r) for r in rules),
            outcome=_member(obj, "outcome", "policy_decision"),
            tier=_member(obj, "tier", "policy_decision"),
            escalation=None if escalation is None else Escalation.from_content(escalation),
        )


# --------------------------------------------------------------------------- #
# Leaf 3 — signer attestation
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class SignerAttestation:
    """Leaf 3: proof of what code held the policy key.

    ``document`` is the enclave attestation (base64 of the CBOR document for AWS
    Nitro) and ``policy_public_key`` is the key it vouches for. A dev signer has
    no attestation: the leaf content is ``null`` and every reader is told the
    signer is unattested (plan D3). Verifying the document itself lands in
    phase 3; this phase commits it.
    """

    document: str
    policy_public_key: str
    format: str = "aws-nitro"

    def __post_init__(self) -> None:
        token(self.document, "signer_attestation.document", max_length=65536)
        token(self.policy_public_key, "signer_attestation.policy_public_key")
        token(self.format, "signer_attestation.format", max_length=64)

    def to_content(self) -> JSONObject:
        return {
            "format": self.format,
            "document": self.document,
            "policy_public_key": self.policy_public_key,
        }

    @classmethod
    def from_content(cls, data: Any) -> SignerAttestation:
        obj = _object(data, "signer_attestation")
        _reject_unknown(obj, {"format", "document", "policy_public_key"}, "signer_attestation")
        return cls(
            document=_member(obj, "document", "signer_attestation"),
            policy_public_key=_member(obj, "policy_public_key", "signer_attestation"),
            format=obj.get("format", "aws-nitro"),
        )


# --------------------------------------------------------------------------- #
# Leaf 4 — settlement
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Settlement:
    """Leaf 4: what the rail did.

    ``observed_anchor`` is the value actually read back from the settled
    transaction's anchor field (the XRPL memo). Comparing it to LEFT is what binds
    the authorization to the settlement; that comparison is a phase 2 check.
    ``settlement_proof_ref`` points at the SHAMap path, ledger header and
    validator quorum captured at submit time (plan D20).
    """

    rail: str
    tx_hash: str
    ledger_index: int
    close_time: str
    signed_tx_blob: str | None = None
    observed_anchor: str | None = None
    settlement_proof_ref: str | None = None

    def __post_init__(self) -> None:
        token(self.rail, "settlement.rail", max_length=64)
        token(self.tx_hash, "settlement.tx_hash", max_length=128)
        if isinstance(self.ledger_index, bool) or not isinstance(self.ledger_index, int):
            raise ReceiptError("settlement.ledger_index must be an integer")
        if self.ledger_index < 0:
            raise ReceiptError("settlement.ledger_index must not be negative")
        instant(self.close_time, "settlement.close_time")
        if self.signed_tx_blob is not None:
            token(self.signed_tx_blob, "settlement.signed_tx_blob", max_length=65536)
        if self.observed_anchor is not None:
            token(self.observed_anchor, "settlement.observed_anchor", max_length=2048)
        if self.settlement_proof_ref is not None:
            token(self.settlement_proof_ref, "settlement.settlement_proof_ref", max_length=256)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "rail": self.rail,
                "tx_hash": self.tx_hash,
                "ledger_index": self.ledger_index,
                "close_time": self.close_time,
                "signed_tx_blob": self.signed_tx_blob,
                "observed_anchor": self.observed_anchor,
                "settlement_proof_ref": self.settlement_proof_ref,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> Settlement:
        obj = _object(data, "settlement")
        _reject_unknown(
            obj,
            {
                "rail",
                "tx_hash",
                "ledger_index",
                "close_time",
                "signed_tx_blob",
                "observed_anchor",
                "settlement_proof_ref",
            },
            "settlement",
        )
        return cls(
            rail=_member(obj, "rail", "settlement"),
            tx_hash=_member(obj, "tx_hash", "settlement"),
            ledger_index=_member(obj, "ledger_index", "settlement"),
            close_time=_member(obj, "close_time", "settlement"),
            signed_tx_blob=obj.get("signed_tx_blob"),
            observed_anchor=obj.get("observed_anchor"),
            settlement_proof_ref=obj.get("settlement_proof_ref"),
        )


# --------------------------------------------------------------------------- #
# Leaf 5 — result
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class BalanceDelta:
    """One account's balance change, as a signed decimal string."""

    account: str
    currency: CurrencyRef
    value: str

    def __post_init__(self) -> None:
        token(self.account, "balance_delta.account", max_length=128)
        currency_content(self.currency)
        decimal_string(self.value, "balance_delta.value", signed=True, positive=False)

    def to_content(self) -> JSONObject:
        return {
            "account": self.account,
            "currency": currency_content(self.currency),
            "value": self.value,
        }

    @classmethod
    def from_content(cls, data: Any) -> BalanceDelta:
        obj = _object(data, "balance_delta")
        _reject_unknown(obj, {"account", "currency", "value"}, "balance_delta")
        return cls(
            account=_member(obj, "account", "balance_delta"),
            currency=currency_from_content(_member(obj, "currency", "balance_delta")),
            value=_member(obj, "value", "balance_delta"),
        )


@dataclasses.dataclass(frozen=True)
class Result:
    """Leaf 5: how it ended, in the rail's own words plus the money that moved.

    ``engine_result`` is the rail's code (``tesSUCCESS``, ``tefBAD_QUORUM``).
    ``outcome_hash`` optionally commits the rail's full raw response, so the
    verbatim document can be disclosed later without bloating the receipt.
    """

    outcome: str
    engine_result: str | None = None
    balance_deltas: tuple[BalanceDelta, ...] = ()
    outcome_hash: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in tuple(ResultOutcome):
            raise ReceiptError(
                f"result.outcome must be one of {[o.value for o in ResultOutcome]}, "
                f"got {self.outcome!r}"
            )
        if self.engine_result is not None:
            token(self.engine_result, "result.engine_result", max_length=64)
        if self.outcome_hash is not None:
            hex_digest(self.outcome_hash, "result.outcome_hash")
        text(self.detail, "result.detail")
        for delta in self.balance_deltas:
            if not isinstance(delta, BalanceDelta):
                raise ReceiptError("result.balance_deltas must contain BalanceDelta values")

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "outcome": self.outcome,
                "engine_result": self.engine_result,
                "balance_deltas": [d.to_content() for d in self.balance_deltas],
                "outcome_hash": self.outcome_hash,
                "detail": self.detail,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> Result:
        obj = _object(data, "result")
        _reject_unknown(
            obj,
            {"outcome", "engine_result", "balance_deltas", "outcome_hash", "detail"},
            "result",
        )
        deltas = obj.get("balance_deltas", [])
        if not isinstance(deltas, list):
            raise ReceiptError("result.balance_deltas must be an array")
        return cls(
            outcome=_member(obj, "outcome", "result"),
            engine_result=obj.get("engine_result"),
            balance_deltas=tuple(BalanceDelta.from_content(d) for d in deltas),
            outcome_hash=obj.get("outcome_hash"),
            detail=obj.get("detail", ""),
        )


# --------------------------------------------------------------------------- #
# Leaf 6 — reasoning
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Reasoning:
    """Leaf 6: the model's account of itself. Testimony, not evidence.

    The receipt proves the *facts* — what was asked, what the policy said, what
    settled. Leaf 6 commits a hash of the model trace so it cannot be rewritten
    afterwards, and carries ``testimony: true`` so no reader mistakes a committed
    explanation for a verified one.
    """

    content_hash: str
    source: str | None = None
    note: str = ""

    def __post_init__(self) -> None:
        hex_digest(self.content_hash, "reasoning.content_hash")
        if self.source is not None:
            token(self.source, "reasoning.source", max_length=128)
        text(self.note, "reasoning.note", max_length=4096)

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "testimony": True,
                "content_hash": self.content_hash,
                "source": self.source,
                "note": self.note,
            }
        )

    @classmethod
    def from_content(cls, data: Any) -> Reasoning:
        obj = _object(data, "reasoning")
        _reject_unknown(obj, {"testimony", "content_hash", "source", "note"}, "reasoning")
        if obj.get("testimony") is not True:
            raise ReceiptError("reasoning.testimony must be true: leaf 6 is never evidence")
        return cls(
            content_hash=_member(obj, "content_hash", "reasoning"),
            source=obj.get("source"),
            note=obj.get("note", ""),
        )


# --------------------------------------------------------------------------- #
# The seven leaves
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ReceiptLeaves:
    """The seven leaf contents, in order. ``None`` means the leaf is absent.

    An absent leaf still commits: its content is the literal JSON ``null``, so
    "there was no attestation" and "there was no settlement" are proven facts
    rather than gaps.
    """

    instruction: Instruction | None = None
    intent: Intent | None = None
    policy_decision: PolicyDecision | None = None
    signer_attestation: SignerAttestation | None = None
    settlement: Settlement | None = None
    result: Result | None = None
    reasoning: Reasoning | None = None

    def contents(self) -> tuple[JSONValue, ...]:
        """The seven canonical contents, in leaf order."""
        models = (
            self.instruction,
            self.intent,
            self.policy_decision,
            self.signer_attestation,
            self.settlement,
            self.result,
            self.reasoning,
        )
        return tuple(None if m is None else m.to_content() for m in models)

    def hashes(self) -> tuple[SHA256Hash, ...]:
        """The seven leaf hashes."""
        return tuple(
            receipt_leaf(name, content)
            for name, content in zip(LEAF_NAMES, self.contents(), strict=True)
        )

    def padded_hashes(self) -> tuple[SHA256Hash, ...]:
        """The eight leaf hashes, the last one repeated as padding."""
        return pad_leaf_hashes(self.hashes())

    @classmethod
    def from_contents(cls, contents: Sequence[JSONValue]) -> ReceiptLeaves:
        """Parse seven raw contents into typed models, validating each."""
        if len(contents) != LEAF_COUNT:
            raise ReceiptError(f"a receipt has {LEAF_COUNT} leaves, got {len(contents)}")
        i, n, p, a, s, r, g = contents
        return cls(
            instruction=None if i is None else Instruction.from_content(i),
            intent=None if n is None else Intent.from_content(n),
            policy_decision=None if p is None else PolicyDecision.from_content(p),
            signer_attestation=None if a is None else SignerAttestation.from_content(a),
            settlement=None if s is None else Settlement.from_content(s),
            result=None if r is None else Result.from_content(r),
            reasoning=None if g is None else Reasoning.from_content(g),
        )


def pad_leaf_hashes(hashes: Sequence[SHA256Hash]) -> tuple[SHA256Hash, ...]:
    """Pad seven leaf hashes to eight by repeating the last, as the tree does."""
    if len(hashes) == PADDED_LEAF_COUNT:
        return tuple(hashes)
    if len(hashes) != LEAF_COUNT:
        raise ReceiptError(
            f"expected {LEAF_COUNT} or {PADDED_LEAF_COUNT} leaf hashes, got {len(hashes)}"
        )
    return (*hashes, hashes[-1])


def _fold(hashes: Sequence[SHA256Hash]) -> SHA256Hash:
    level = list(hashes)
    while len(level) > 1:
        level = [
            SHA256Hash.from_bytes(level[i].bytes + level[i + 1].bytes)
            for i in range(0, len(level), 2)
        ]
    return level[0]


def build_left(leaves: Sequence[SHA256Hash]) -> SHA256Hash:
    """LEFT: the authorization commitment over leaf hashes 0-3."""
    if len(leaves) != 4:
        raise ReceiptError(f"LEFT is built from exactly 4 leaf hashes, got {len(leaves)}")
    return _fold(leaves)


def build_right(leaves: Sequence[SHA256Hash]) -> SHA256Hash:
    """RIGHT: the settlement half over leaf hashes 4-7 (7 being the padding leaf)."""
    if len(leaves) != 4:
        raise ReceiptError(f"RIGHT is built from exactly 4 leaf hashes, got {len(leaves)}")
    return _fold(leaves)


def build_root(leaves: Sequence[SHA256Hash]) -> SHA256Hash:
    """ROOT = SHA-256(LEFT || RIGHT) from seven or eight leaf hashes."""
    padded = pad_leaf_hashes(leaves)
    return SHA256Hash.from_bytes(
        build_left(padded[LEFT_LEAVES]).bytes + build_right(padded[RIGHT_LEAVES]).bytes
    )


def build_tree(leaves: Sequence[SHA256Hash]) -> MerkleTree:
    """The eight-leaf tree over seven leaf hashes, padded the usual way."""
    if len(leaves) not in (LEAF_COUNT, PADDED_LEAF_COUNT):
        raise ReceiptError(
            f"expected {LEAF_COUNT} or {PADDED_LEAF_COUNT} leaf hashes, got {len(leaves)}"
        )
    return MerkleTree.build(list(leaves[:LEAF_COUNT]))


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class SessionLocator:
    """Where the receipt's envelope hash was committed in a session (plan D4)."""

    session_id: str
    leaf_index: int

    def __post_init__(self) -> None:
        token(self.session_id, "session_locator.session_id", max_length=128)
        if isinstance(self.leaf_index, bool) or not isinstance(self.leaf_index, int):
            raise ReceiptError("session_locator.leaf_index must be an integer")
        if self.leaf_index < 0:
            raise ReceiptError("session_locator.leaf_index must not be negative")

    def to_content(self) -> JSONObject:
        return {"session_id": self.session_id, "leaf_index": self.leaf_index}

    @classmethod
    def from_content(cls, data: Any) -> SessionLocator:
        obj = _object(data, "session_locator")
        _reject_unknown(obj, {"session_id", "leaf_index"}, "session_locator")
        return cls(
            session_id=_member(obj, "session_id", "session_locator"),
            leaf_index=_member(obj, "leaf_index", "session_locator"),
        )


@dataclasses.dataclass(frozen=True)
class Envelope:
    """The public face of a receipt: commitments plus the handful of fields a
    reader needs to find everything else.

    The envelope's canonical hash is committed as one action in the enclosing
    session (plan D4), which is how a receipt inherits log inclusion, the
    checkpoint signature and Bitcoin anchoring without a second chain.
    """

    receipt_id: str
    root: SHA256Hash
    left: SHA256Hash
    leaf_hashes: tuple[SHA256Hash, ...]
    rail: str
    treasury: str
    agent_id: str
    policy_hash: str
    signer_public_key: str
    session_locator: SessionLocator | None = None
    version: str = RECEIPT_VERSION

    def __post_init__(self) -> None:
        token(self.receipt_id, "envelope.receipt_id", max_length=128)
        token(self.version, "envelope.version", max_length=64)
        if len(self.leaf_hashes) != PADDED_LEAF_COUNT:
            raise ReceiptError(
                f"envelope.leaf_hashes must hold {PADDED_LEAF_COUNT} hashes, "
                f"got {len(self.leaf_hashes)}"
            )
        token(self.rail, "envelope.rail", max_length=64)
        token(self.treasury, "envelope.treasury", max_length=128)
        token(self.agent_id, "envelope.agent_id", max_length=128)
        hex_digest(self.policy_hash, "envelope.policy_hash")
        token(self.signer_public_key, "envelope.signer_public_key")

    def to_content(self) -> JSONObject:
        """The canonical envelope object; its hash is the session action's input_hash."""
        content = drop_none(
            {
                "receipt_id": self.receipt_id,
                "version": self.version,
                "root": self.root.hex(),
                "left": self.left.hex(),
                "leaf_hashes": [h.hex() for h in self.leaf_hashes],
                "rail": self.rail,
                "treasury": self.treasury,
                "agent_id": self.agent_id,
                "policy_hash": self.policy_hash,
                "signer_public_key": self.signer_public_key,
                "session_locator": (
                    self.session_locator.to_content() if self.session_locator else None
                ),
            }
        )
        ensure_canonical_content(content)
        return content

    def envelope_hash(self) -> SHA256Hash:
        """``SHA-256(canonical_bytes(envelope))``.

        Deliberately *not* tagged with a separate domain prefix: this digest has
        to equal ``content_hash(envelope_json)`` from SPEC.md section 1 so it can
        be an action's ``input_hash`` unchanged. The tag lives inside the object,
        as the ``version`` member.
        """
        return SHA256Hash.from_bytes(canonical_bytes(self.to_content()))

    @classmethod
    def from_content(cls, data: Any) -> Envelope:
        obj = _object(data, "envelope")
        _reject_unknown(
            obj,
            {
                "receipt_id",
                "version",
                "root",
                "left",
                "leaf_hashes",
                "rail",
                "treasury",
                "agent_id",
                "policy_hash",
                "signer_public_key",
                "session_locator",
            },
            "envelope",
        )
        leaf_hashes = _member(obj, "leaf_hashes", "envelope")
        if not isinstance(leaf_hashes, list):
            raise ReceiptError("envelope.leaf_hashes must be an array")
        locator = obj.get("session_locator")
        return cls(
            receipt_id=_member(obj, "receipt_id", "envelope"),
            version=obj.get("version", RECEIPT_VERSION),
            root=_hash_from_hex(_member(obj, "root", "envelope"), "envelope.root"),
            left=_hash_from_hex(_member(obj, "left", "envelope"), "envelope.left"),
            leaf_hashes=tuple(
                _hash_from_hex(h, f"envelope.leaf_hashes[{i}]") for i, h in enumerate(leaf_hashes)
            ),
            rail=_member(obj, "rail", "envelope"),
            treasury=_member(obj, "treasury", "envelope"),
            agent_id=_member(obj, "agent_id", "envelope"),
            policy_hash=_member(obj, "policy_hash", "envelope"),
            signer_public_key=_member(obj, "signer_public_key", "envelope"),
            session_locator=None if locator is None else SessionLocator.from_content(locator),
        )


def _hash_from_hex(value: Any, field: str) -> SHA256Hash:
    return SHA256Hash(bytes.fromhex(hex_digest(value, field)))


# --------------------------------------------------------------------------- #
# Verification result
# --------------------------------------------------------------------------- #


class CheckStatus(enum.StrEnum):
    """Outcome of one verification check.

    ``NOT_IMPLEMENTED`` is not a pass. A verifier that cannot yet run a check says
    so out loud — never a single verdict that hides which half was checked
    (plan D10).
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_IMPLEMENTED = "not_implemented"


@dataclasses.dataclass(frozen=True)
class Check:
    """One named check and what it found."""

    name: str
    status: CheckStatus
    detail: str = ""

    def to_content(self) -> JSONObject:
        return {"name": self.name, "status": self.status.value}


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    """Every check, in the order the spec runs them.

    ``ok`` means nothing was contradicted. ``complete`` means every check in the
    list actually ran. Both lines are reported; neither alone is a verdict.
    """

    checks: tuple[Check, ...]

    @property
    def ok(self) -> bool:
        """True when no check failed."""
        return not self.failures

    @property
    def complete(self) -> bool:
        """True when every check ran, i.e. none is deferred to a later phase."""
        return not self.deferred

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.FAIL)

    @property
    def deferred(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.status is CheckStatus.NOT_IMPLEMENTED)

    def get(self, name: str) -> Check | None:
        """The check with this name, or None."""
        for check in self.checks:
            if check.name == name:
                return check
        return None

    def to_content(self) -> JSONObject:
        """Plain JSON: the verdict lines plus every check name and status."""
        return {
            "ok": self.ok,
            "complete": self.complete,
            "checks": [c.to_content() for c in self.checks],
        }


CHECK_VERSION: Final = "receipt.version"
CHECK_LEAF_COUNT: Final = "leaves.count"
CHECK_REQUIRED_LEAVES: Final = "leaves.required_present"
CHECK_PADDING: Final = "leaves.padding"
CHECK_LEFT: Final = "commitment.left"
CHECK_RIGHT: Final = "commitment.right"
CHECK_ROOT: Final = "commitment.root"
CHECK_ENVELOPE_RAIL: Final = "envelope.rail"
CHECK_ENVELOPE_TREASURY: Final = "envelope.treasury"
CHECK_ENVELOPE_POLICY_HASH: Final = "envelope.policy_hash"
CHECK_DISCLOSURE_ROOT: Final = "disclosure.root"


def leaf_check(name: str) -> str:
    """Check name for "leaf <name> hashes to the value the envelope commits"."""
    return f"leaf.{name}"


def proof_check(name: str) -> str:
    """Check name for "the disclosed proof for <name> folds to the root"."""
    return f"proof.{name}"


DEFERRED_CHECKS: Final[tuple[tuple[str, str], ...]] = (
    ("policy.signature", "phase 2: verify the policy key's signature over the tx blob / LEFT"),
    ("signer.attestation", "phase 3: verify the Nitro attestation document and PCR allowlist"),
    ("intent.matches_settled_fields", "phase 2: compare intent to the settled transaction"),
    ("settlement.anchor_equals_left", "phase 2: the rail memo must equal LEFT"),
    ("settlement.signed_blob", "phase 2: re-derive the tx hash from the signed blob"),
    ("settlement.ledger_inclusion", "phase 2: inclusion proof against pinned validators"),
    ("session.log_join", "phase 4: envelope hash committed in the session log (level 2)"),
)
"""Checks the spec defines but this phase does not run, with the phase that will.

These are the extension points. A later phase replaces the deferred entry with a
real check of the same name; the vectors then move that name from
``not_implemented`` to ``pass``.
"""

_DEFERRED_DETAIL: Final = dict(DEFERRED_CHECKS)


def _deferred(name: str) -> Check:
    return Check(name=name, status=CheckStatus.NOT_IMPLEMENTED, detail=_DEFERRED_DETAIL[name])


def _check(name: str, passed: bool, detail: str = "") -> Check:
    return Check(name=name, status=CheckStatus.PASS if passed else CheckStatus.FAIL, detail=detail)


# --------------------------------------------------------------------------- #
# Selective disclosure
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class DisclosedLeaf:
    """One revealed leaf: its content and the siblings that tie it to the root."""

    index: int
    name: str
    content: JSONValue
    proof: MerkleProof

    def __post_init__(self) -> None:
        if not 0 <= self.index < LEAF_COUNT:
            raise ReceiptError(f"disclosed leaf index {self.index} is outside 0..{LEAF_COUNT - 1}")
        if self.name != LEAF_NAMES[self.index]:
            raise ReceiptError(
                f"disclosed leaf {self.index} must be named {LEAF_NAMES[self.index]!r}, "
                f"got {self.name!r}"
            )

    def leaf_hash(self) -> SHA256Hash:
        """Recompute this leaf's hash from the disclosed content."""
        return receipt_leaf(self.name, self.content)

    def to_content(self) -> JSONObject:
        return {
            "index": self.index,
            "name": self.name,
            "content": self.content,
            "proof": {
                "siblings": [s.hex() for s in self.proof.siblings],
                "directions": list(self.proof.directions),
            },
        }

    @classmethod
    def from_content(cls, data: Any) -> DisclosedLeaf:
        obj = _object(data, "disclosed leaf")
        _reject_unknown(obj, {"index", "name", "content", "proof"}, "disclosed leaf")
        return cls(
            index=_member(obj, "index", "disclosed leaf"),
            name=_member(obj, "name", "disclosed leaf"),
            content=obj.get("content"),
            proof=MerkleProof.from_dict(
                dict(_object(_member(obj, "proof", "disclosed leaf"), "proof"))
            ),
        )


@dataclasses.dataclass(frozen=True)
class Disclosure:
    """A receipt with only some leaves revealed.

    The eight leaf hashes travel with it, so a reader sees the whole commitment
    and can recompute LEFT, RIGHT and ROOT; the withheld leaves stay hidden behind
    their hashes. Each revealed leaf carries its own inclusion proof, which is
    what a verifier folds.
    """

    receipt_id: str
    root: SHA256Hash
    left: SHA256Hash
    leaf_hashes: tuple[SHA256Hash, ...]
    leaves: tuple[DisclosedLeaf, ...]
    version: str = RECEIPT_VERSION

    def __post_init__(self) -> None:
        token(self.receipt_id, "disclosure.receipt_id", max_length=128)
        if len(self.leaf_hashes) != PADDED_LEAF_COUNT:
            raise ReceiptError(
                f"disclosure.leaf_hashes must hold {PADDED_LEAF_COUNT} hashes, "
                f"got {len(self.leaf_hashes)}"
            )

    @property
    def disclosed_names(self) -> tuple[str, ...]:
        return tuple(leaf.name for leaf in self.leaves)

    @property
    def withheld_names(self) -> tuple[str, ...]:
        return tuple(n for n in LEAF_NAMES if n not in self.disclosed_names)

    def to_content(self) -> JSONObject:
        content: JSONObject = {
            "receipt_id": self.receipt_id,
            "version": self.version,
            "root": self.root.hex(),
            "left": self.left.hex(),
            "leaf_hashes": [h.hex() for h in self.leaf_hashes],
            "leaves": [leaf.to_content() for leaf in self.leaves],
        }
        ensure_canonical_content(content)
        return content

    @classmethod
    def from_content(cls, data: Any) -> Disclosure:
        obj = _object(data, "disclosure")
        _reject_unknown(
            obj, {"receipt_id", "version", "root", "left", "leaf_hashes", "leaves"}, "disclosure"
        )
        leaf_hashes = _member(obj, "leaf_hashes", "disclosure")
        leaves = _member(obj, "leaves", "disclosure")
        if not isinstance(leaf_hashes, list) or not isinstance(leaves, list):
            raise ReceiptError("disclosure.leaf_hashes and disclosure.leaves must be arrays")
        return cls(
            receipt_id=_member(obj, "receipt_id", "disclosure"),
            version=obj.get("version", RECEIPT_VERSION),
            root=_hash_from_hex(_member(obj, "root", "disclosure"), "disclosure.root"),
            left=_hash_from_hex(_member(obj, "left", "disclosure"), "disclosure.left"),
            leaf_hashes=tuple(
                _hash_from_hex(h, f"disclosure.leaf_hashes[{i}]")
                for i, h in enumerate(leaf_hashes)
            ),
            leaves=tuple(DisclosedLeaf.from_content(leaf) for leaf in leaves),
        )


def disclose(envelope: Envelope, leaves: ReceiptLeaves, names: Iterable[str]) -> Disclosure:
    """Reveal only ``names``, with an inclusion proof for each.

    Proofs are built over the leaf hashes recomputed from ``leaves``, and the
    envelope supplies the root they are folded against — so a disclosure taken
    from a doctored envelope fails to verify rather than quietly agreeing with
    itself.
    """
    wanted = list(dict.fromkeys(names))
    unknown = [n for n in wanted if n not in LEAF_NAMES]
    if unknown:
        raise ReceiptError(f"unknown leaf names: {unknown}")
    tree = build_tree(leaves.hashes())
    ordered = sorted(wanted, key=LEAF_NAMES.index)
    contents = leaves.contents()
    return Disclosure(
        receipt_id=envelope.receipt_id,
        version=envelope.version,
        root=envelope.root,
        left=envelope.left,
        leaf_hashes=envelope.leaf_hashes,
        leaves=tuple(
            DisclosedLeaf(
                index=LEAF_NAMES.index(name),
                name=name,
                content=contents[LEAF_NAMES.index(name)],
                proof=tree.get_proof(LEAF_NAMES.index(name)),
            )
            for name in ordered
        ),
    )


def verify_disclosure(disclosure: Disclosure, root: SHA256Hash) -> VerificationResult:
    """Check a disclosure against a root the reader already trusts.

    The root is an input, not something the disclosure gets to assert: it comes
    from the envelope, the session log, or wherever the reader pinned it.
    """
    checks: list[Check] = [
        _check(
            CHECK_VERSION,
            disclosure.version == RECEIPT_VERSION,
            f"version is {disclosure.version!r}",
        ),
        _check(
            CHECK_DISCLOSURE_ROOT,
            disclosure.root == root,
            f"disclosure root {disclosure.root.hex()} vs expected {root.hex()}",
        ),
        _check(
            CHECK_LEAF_COUNT,
            len(disclosure.leaf_hashes) == PADDED_LEAF_COUNT,
            f"{len(disclosure.leaf_hashes)} leaf hashes",
        ),
        _check(
            CHECK_PADDING,
            disclosure.leaf_hashes[PADDED_LEAF_COUNT - 1]
            == disclosure.leaf_hashes[LEAF_COUNT - 1],
            "leaf 7 must repeat leaf 6",
        ),
    ]

    for leaf in disclosure.leaves:
        try:
            computed = leaf.leaf_hash()
        except ValidationError as exc:
            checks.append(Check(leaf_check(leaf.name), CheckStatus.FAIL, str(exc)))
            checks.append(Check(proof_check(leaf.name), CheckStatus.FAIL, "leaf hash unavailable"))
            continue
        committed = disclosure.leaf_hashes[leaf.index]
        checks.append(
            _check(
                leaf_check(leaf.name),
                computed == committed,
                f"recomputed {computed.hex()} vs committed {committed.hex()}",
            )
        )
        checks.append(
            _check(
                proof_check(leaf.name),
                leaf.proof.verify(computed, root),
                f"proof folds to {leaf.proof.derive_root(computed).hex()}",
            )
        )

    left = build_left(disclosure.leaf_hashes[LEFT_LEAVES])
    right = build_right(disclosure.leaf_hashes[RIGHT_LEAVES])
    checks.append(
        _check(CHECK_LEFT, left == disclosure.left, f"recomputed LEFT {left.hex()}")
    )
    recomputed_root = SHA256Hash.from_bytes(left.bytes + right.bytes)
    checks.append(
        _check(CHECK_ROOT, recomputed_root == root, f"recomputed ROOT {recomputed_root.hex()}")
    )
    return VerificationResult(checks=tuple(checks))


# --------------------------------------------------------------------------- #
# Structural verification
# --------------------------------------------------------------------------- #


def _contents_of(leaves: ReceiptLeaves | Sequence[JSONValue]) -> tuple[JSONValue, ...]:
    """Accept typed leaves or seven raw JSON contents.

    A verifier receives JSON, not Python objects, and content that no longer
    parses into a model must still be *hashable* — otherwise a tampered receipt
    would raise instead of failing a check.
    """
    if isinstance(leaves, ReceiptLeaves):
        return leaves.contents()
    return tuple(leaves)


def _content_member(content: JSONValue, key: str) -> Any:
    if isinstance(content, dict):
        return content.get(key)
    return None


def verify_receipt_structure(
    envelope: Envelope,
    leaves: ReceiptLeaves | Sequence[JSONValue],
) -> VerificationResult:
    """Recompute leaves, LEFT, RIGHT and ROOT, and report every check.

    This is the structural half of verification — everything that needs nothing
    but the receipt itself. The cryptographic and settlement halves (policy
    signature, attestation, memo binding, ledger inclusion, session join) appear
    as :data:`DEFERRED_CHECKS` in the position the spec gives them, so a reader
    always sees what was not checked.
    """
    contents = _contents_of(leaves)
    checks: list[Check] = [
        _check(
            CHECK_VERSION,
            envelope.version == RECEIPT_VERSION,
            f"version {envelope.version!r}",
        ),
        _check(CHECK_LEAF_COUNT, len(contents) == LEAF_COUNT, f"{len(contents)} leaf contents"),
        _check(
            CHECK_REQUIRED_LEAVES,
            all(
                i < len(contents) and contents[i] is not None
                for i in (LEAF_NAMES.index(n) for n in REQUIRED_LEAVES)
            ),
            f"{list(REQUIRED_LEAVES)} are present in every receipt",
        ),
    ]

    computed: list[SHA256Hash | None] = []
    for i, name in enumerate(LEAF_NAMES):
        if i >= len(contents):
            computed.append(None)
            checks.append(Check(leaf_check(name), CheckStatus.FAIL, "leaf content missing"))
            continue
        try:
            digest = receipt_leaf(name, contents[i])
        except ValidationError as exc:
            computed.append(None)
            checks.append(Check(leaf_check(name), CheckStatus.FAIL, str(exc)))
            continue
        computed.append(digest)
        committed = envelope.leaf_hashes[i]
        checks.append(
            _check(
                leaf_check(name),
                digest == committed,
                f"recomputed {digest.hex()} vs committed {committed.hex()}",
            )
        )

    checks.append(
        _check(
            CHECK_PADDING,
            envelope.leaf_hashes[PADDED_LEAF_COUNT - 1] == envelope.leaf_hashes[LEAF_COUNT - 1],
            "leaf 7 must repeat leaf 6",
        )
    )

    committed_left = build_left(envelope.leaf_hashes[LEFT_LEAVES])
    left_ok = committed_left == envelope.left
    if all(h is not None for h in computed[LEFT_LEAVES]):
        recomputed_left = build_left([h for h in computed[LEFT_LEAVES] if h is not None])
        left_ok = left_ok and recomputed_left == envelope.left
    checks.append(
        _check(CHECK_LEFT, left_ok, f"LEFT over leaves 0-3 is {committed_left.hex()}")
    )

    checks.append(_deferred("policy.signature"))
    checks.append(_deferred("signer.attestation"))
    checks.append(_deferred("intent.matches_settled_fields"))
    checks.append(_deferred("settlement.anchor_equals_left"))
    checks.append(_deferred("settlement.signed_blob"))
    checks.append(_deferred("settlement.ledger_inclusion"))

    committed_right = build_right(envelope.leaf_hashes[RIGHT_LEAVES])
    right_ok = True
    tail = computed[4:LEAF_COUNT]
    if len(tail) == LEAF_COUNT - 4 and all(h is not None for h in tail):
        recomputed_tail = [h for h in tail if h is not None]
        right_ok = build_right([*recomputed_tail, recomputed_tail[-1]]) == committed_right
    checks.append(
        _check(CHECK_RIGHT, right_ok, f"RIGHT over leaves 4-7 is {committed_right.hex()}")
    )

    recomputed_root = SHA256Hash.from_bytes(committed_left.bytes + committed_right.bytes)
    checks.append(
        _check(
            CHECK_ROOT,
            recomputed_root == envelope.root,
            f"SHA-256(LEFT || RIGHT) is {recomputed_root.hex()}",
        )
    )

    intent_content = contents[1] if len(contents) > 1 else None
    decision_content = contents[2] if len(contents) > 2 else None
    checks.append(
        _check(
            CHECK_ENVELOPE_RAIL,
            _content_member(intent_content, "rail") == envelope.rail,
            f"envelope rail {envelope.rail!r}",
        )
    )
    checks.append(
        _check(
            CHECK_ENVELOPE_TREASURY,
            _content_member(intent_content, "treasury") == envelope.treasury,
            f"envelope treasury {envelope.treasury!r}",
        )
    )
    checks.append(
        _check(
            CHECK_ENVELOPE_POLICY_HASH,
            _content_member(decision_content, "policy_hash") == envelope.policy_hash,
            f"envelope policy_hash {envelope.policy_hash}",
        )
    )
    checks.append(_deferred("session.log_join"))
    return VerificationResult(checks=tuple(checks))


# --------------------------------------------------------------------------- #
# Receipt
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class Receipt:
    """An envelope and the seven leaves it commits."""

    envelope: Envelope
    leaves: ReceiptLeaves

    @classmethod
    def build(
        cls,
        *,
        receipt_id: str,
        leaves: ReceiptLeaves,
        agent_id: str,
        signer_public_key: str,
        session_locator: SessionLocator | None = None,
        rail: str | None = None,
        treasury: str | None = None,
        policy_hash: str | None = None,
    ) -> Receipt:
        """Assemble a receipt, deriving the envelope's commitments from the leaves.

        ``rail``, ``treasury`` and ``policy_hash`` are read off the intent and
        decision leaves unless given explicitly; giving a value that disagrees
        with the leaves is an error here rather than a failed check later.
        """
        if leaves.intent is None:
            raise ReceiptError("a receipt requires an intent leaf")
        if leaves.policy_decision is None:
            raise ReceiptError("a receipt requires a policy_decision leaf")
        rail = _agree(rail, leaves.intent.rail, "rail")
        treasury = _agree(treasury, leaves.intent.treasury, "treasury")
        policy_hash = _agree(policy_hash, leaves.policy_decision.policy_hash, "policy_hash")

        padded = leaves.padded_hashes()
        envelope = Envelope(
            receipt_id=receipt_id,
            root=build_root(padded),
            left=build_left(padded[LEFT_LEAVES]),
            leaf_hashes=padded,
            rail=rail,
            treasury=treasury,
            agent_id=agent_id,
            policy_hash=policy_hash,
            signer_public_key=signer_public_key,
            session_locator=session_locator,
        )
        return cls(envelope=envelope, leaves=leaves)

    @property
    def root(self) -> SHA256Hash:
        return self.envelope.root

    @property
    def left(self) -> SHA256Hash:
        """The authorization commitment: what the policy key signs and the rail carries."""
        return self.envelope.left

    @property
    def right(self) -> SHA256Hash:
        return build_right(self.envelope.leaf_hashes[RIGHT_LEAVES])

    def tree(self) -> MerkleTree:
        """The eight-leaf tree over this receipt's leaves."""
        return build_tree(self.leaves.hashes())

    def proof(self, name: str) -> MerkleProof:
        """Inclusion proof for one leaf, from the leaf to ROOT."""
        if name not in LEAF_NAMES:
            raise ReceiptError(f"unknown leaf name: {name!r}")
        return self.tree().get_proof(LEAF_NAMES.index(name))

    def half_proof(self, name: str) -> MerkleProof:
        """Inclusion proof for one leaf, from the leaf to its half (LEFT or RIGHT)."""
        if name not in LEAF_NAMES:
            raise ReceiptError(f"unknown leaf name: {name!r}")
        return self.tree().subtree_proof(LEAF_NAMES.index(name), HALF_LEVEL)

    def envelope_hash(self) -> SHA256Hash:
        return self.envelope.envelope_hash()

    def disclose(self, names: Iterable[str]) -> Disclosure:
        """Reveal only ``names``; every other leaf stays behind its hash."""
        return disclose(self.envelope, self.leaves, names)

    def verify_structure(self) -> VerificationResult:
        """Recompute everything the receipt commits to on its own."""
        return verify_receipt_structure(self.envelope, self.leaves)


def _agree(given: str | None, derived: str, field: str) -> str:
    if given is not None and given != derived:
        raise ReceiptError(
            f"envelope {field} {given!r} disagrees with the leaves ({derived!r})"
        )
    return derived
