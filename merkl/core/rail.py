"""Rail-facing value objects, and the one rail fact core is allowed to know.

Core does not talk to a ledger. It does need a vocabulary for what an adapter
hands back, and it needs to be able to answer one question offline: *does this
transaction hash actually come from this signed blob?* That question is check 11
of the verification order, and answering it needs a per-rail digest rule and
nothing else — no client, no keys, no network. So the rule lives here, in a small
registry, and everything else about the rail lives in the adapter.

## The anchor placeholder

The authorization commitment (LEFT) covers the policy decision, so it cannot
exist until the signer has decided — but the transaction the signer signs has to
carry LEFT in its anchor field. The way out is a placeholder: the adapter
prepares the transaction with 32 zero bytes where the anchor goes, the signer
verifies those bytes are still zero, writes LEFT over them itself, and signs the
result. The signer never has to parse the rail's binary format to know that the
memo it authorized is the memo that will settle, because it wrote the memo.

The adapter then re-prepares the same transaction with the real commitment and
checks it reproduces the exact bytes the signer signed, which closes the loop
from the other end.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    JSONValue,
    drop_none,
    ensure_canonical_content,
    hex_digest,
    instant,
    token,
)

ANCHOR_BYTES: Final = 32
ANCHOR_PLACEHOLDER: Final = bytes(ANCHOR_BYTES)
"""32 zero bytes: what sits in the anchor field until the signer fills it in."""

ANCHOR_PLACEHOLDER_HEX: Final = ANCHOR_PLACEHOLDER.hex()

MEMO_TYPE: Final = "merkl/receipt-v1"
"""The rail anchor's type tag. On XRPL this is the first memo's ``MemoType``."""

MEMO_AGENT_TYPE: Final = "agent"
"""The second XRPL memo's type tag.

xrpl.org's *Track agent behavior* page encodes ``{agent_id, session_id, action,
task_id}`` as MemoData and omits MemoType. We label it ``agent`` so the codec
can tell this memo from the authorization anchor. MemoData is compact JSON,
the same payload their sample uses.
"""

MERKL_SOURCE_TAG: Final = 20260907
"""Default XRPL ``SourceTag`` for Merkl co-signed payments.

Not XRPL's Wallet-skill default (``20260530``): that tag means "their starter
kit signed this", which is a different product. A policy may override per
agent; when the agent section omits ``source_tag`` this value is used, and
omitting it is hash-neutral so every policy signed before the field existed
keeps its hash.
"""

RAIL_XRPL: Final = "xrpl"
RAIL_FAKE: Final = "fake"

NETWORK_XRPL_MAINNET: Final = "xrpl-mainnet"
NETWORK_XRPL_TESTNET: Final = "xrpl-testnet"

NETWORKS_BY_RAIL: Final[dict[str, tuple[str, ...]]] = {
    RAIL_XRPL: (NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET),
    RAIL_FAKE: (),
}
"""Which chains each rail has. A rail is a *family*; a network is one ledger in it.

`rail` alone does not say which ledger a treasury lives on, and every address,
issuer and validator set differs between them. An `rXXX` on testnet and the same
`rXXX` on mainnet are unrelated accounts, so a policy that only says "xrpl" can be
pointed at either — which is the one confusion that turns a rehearsal into a
payment. `PolicyDocument.network` is optional so every policy signed before it
existed keeps its hash; when set it must be one of these.
"""


def networks_for(rail: str) -> tuple[str, ...]:
    """The networks this rail has, or ``()`` for a rail with none (or an unknown one)."""
    return NETWORKS_BY_RAIL.get(rail, ())


def agent_memo_json(
    *, agent_id: str, session_id: str, task_id: str, action: str = "payment"
) -> str:
    """The compact JSON xrpl.org's agent-tracking page puts in MemoData.

    Keys sorted so two implementations encode the same bytes. ``action`` is
    always ``payment`` for Intent v1.
    """
    return json.dumps(
        {
            "action": action,
            "agent_id": agent_id,
            "session_id": session_id,
            "task_id": task_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


class RailError(ContentError):
    """Raised when rail-facing data is not well formed."""

    error_code = "rail_error"


class AnchorCapability(enum.StrEnum):
    """How well a rail can carry a commitment.

    ``IMMUTABLE`` — the anchor is part of the signed, validated transaction and
    cannot be edited afterwards (XRPL memos). ``MUTABLE`` — the rail stores it but
    someone can change it later. ``NONE`` — there is nowhere to put it, and the
    receipt binds to settlement by other means.
    """

    IMMUTABLE = "immutable"
    MUTABLE = "mutable"
    NONE = "none"


# --------------------------------------------------------------------------- #
# Transaction hashing (verification check ``settlement.signed_blob``)
# --------------------------------------------------------------------------- #

XRPL_TX_ID_PREFIX: Final = bytes.fromhex("54584E00")
"""``TXN`` — rippled's prefix for hashing a signed transaction into its id."""

FAKE_TX_ID_TAG: Final = b"merkl-fake-tx-v1"


def _sha512_half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def xrpl_tx_id(signed_blob: bytes) -> str:
    """``SHA-512Half("TXN" || blob)`` — how XRPL names a transaction. Uppercase hex."""
    return _sha512_half(XRPL_TX_ID_PREFIX + signed_blob).hex().upper()


def fake_tx_id(signed_blob: bytes) -> str:
    """The in-memory rail's transaction id. Uppercase hex, like a real one."""
    return hashlib.sha256(FAKE_TX_ID_TAG + b"\x00" + signed_blob).hexdigest().upper()


TX_ID_RULES: Final[dict[str, Any]] = {
    RAIL_XRPL: xrpl_tx_id,
    RAIL_FAKE: fake_tx_id,
}
"""Rails whose transaction id a verifier can re-derive offline from the blob."""


def tx_id_from_blob(rail: str, signed_blob_hex: str) -> str | None:
    """Re-derive a transaction id from its signed blob, or None for an unknown rail.

    ``None`` is not a failure — it means this verifier cannot check that rail, and
    the check is reported as ``not_implemented`` rather than as a pass.
    """
    rule = TX_ID_RULES.get(rail)
    if rule is None:
        return None
    try:
        blob = bytes.fromhex(signed_blob_hex)
    except ValueError:
        return None
    result: str = rule(blob)
    return result


# --------------------------------------------------------------------------- #
# Transactions in flight
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class UnsignedTx:
    """A prepared transaction, anchored or still holding the placeholder.

    ``signing_payload`` is exactly the bytes a signer signs — for XRPL, the
    multisigning pre-image, which already carries the signer's account. ``fields``
    is the same transaction in plain, canonical JSON, and is what the signer
    checks against the intent. ``handle`` is the adapter's own object; it never
    crosses the RPC boundary and is never hashed.
    """

    rail: str
    treasury: str
    signing_payload: str
    anchor_offset: int
    fields: JSONObject
    commitment: str = ANCHOR_PLACEHOLDER_HEX
    handle: object | None = None

    def __post_init__(self) -> None:
        token(self.rail, "unsigned_tx.rail", max_length=64)
        token(self.treasury, "unsigned_tx.treasury", max_length=128)
        token(self.signing_payload, "unsigned_tx.signing_payload", max_length=131072)
        if isinstance(self.anchor_offset, bool) or not isinstance(self.anchor_offset, int):
            raise RailError("unsigned_tx.anchor_offset must be an integer")
        if self.anchor_offset < 0:
            raise RailError("unsigned_tx.anchor_offset must not be negative")
        ensure_canonical_content(self.fields, path="unsigned_tx.fields")
        hex_digest(self.commitment, "unsigned_tx.commitment")
        if self.anchor_offset + ANCHOR_BYTES > len(self.payload_bytes):
            raise RailError("unsigned_tx.anchor_offset points past the end of the payload")

    @property
    def payload_bytes(self) -> bytes:
        try:
            return bytes.fromhex(self.signing_payload)
        except ValueError as exc:
            raise RailError("unsigned_tx.signing_payload is not hex") from exc

    @property
    def anchor(self) -> bytes:
        """The 32 bytes currently sitting in the anchor field."""
        return self.payload_bytes[self.anchor_offset : self.anchor_offset + ANCHOR_BYTES]

    def with_anchor(self, commitment: str) -> UnsignedTx:
        """The same transaction with ``commitment`` written into the anchor field.

        This is the splice the signer performs. It changes 32 bytes and nothing
        else, which is why the adapter can reproduce the result independently.
        """
        raw = bytearray(self.payload_bytes)
        digest = bytes.fromhex(hex_digest(commitment, "commitment"))
        raw[self.anchor_offset : self.anchor_offset + ANCHOR_BYTES] = digest
        return dataclasses.replace(self, signing_payload=bytes(raw).hex(), commitment=commitment)

    def to_content(self) -> JSONObject:
        """The wire form. ``handle`` is deliberately absent."""
        return {
            "rail": self.rail,
            "treasury": self.treasury,
            "signing_payload": self.signing_payload,
            "anchor_offset": self.anchor_offset,
            "fields": self.fields,
            "commitment": self.commitment,
        }

    @classmethod
    def from_content(cls, data: Any) -> UnsignedTx:
        obj = _object(data, "unsigned_tx")
        fields = obj.get("fields", {})
        if not isinstance(fields, dict):
            raise RailError("unsigned_tx.fields must be an object")
        return cls(
            rail=_required(obj, "rail", "unsigned_tx"),
            treasury=_required(obj, "treasury", "unsigned_tx"),
            signing_payload=_required(obj, "signing_payload", "unsigned_tx"),
            anchor_offset=_required(obj, "anchor_offset", "unsigned_tx"),
            fields=fields,
            commitment=obj.get("commitment", ANCHOR_PLACEHOLDER_HEX),
        )


@dataclasses.dataclass(frozen=True)
class Signature:
    """One signature over an unsigned transaction's payload."""

    public_key: str
    signature: str
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        token(self.public_key, "signature.public_key", max_length=256)
        token(self.signature, "signature.signature", max_length=2048)
        token(self.algorithm, "signature.algorithm", max_length=64)

    def to_content(self) -> JSONObject:
        return {
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_content(cls, data: Any) -> Signature:
        obj = _object(data, "signature")
        return cls(
            public_key=_required(obj, "public_key", "signature"),
            signature=_required(obj, "signature", "signature"),
            algorithm=obj.get("algorithm", "ed25519"),
        )


@dataclasses.dataclass(frozen=True)
class PartialTx:
    """An anchored transaction carrying some of the signatures it needs."""

    unsigned: UnsignedTx
    signatures: tuple[Signature, ...] = ()

    def with_signature(self, signature: Signature) -> PartialTx:
        return dataclasses.replace(self, signatures=(*self.signatures, signature))


@dataclasses.dataclass(frozen=True)
class SignedTx:
    """A transaction ready to submit: the blob, and who signed it."""

    rail: str
    blob: str
    commitment: str
    signatures: tuple[Signature, ...] = ()
    handle: object | None = None

    def __post_init__(self) -> None:
        token(self.rail, "signed_tx.rail", max_length=64)
        token(self.blob, "signed_tx.blob", max_length=131072)
        hex_digest(self.commitment, "signed_tx.commitment")

    def tx_id(self) -> str | None:
        """The id this blob will have on the ledger, derived offline."""
        return tx_id_from_blob(self.rail, self.blob)


@dataclasses.dataclass(frozen=True)
class SettlementRef:
    """What the rail said after it validated the transaction."""

    rail: str
    tx_hash: str
    ledger_index: int
    close_time: str
    observed_anchor: str | None = None
    signed_tx_blob: str | None = None
    engine_result: str | None = None
    validated: bool = True
    observed_memos: tuple[JSONObject, ...] | None = None

    def __post_init__(self) -> None:
        token(self.rail, "settlement_ref.rail", max_length=64)
        token(self.tx_hash, "settlement_ref.tx_hash", max_length=128)
        if isinstance(self.ledger_index, bool) or not isinstance(self.ledger_index, int):
            raise RailError("settlement_ref.ledger_index must be an integer")
        instant(self.close_time, "settlement_ref.close_time")

    def to_content(self) -> JSONObject:
        return drop_none(
            {
                "rail": self.rail,
                "tx_hash": self.tx_hash,
                "ledger_index": self.ledger_index,
                "close_time": self.close_time,
                "observed_anchor": self.observed_anchor,
                "engine_result": self.engine_result,
                "validated": self.validated,
                "observed_memos": list(self.observed_memos) if self.observed_memos else None,
            }
        )


@dataclasses.dataclass(frozen=True)
class SettlementProof:
    """Evidence captured at settlement time (plan D20).

    ``captured`` names exactly what is inside and ``missing`` names what a full
    offline inclusion proof would still need. Both are written into the proof
    rather than assumed, because a proof that does not say what it is missing is
    read as complete.
    """

    rail: str
    tx_hash: str
    ledger_index: int
    ledger_hash: str | None = None
    ledger_header: JSONValue = None
    transaction: JSONValue = None
    tx_path: JSONValue = None
    """Siblings and directions from this transaction to the header's transaction root.

    The link that turns "a quorum signed some ledger" into "this payment is in
    it". XRPL captures leave it ``None`` and name ``shamap_path`` in
    :attr:`missing`; the fake rail builds it, so the offline-inclusion path is
    exercised rather than merely specified.
    """

    validations: tuple[JSONValue, ...] = ()
    captured: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def proof_ref(self) -> str:
        """A short, stable id for this proof, suitable for the settlement leaf."""
        return f"{self.rail}:{self.ledger_index}:{self.tx_hash[:16].lower()}"

    def to_content(self) -> JSONObject:
        content = drop_none(
            {
                "rail": self.rail,
                "tx_hash": self.tx_hash,
                "ledger_index": self.ledger_index,
                "ledger_hash": self.ledger_hash,
                "ledger_header": self.ledger_header,
                "transaction": self.transaction,
                "tx_path": self.tx_path,
                "validations": list(self.validations),
                "captured": list(self.captured),
                "missing": list(self.missing),
            }
        )
        return content


def _object(data: Any, owner: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise RailError(f"{owner} must be an object, got {type(data).__name__}")
    return data


def _required(data: Mapping[str, Any], key: str, owner: str) -> Any:
    if key not in data:
        raise RailError(f"{owner} requires {key}")
    return data[key]
