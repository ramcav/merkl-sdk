"""XRPL primitives a settlement verifier needs and ``xrpl-py`` does not give it.

Three things, in the order a proof actually needs them:

``build_tx_path`` / ``fold_tx_path``
    The transaction SHAMap: a 16-ary radix trie over a ledger's full transaction
    set, keyed by transaction id. The adapter builds the whole tree once, at
    capture time, to extract the sibling hashes from one leaf to the root
    (``build_tx_path``); the verifier only ever folds that short path back up
    (``fold_tx_path``). Both share the two node hashes rippled defines
    (``HashPrefix::InnerNode`` = ``MIN\\0``, ``HashPrefix::TxNode`` = ``SND\\0``),
    proven against real testnet ledgers in ``tests/core/test_verify_xrpl.py``
    (the tree's root must equal the ledger header's ``transaction_hash``).

``verify_validation``
    A validator's ``STValidation`` message, reconstructed from the raw blob the
    ``validations`` stream publishes (the ``data`` field): parse every field,
    reserialize everything but the signature (``HashPrefix::Validation`` =
    ``VAL\\0``, exactly rippled's ``STObject::getSigningHash``), and check it
    against the embedded ``SigningPubKey`` — secp256k1 or Ed25519, whichever the
    validator used.

``verify_manifest`` / ``pin_validator_list``
    A manifest is the same kind of object (``HashPrefix::Manifest`` = ``MAN\\0``):
    the master key signs the ephemeral key, and — for a published UNL — a
    top-level signature over the raw ``blob`` bytes is made with that ephemeral
    key. ``pin_validator_list`` runs that whole chain over a document already
    fetched from a URL like ``vl.ripple.com`` and returns the pinned master-key
    set a verifier can trust *without* re-fetching it at verification time.

No base58 anywhere: every public key this module reads comes straight out of a
binary field (manifest, validation, or a UNL's own hex `validation_public_key`)
already in raw form. The base58 "n..." strings rippled prints for humans never
have to be decoded to verify anything here.

Pure stdlib plus :mod:`merkl.core.crypto` (which is ``cryptography``, for
verification only) — no ``xrpl-py``. This module is read by
:mod:`merkl.core.verify.settlement`, which never imports the rail SDK either.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
from collections.abc import Collection, Mapping, Sequence
from typing import Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.crypto import CryptoError, ed25519_verify, hex_bytes, secp256k1_verify_digest

__all__ = [
    "CryptoError",
    "FieldSpan",
    "ManifestInfo",
    "TX_NODE_PREFIX",
    "INNER_NODE_PREFIX",
    "VALIDATION_PREFIX",
    "MANIFEST_PREFIX",
    "PinnedUNLReading",
    "ValidationInfo",
    "ValidationVerdict",
    "build_tx_path",
    "encode_vl",
    "evaluate_validation",
    "fold_tx_path",
    "inner_node_hash",
    "parse_fields",
    "parse_manifest",
    "parse_validation",
    "pin_validator_list",
    "tx_leaf_hash",
    "verify_manifest",
    "verify_validation",
]

# --------------------------------------------------------------------------- #
# Hash prefixes (rippled's HashPrefix.h) and the zero hash
# --------------------------------------------------------------------------- #

TX_NODE_PREFIX: Final = bytes.fromhex("534E4400")
"""``SND\\0`` — a transaction-with-metadata SHAMap leaf."""

INNER_NODE_PREFIX: Final = bytes.fromhex("4D494E00")
"""``MIN\\0`` — a SHAMap inner node's 16 children."""

VALIDATION_PREFIX: Final = bytes.fromhex("56414C00")
"""``VAL\\0`` — an ``STValidation``'s signing hash."""

MANIFEST_PREFIX: Final = bytes.fromhex("4D414E00")
"""``MAN\\0`` — a manifest's signing hash."""

_ZERO32: Final = b"\x00" * 32


def _sha512_half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


# --------------------------------------------------------------------------- #
# XRPL's variable-length prefix (used by Blob and Vector256 fields)
# --------------------------------------------------------------------------- #


def encode_vl(data: bytes) -> bytes:
    """The VL length prefix XRPL puts before a blob, then the blob itself."""
    length = len(data)
    if length <= 192:
        return bytes([length]) + data
    if length <= 12480:
        length -= 193
        return bytes([193 + (length >> 8), length & 0xFF]) + data
    if length <= 918744:
        length -= 12481
        return bytes([241 + (length >> 16), (length >> 8) & 0xFF, length & 0xFF]) + data
    raise ValueError(f"blob of {len(data)} bytes is too long for XRPL's VL encoding")


def _read_vl_length(data: bytes, i: int) -> tuple[int, int]:
    """The length a VL prefix encodes, and the offset just past the prefix."""
    if i >= len(data):
        raise ValueError("truncated VL length prefix")
    b0 = data[i]
    if b0 <= 192:
        return b0, i + 1
    if b0 <= 240:
        if i + 1 >= len(data):
            raise ValueError("truncated VL length prefix")
        return 193 + (b0 - 193) * 256 + data[i + 1], i + 2
    if i + 2 >= len(data):
        raise ValueError("truncated VL length prefix")
    return 12481 + (b0 - 241) * 65536 + data[i + 1] * 256 + data[i + 2], i + 3


# --------------------------------------------------------------------------- #
# A minimal STObject field walker
# --------------------------------------------------------------------------- #
#
# Only the field types that actually appear in an STValidation or a manifest
# (rippled's SOTemplate for each — see module docstring): fixed-width integers
# and hashes, VL-encoded blobs and Vector256, and the always-8-byte native
# (XRP) form of Amount. Anything else (AccountID, PathSet, nested objects, an
# issued-currency Amount) is not part of either template; a field of one of
# those types raises rather than guesses, so an object this walker cannot
# fully account for is never silently half-read.

_FIXED_WIDTH: Final[dict[int, int]] = {
    16: 1,  # UInt8
    1: 2,  # UInt16
    2: 4,  # UInt32
    3: 8,  # UInt64
    4: 16,  # Hash128
    17: 20,  # Hash160
    20: 12,  # UInt96
    5: 32,  # Hash256
    21: 24,  # Hash192
    22: 48,  # Hash384
    23: 64,  # Hash512
}
_VL_ENCODED: Final = frozenset({7, 19})  # Blob, Vector256
_AMOUNT_TYPE: Final = 6


@dataclasses.dataclass(frozen=True)
class FieldSpan:
    """One field's position in a serialized object.

    ``start``/``end`` bound the whole field (header, length prefix if any, and
    value) — the span you copy verbatim to keep a field in a re-serialization.
    ``value_start`` is where the value itself begins.
    """

    type_code: int
    field_code: int
    start: int
    end: int
    value_start: int

    def value(self, data: bytes) -> bytes:
        return data[self.value_start : self.end]


def parse_fields(data: bytes) -> list[FieldSpan]:
    """Walk a serialized top-level object into its fields, in wire order.

    Wire order for a well-formed object is already canonical (ascending
    ``(type_code, field_code)``), which is what lets a caller drop one field
    and re-concatenate the rest to get another valid, still-canonical signing
    preimage — see :func:`_signing_preimage`.

    Raises ``ValueError`` on anything this walker cannot account for: a
    truncated field, or a field type outside the fixed set above. A capture
    this cannot parse is reported as unchecked evidence by the caller, never
    silently accepted.
    """
    fields: list[FieldSpan] = []
    i = 0
    n = len(data)
    try:
        while i < n:
            start = i
            header = data[i]
            i += 1
            type_code = header >> 4
            field_code = header & 0x0F
            if type_code == 0:
                type_code = data[i]
                i += 1
            if field_code == 0:
                field_code = data[i]
                i += 1
            if type_code in _VL_ENCODED:
                length, value_start = _read_vl_length(data, i)
                i = value_start + length
            elif type_code == _AMOUNT_TYPE:
                if (data[i] & 0x80) != 0:
                    raise ValueError(
                        f"field ({type_code},{field_code}) at offset {start} is a "
                        "non-native Amount, which never appears in a Validation or "
                        "Manifest object"
                    )
                value_start = i
                i += 8
            else:
                width = _FIXED_WIDTH.get(type_code)
                if width is None:
                    raise ValueError(
                        f"field ({type_code},{field_code}) at offset {start} has an "
                        "unsupported type for this walker"
                    )
                value_start = i
                i += width
            if i > n:
                raise ValueError(
                    f"field ({type_code},{field_code}) at offset {start} is truncated"
                )
            fields.append(FieldSpan(type_code, field_code, start, i, value_start))
    except IndexError as exc:
        raise ValueError(f"truncated field at offset {i}") from exc
    return fields


def _signing_preimage(
    data: bytes, fields: Sequence[FieldSpan], *exclude: tuple[int, int]
) -> bytes:
    """``data`` with the given ``(type_code, field_code)`` spans excised.

    Order is preserved because it was already canonical — dropping elements
    from a sorted sequence leaves the rest sorted.
    """
    excluded = frozenset(exclude)
    out = bytearray()
    for f in fields:
        if (f.type_code, f.field_code) not in excluded:
            out += data[f.start : f.end]
    return bytes(out)


def _field(
    fields: Sequence[FieldSpan], data: bytes, type_code: int, field_code: int
) -> bytes | None:
    for f in fields:
        if f.type_code == type_code and f.field_code == field_code:
            return f.value(data)
    return None


# --------------------------------------------------------------------------- #
# Generic signature check: secp256k1 or Ed25519, by the key's own prefix byte
# --------------------------------------------------------------------------- #


def _verify_generic(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """XRPL's own convention: 0xED means Ed25519, 0x02/0x03 means secp256k1.

    Ed25519 hashes the message itself; secp256k1 signs SHA-512Half of it, since
    that is what every XRPL object (validations, manifests, ledger headers)
    hashes with.
    """
    if len(public_key) != 33:
        raise ValueError(f"public key must be 33 bytes, got {len(public_key)}")
    if public_key[0] == 0xED:
        return ed25519_verify(public_key[1:].hex(), signature.hex(), message)
    if public_key[0] in (0x02, 0x03):
        return secp256k1_verify_digest(public_key.hex(), signature.hex(), _sha512_half(message))
    raise ValueError(f"public key has an unrecognized prefix byte 0x{public_key[0]:02x}")


# --------------------------------------------------------------------------- #
# The transaction SHAMap
# --------------------------------------------------------------------------- #


def tx_leaf_hash(tx_id: bytes, tx_blob: bytes, meta_blob: bytes) -> bytes:
    """A transaction-with-metadata SHAMap leaf's hash.

    ``SHA-512Half("SND\\0" ‖ VL(tx_blob) ‖ VL(meta_blob) ‖ tx_id)`` — rippled's
    ``Ledger::rawTxInsert`` builds exactly this item, and
    ``SHAMapTxPlusMetaLeafNode::updateHash`` hashes it exactly this way.
    """
    if len(tx_id) != 32:
        raise ValueError(f"tx_id must be 32 bytes, got {len(tx_id)}")
    return _sha512_half(TX_NODE_PREFIX + encode_vl(tx_blob) + encode_vl(meta_blob) + tx_id)


def inner_node_hash(children: Sequence[bytes]) -> bytes:
    """A SHAMap inner node's hash: its 16 children, empty branches zeroed.

    ``SHA-512Half("MIN\\0" ‖ child[0] ‖ ... ‖ child[15])``, or the all-zero hash
    when every branch is empty (``SHAMapInnerNode::updateHash``).
    """
    if len(children) != 16:
        raise ValueError(f"a SHAMap inner node has 16 branches, got {len(children)}")
    for child in children:
        if len(child) != 32:
            raise ValueError("every child hash must be 32 bytes")
    if all(child == _ZERO32 for child in children):
        return _ZERO32
    return _sha512_half(INNER_NODE_PREFIX + b"".join(children))


def _nibble(key: bytes, depth: int) -> int:
    byte = key[depth // 2]
    return (byte >> 4) if depth % 2 == 0 else (byte & 0x0F)


def _subtree_hash(items: Sequence[tuple[bytes, bytes, bytes]], depth: int) -> bytes:
    if len(items) == 1:
        tx_id, blob, meta = items[0]
        return tx_leaf_hash(tx_id, blob, meta)
    buckets: list[list[tuple[bytes, bytes, bytes]]] = [[] for _ in range(16)]
    for item in items:
        buckets[_nibble(item[0], depth)].append(item)
    children = [_subtree_hash(b, depth + 1) if b else _ZERO32 for b in buckets]
    return inner_node_hash(children)


def build_tx_path(
    target_tx_id: bytes, items: Sequence[tuple[bytes, bytes, bytes]]
) -> tuple[str, list[JSONObject]]:
    """Build the whole transaction SHAMap and return one leaf's path to the root.

    ``items`` is the ledger's *full* transaction set, each a
    ``(tx_id, tx_blob, meta_blob)`` triple. Returns ``(root_hex, path)`` where
    ``path`` runs leaf-to-root: ``[{"nibble": int, "siblings": [15 hex hashes]},
    ...]``, one step per inner node actually materialized along the way (path
    compression means a transaction sharing no prefix with any other needs a
    single step, not 64). Raises ``ValueError`` if ``target_tx_id`` is not
    among ``items`` — a capture bug should be loud, not a silently useless
    empty path.
    """
    if not items:
        raise ValueError("no transactions to build a path from")
    if not any(item[0] == target_tx_id for item in items):
        raise ValueError("the target transaction is not in this ledger's transaction set")

    path: list[JSONObject] = []

    def walk(sub_items: Sequence[tuple[bytes, bytes, bytes]], depth: int) -> bytes:
        if len(sub_items) == 1:
            tx_id, blob, meta = sub_items[0]
            return tx_leaf_hash(tx_id, blob, meta)
        buckets: list[list[tuple[bytes, bytes, bytes]]] = [[] for _ in range(16)]
        for item in sub_items:
            buckets[_nibble(item[0], depth)].append(item)
        in_this_subtree = any(item[0] == target_tx_id for item in sub_items)
        target_nibble = _nibble(target_tx_id, depth) if in_this_subtree else -1
        children: list[bytes] = []
        for branch in range(16):
            bucket = buckets[branch]
            if not bucket:
                children.append(_ZERO32)
            elif in_this_subtree and branch == target_nibble:
                children.append(walk(bucket, depth + 1))
            else:
                children.append(_subtree_hash(bucket, depth + 1))
        if in_this_subtree:
            siblings: list[JSONValue] = [
                children[b].hex() for b in range(16) if b != target_nibble
            ]
            step: JSONObject = {"nibble": target_nibble, "siblings": siblings}
            path.append(step)
        return inner_node_hash(children)

    root = walk(list(items), 0)
    return root.hex(), path


def fold_tx_path(
    tx_id_hex: str, tx_blob_hex: str, meta_hex: str, path: Sequence[Mapping[str, object]]
) -> str | None:
    """Recompute a SHAMap root from a leaf and its path. ``None`` on anything malformed.

    The counterpart to :func:`build_tx_path`: recomputes the leaf hash from the
    transaction's own raw bytes (so the path is tied to *this* transaction's
    content, not merely to a hash it hands over) and folds ``path`` from leaf
    to root, same order it was built in.
    """
    try:
        tx_id = bytes.fromhex(tx_id_hex)
        tx_blob = bytes.fromhex(tx_blob_hex)
        meta = bytes.fromhex(meta_hex)
        current = tx_leaf_hash(tx_id, tx_blob, meta)
        for step in path:
            nibble = step.get("nibble") if isinstance(step, Mapping) else None
            siblings = step.get("siblings") if isinstance(step, Mapping) else None
            if not isinstance(nibble, int) or isinstance(nibble, bool) or not (0 <= nibble <= 15):
                return None
            if not isinstance(siblings, list) or len(siblings) != 15:
                return None
            children = [_ZERO32] * 16
            children[nibble] = current
            others = iter(bytes.fromhex(s) for s in siblings)
            for branch in range(16):
                if branch != nibble:
                    sibling = next(others)
                    if len(sibling) != 32:
                        return None
                    children[branch] = sibling
            current = inner_node_hash(children)
        return current.hex()
    except (ValueError, TypeError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
# STValidation
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ValidationInfo:
    """What one ``STValidation`` blob says, and whether its signature checks out."""

    ledger_hash: str
    signing_key: str
    signature_valid: bool
    ledger_index: int | None = None


def parse_validation(data: bytes) -> tuple[list[FieldSpan], bytes, bytes, bytes]:
    """Fields, ``LedgerHash``, ``SigningPubKey`` and ``Signature`` — raw bytes.

    Raises ``ValueError`` when the object does not parse or is missing one of
    the three fields every validation needs to be checked at all.
    """
    fields = parse_fields(data)
    ledger_hash = _field(fields, data, 5, 1)  # Hash256 LedgerHash, nth 1
    signing_key = _field(fields, data, 7, 3)  # Blob SigningPubKey, nth 3
    signature = _field(fields, data, 7, 6)  # Blob Signature, nth 6
    if ledger_hash is None or signing_key is None or signature is None:
        raise ValueError("validation is missing LedgerHash, SigningPubKey or Signature")
    return fields, ledger_hash, signing_key, signature


def verify_validation(data: bytes) -> ValidationInfo:
    """Recompute the signing hash and check ``Signature`` against ``SigningPubKey``.

    ``SHA-512Half("VAL\\0" ‖ every field except Signature)``, exactly
    ``STObject::getSigningHash(HashPrefix::Validation)`` — Signature is the only
    field ``isSigningField: false`` marks in ``STValidation``'s template, so it
    is the only one excised here.
    """
    fields, ledger_hash, signing_key, signature = parse_validation(data)
    preimage = _signing_preimage(data, fields, (7, 6))
    valid = _verify_generic(signing_key, signature, VALIDATION_PREFIX + preimage)
    ledger_seq = _field(fields, data, 2, 6)  # UInt32 LedgerSequence, nth 6
    return ValidationInfo(
        ledger_hash=ledger_hash.hex(),
        signing_key=signing_key.hex(),
        signature_valid=valid,
        ledger_index=int.from_bytes(ledger_seq, "big") if ledger_seq is not None else None,
    )


# --------------------------------------------------------------------------- #
# Manifests
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ManifestInfo:
    """A manifest's identity, and whether both signatures check out."""

    sequence: int
    master_key: str
    signing_key: str
    domain: str | None
    master_signature_valid: bool
    ephemeral_signature_valid: bool

    @property
    def valid(self) -> bool:
        return self.master_signature_valid and self.ephemeral_signature_valid


def parse_manifest(
    data: bytes,
) -> tuple[list[FieldSpan], int, bytes, bytes, bytes, bytes, bytes | None]:
    """Fields, sequence, master key, ephemeral key, signature, master signature, domain."""
    fields = parse_fields(data)
    sequence = _field(fields, data, 2, 4)  # UInt32 Sequence, nth 4
    master_key = _field(fields, data, 7, 1)  # Blob PublicKey, nth 1
    signing_key = _field(fields, data, 7, 3)  # Blob SigningPubKey, nth 3
    signature = _field(fields, data, 7, 6)  # Blob Signature, nth 6
    master_signature = _field(fields, data, 7, 18)  # Blob MasterSignature, nth 18
    domain = _field(fields, data, 7, 7)  # Blob Domain, nth 7 (optional)
    if sequence is None or master_key is None or signing_key is None:
        raise ValueError("manifest is missing Sequence, PublicKey or SigningPubKey")
    if signature is None or master_signature is None:
        raise ValueError("manifest is missing Signature or MasterSignature")
    return (
        fields,
        int.from_bytes(sequence, "big"),
        master_key,
        signing_key,
        signature,
        master_signature,
        domain,
    )


def verify_manifest(data: bytes) -> ManifestInfo:
    """Recompute the manifest's signing hash and check both signatures against it.

    Both ``Signature`` (the ephemeral key, over itself) and ``MasterSignature``
    (the master key vouching for that ephemeral key) cover the same preimage:
    ``SHA-512Half("MAN\\0" ‖ every field except Signature and MasterSignature)``.
    """
    fields, sequence, master_key, signing_key, signature, master_signature, domain = (
        parse_manifest(data)
    )
    preimage = _signing_preimage(data, fields, (7, 6), (7, 18))
    message = MANIFEST_PREFIX + preimage
    master_ok = _verify_generic(master_key, master_signature, message)
    ephemeral_ok = _verify_generic(signing_key, signature, message)
    return ManifestInfo(
        sequence=sequence,
        master_key=master_key.hex(),
        signing_key=signing_key.hex(),
        domain=domain.decode("ascii", errors="replace") if domain else None,
        master_signature_valid=master_ok,
        ephemeral_signature_valid=ephemeral_ok,
    )


# --------------------------------------------------------------------------- #
# A validation entry against a pinned master-key set
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ValidationVerdict:
    """What one captured validation entry proves about one pinned validator."""

    outcome: str  # "agree" | "disagree" | "unchecked"
    master_key: str | None
    detail: str


def evaluate_validation(
    entry: Mapping[str, object],
    *,
    ledger_hash: str,
    pinned_masters: Collection[str],
) -> ValidationVerdict | None:
    """Does this captured validation entry count as a pinned validator's agreement?

    ``entry`` is one member of a settlement proof's ``validations``: at minimum
    the raw ``data`` hex the validations stream published, and — captured
    separately, since the stream itself does not carry it — the ``manifest``
    (base64) in effect for that validator when it signed. Returns ``None`` when
    the entry cannot be attributed to any *pinned* master key at all (an
    unrelated validator, or a validator whose current manifest this capture
    does not carry): it is not evidence either way, so it does not count.

    A pinned master key's own validation counting only when its manifest is
    present, both of the manifest's own signatures check out, its ephemeral key
    matches the one that actually signed this validation, and *that* signature
    checks out too — every link is independently verified here, none of it
    taken from a self-reported ``master_key`` field on the message.
    """
    raw = entry.get("data")
    if not isinstance(raw, str) or not raw:
        return ValidationVerdict("unchecked", None, "the entry carries no raw validation data")
    try:
        validation = verify_validation(bytes.fromhex(raw))
    except (ValueError, CryptoError) as exc:
        return ValidationVerdict("unchecked", None, f"the validation does not parse: {exc}")

    manifest_b64 = entry.get("manifest")
    if not isinstance(manifest_b64, str) or not manifest_b64:
        return ValidationVerdict(
            "unchecked", None, f"no manifest was captured for signing key {validation.signing_key}"
        )
    try:
        manifest = verify_manifest(base64.b64decode(manifest_b64))
    except Exception as exc:  # noqa: BLE001 - any parse failure of borrowed base64 is unchecked
        return ValidationVerdict("unchecked", None, f"the manifest does not parse: {exc}")

    master = manifest.master_key.lower()
    if master not in {m.lower() for m in pinned_masters}:
        return None  # not a validator this verifier pinned — not evidence either way
    if not manifest.valid:
        return ValidationVerdict(
            "unchecked", master, f"validator {master}'s manifest does not verify"
        )
    if manifest.signing_key.lower() != validation.signing_key.lower():
        return ValidationVerdict(
            "unchecked",
            master,
            f"validator {master}'s pinned manifest names a different ephemeral key",
        )
    if validation.ledger_hash.lower() != ledger_hash.lower():
        return ValidationVerdict(
            "disagree", master, f"validator {master} signed a different ledger hash"
        )
    if not validation.signature_valid:
        return ValidationVerdict(
            "disagree", master, f"validator {master}'s signature does not verify"
        )
    return ValidationVerdict("agree", master, f"validator {master} signed ledger {ledger_hash}")


# --------------------------------------------------------------------------- #
# Turning a published validator list into a pinned form
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PinnedUNLReading:
    """What auditing a published validator list found.

    ``masters`` is what a verifier pins: the master keys, hex, of every
    validator whose manifest verified against the publisher's own signature
    chain. ``skipped`` names every validator entry that did not make it in, and
    why — the audit trail for whoever has to explain later why a validator is
    or is not trusted.
    """

    publisher_key: str
    sequence: int
    expiration: int
    masters: tuple[str, ...]
    skipped: tuple[str, ...]

    def quorum(self, fraction: float = 0.8) -> int:
        """Validators that must agree: at least ``fraction`` of the pinned set."""
        return math.ceil(fraction * len(self.masters))


def pin_validator_list(document: Mapping[str, object]) -> PinnedUNLReading:
    """Audit a published validator list (``vl.ripple.com``, ``vl.xrplf.org``, ...).

    ``document`` is the JSON object such a URL returns, already fetched by the
    caller — this function does no network I/O, so the audit is reproducible
    from a file saved once and reviewed by a human. Verifies the whole chain:
    the publisher's own manifest (master key signs ephemeral key), the
    top-level ``signature`` over the raw decoded ``blob`` (made with that
    ephemeral key), and every validator's own manifest inside the blob. Raises
    ``ValueError`` when the *publisher's* chain does not check out — that
    makes the entire list untrustworthy, not just one entry. A single bad
    validator entry inside an otherwise-good list is skipped, not fatal.
    """
    publisher_key = document.get("public_key")
    manifest_b64 = document.get("manifest")
    blob_b64 = document.get("blob")
    signature_hex = document.get("signature")
    if (
        not isinstance(publisher_key, str)
        or not isinstance(manifest_b64, str)
        or not isinstance(blob_b64, str)
        or not isinstance(signature_hex, str)
        or not (publisher_key and manifest_b64 and blob_b64 and signature_hex)
    ):
        raise ValueError(
            "not a validator-list document: missing public_key, manifest, blob or signature"
        )

    publisher_manifest = verify_manifest(base64.b64decode(manifest_b64))
    if not publisher_manifest.valid:
        raise ValueError("the publisher's own manifest does not verify")
    if publisher_manifest.master_key.lower() != publisher_key.lower():
        raise ValueError("the publisher's manifest names a different master key than public_key")

    blob_bytes = base64.b64decode(blob_b64)
    blob_signature = hex_bytes(signature_hex.lower(), "unl.signature")
    if not _verify_generic(
        bytes.fromhex(publisher_manifest.signing_key), blob_signature, blob_bytes
    ):
        raise ValueError(
            "the list's top-level signature does not verify against the publisher's manifest"
        )

    blob = json.loads(blob_bytes)
    if not isinstance(blob, dict) or not isinstance(blob.get("validators"), list):
        raise ValueError("the decoded blob is not a validator-list body")

    masters: list[str] = []
    skipped: list[str] = []
    for entry in blob["validators"]:
        if not isinstance(entry, dict):
            skipped.append("(not an object)")
            continue
        claimed = entry.get("validation_public_key")
        manifest_value = entry.get("manifest")
        if not isinstance(claimed, str) or not isinstance(manifest_value, str):
            skipped.append(str(claimed))
            continue
        try:
            info = verify_manifest(base64.b64decode(manifest_value))
        except (ValueError, CryptoError) as exc:
            skipped.append(f"{claimed} (manifest does not parse: {exc})")
            continue
        if not info.valid:
            skipped.append(f"{claimed} (manifest signatures do not verify)")
            continue
        if info.master_key.lower() != claimed.lower():
            skipped.append(f"{claimed} (manifest names a different master key)")
            continue
        masters.append(info.master_key.lower())

    return PinnedUNLReading(
        publisher_key=publisher_manifest.master_key,
        sequence=int(blob.get("sequence", 0)),
        expiration=int(blob.get("expiration", 0)),
        masters=tuple(masters),
        skipped=tuple(skipped),
    )
