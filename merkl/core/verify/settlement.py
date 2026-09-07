"""Settlement proofs — what a capture taken at settlement time actually proves.

Plan D20 makes the initiating rail capture evidence *at submit time*: the
validated transaction, the ledger header, and the validation messages the
network broadcast for that ledger. This module reads such a capture back and
says, check by check, how far it gets.

Three questions, kept separate on purpose, because collapsing them is how a
verifier ends up claiming more than it holds:

``settlement.proof_matches_receipt``
    Is the proof even about this transaction? A capture for another tx hash or
    another ledger index is not weak evidence, it is the wrong evidence.

``settlement.ledger_header``
    Does the header hash to the ledger hash it claims? For a rail whose ledger
    hash is a function of its header (XRPL, and the fake rail modelled on it),
    recomputing it binds the header's transaction-set root to the ledger
    identity the validators signed. Without that link the transaction root is
    an unattested number in a JSON blob.

``settlement.validator_quorum``
    Did enough validators the *verifier* pinned sign that ledger hash? The key
    set and the threshold are arguments, never taken from the proof: a proof
    that nominates its own validators proves nothing.

And then the composite the reader actually asked about,
``settlement.ledger_inclusion``: is this transaction in that ledger? That needs
one more link — a path from the transaction to the header's transaction-set
root. Both rails carry it: the fake rail's own toy binary tree, and XRPL's real
16-ary transaction SHAMap (:mod:`merkl.core.verify.xrpl`), built by the adapter
at capture time from the ledger's full binary transaction set and folded back
here from the leaf — recomputed from the transaction's own raw bytes, not
merely a hash the proof hands over.

XRPL's validator quorum is a real check too, not a count: each validation entry
carries the raw ``STValidation`` blob the validations stream published and the
manifest in effect for that validator, and :func:`~merkl.core.verify.xrpl.evaluate_validation`
verifies the whole chain — the manifest's own signatures, that its ephemeral
key is the one that actually signed, and that signature itself — before an
entry counts as one *pinned master key's* agreement.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Mapping
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.checks import Check, CheckStatus, no_data, outcome
from merkl.core.crypto import CryptoError, ed25519_verify
from merkl.core.rail import RAIL_FAKE, RAIL_XRPL
from merkl.core.verify.xrpl import evaluate_validation, fold_tx_path

__all__ = [
    "CHECK_LEDGER_HEADER",
    "CHECK_PROOF_MATCHES",
    "CHECK_VALIDATOR_QUORUM",
    "FAKE_LEDGER_TAG",
    "FAKE_VALIDATION_TAG",
    "LEDGER_PROVEN_OFFLINE",
    "LEDGER_SUPPLIED_UNVERIFIED",
    "LEDGER_UNCHECKED",
    "LEDGER_VERIFIED_LIVE",
    "SettlementProofReading",
    "ValidatorTrust",
    "fake_ledger_hash",
    "fake_validation_message",
    "read_settlement_proof",
    "xrpl_ledger_hash",
]


# --------------------------------------------------------------------------- #
# Check names and the four states of plan D10's second line
# --------------------------------------------------------------------------- #


CHECK_PROOF_MATCHES: Final = "settlement.proof_matches_receipt"
CHECK_LEDGER_HEADER: Final = "settlement.ledger_header"
CHECK_VALIDATOR_QUORUM: Final = "settlement.validator_quorum"

LEDGER_PROVEN_OFFLINE: Final = "proven-offline"
"""A pinned validator quorum signed a ledger, and a path puts this tx inside it."""

LEDGER_VERIFIED_LIVE: Final = "verified-live"
"""A live rail query confirmed the transaction. Trusts whoever answered."""

LEDGER_SUPPLIED_UNVERIFIED: Final = "supplied-unverified"
"""The receipt names a ledger; nothing here proved the transaction is in it."""

LEDGER_UNCHECKED: Final = "unchecked"
"""Nothing settled, or no material to check was supplied."""


# --------------------------------------------------------------------------- #
# Ledger hashing, per rail
# --------------------------------------------------------------------------- #


XRPL_LEDGER_PREFIX: Final = bytes.fromhex("4C575200")
"""``LWR\\0`` — XRPL's hash prefix for a ledger header."""

FAKE_LEDGER_TAG: Final = b"merkl-fake-ledger-v1"
"""Domain tag of the fake rail's ledger identity. Not a real rail's encoding."""

FAKE_VALIDATION_TAG: Final = b"merkl-fake-validation-v1"
"""Domain tag of the bytes a fake-rail validator signs."""

_NUL: Final = b"\x00"


def _u8be(value: int) -> bytes:
    return int(value).to_bytes(8, "big")


def _sha512_half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def _u32(value: Any, field: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer")
    return int(value).to_bytes(4, "big")


def _u64(value: Any, field: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer")
    return int(value).to_bytes(8, "big")


def _u8(value: Any, field: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer")
    return int(value).to_bytes(1, "big")


def _hash32(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be hex")
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"{field} must be 32 bytes")
    return raw


def xrpl_ledger_hash(header: Mapping[str, Any]) -> str:
    """The ledger hash XRPL derives from a ledger header, lowercase hex.

    ``SHA-512Half("LWR\\0" ‖ ledger_index(4) ‖ total_coins(8) ‖ parent_hash(32) ‖
    transaction_hash(32) ‖ account_hash(32) ‖ parent_close_time(4) ‖
    close_time(4) ‖ close_time_resolution(1) ‖ close_flags(1))``

    Every field is in the header a ``ledger`` request returns. Recomputing it is
    what ties ``transaction_hash`` — the root of the ledger's transaction set —
    to the identity validators actually sign. Raises ``ValueError`` when a field
    is missing or malformed; the caller turns that into a named failed check.
    """
    index = header.get("ledger_index", header.get("seq"))
    body = b"".join(
        (
            XRPL_LEDGER_PREFIX,
            _u32(index, "ledger_index"),
            _u64(header["total_coins"], "total_coins"),
            _hash32(header["parent_hash"], "parent_hash"),
            _hash32(header["transaction_hash"], "transaction_hash"),
            _hash32(header["account_hash"], "account_hash"),
            _u32(header["parent_close_time"], "parent_close_time"),
            _u32(header["close_time"], "close_time"),
            _u8(header["close_time_resolution"], "close_time_resolution"),
            _u8(header["close_flags"], "close_flags"),
        )
    )
    return _sha512_half(body).hex()


def fake_ledger_hash(header: Mapping[str, Any]) -> str:
    """The fake rail's ledger identity, lowercase hex.

    ``SHA-256("merkl-fake-ledger-v1" ‖ NUL ‖ ledger_index(8, big-endian) ‖
    transaction_hash)``

    Deliberately the same *shape* as XRPL's: a ledger is identified by its
    sequence and the root of its transaction set, so the scenario suite exercises
    the same reasoning the real rail needs.
    """
    body = (
        FAKE_LEDGER_TAG
        + _NUL
        + _u8be(header["ledger_index"])
        + _hash32(header["transaction_hash"], "transaction_hash")
    )
    return hashlib.sha256(body).hexdigest()


LEDGER_HASH_RULES: Final[dict[str, Any]] = {
    RAIL_XRPL: xrpl_ledger_hash,
    RAIL_FAKE: fake_ledger_hash,
}
"""Rails whose ledger hash this verifier can recompute from a header."""


def fake_validation_message(ledger_hash: str, ledger_index: int) -> bytes:
    """The bytes a fake-rail validator signs.

    ``"merkl-fake-validation-v1" ‖ NUL ‖ ledger_hash(32) ‖ ledger_index(8, big-endian)``

    Both members are in the message so a signature over one ledger cannot be
    replayed onto another with the same hash prefix.
    """
    return FAKE_VALIDATION_TAG + _NUL + _hash32(ledger_hash, "ledger_hash") + _u8be(ledger_index)


# --------------------------------------------------------------------------- #
# What the verifier pinned
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ValidatorTrust:
    """The validator set and threshold the *verifier* chose, before it saw a proof.

    ``validators`` maps the identifier a validation message carries to that
    validator's Ed25519 public key in lowercase hex, or to the empty string for a
    validator that is pinned but whose signatures this verifier cannot check —
    XRPL's validation stream reports secp256k1 keys and does not republish the
    signed bytes, so a capture from it supports counting agreement, not verifying
    it. That distinction is reported, never smoothed over.

    ``quorum`` is how many *distinct* pinned validators must agree. It is a count
    and not a fraction so the arithmetic is the same in both implementations.
    """

    validators: Mapping[str, str] = dataclasses.field(default_factory=dict)
    quorum: int = 0

    def __post_init__(self) -> None:
        if self.quorum < 0:
            raise ValueError("validator quorum cannot be negative")
        if self.quorum > len(self.validators):
            raise ValueError(
                f"quorum {self.quorum} exceeds the {len(self.validators)} pinned validators"
            )

    @property
    def checkable(self) -> bool:
        """True when every pinned validator has a key whose signatures we can check."""
        return bool(self.validators) and all(bool(k) for k in self.validators.values())


# --------------------------------------------------------------------------- #
# Reading a proof
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class SettlementProofReading:
    """Every check the proof supported, plus the D10 ledger-inclusion state."""

    checks: tuple[Check, ...]
    ledger_inclusion: str
    detail: str

    def to_content(self) -> JSONObject:
        return {
            "ledger_inclusion": self.ledger_inclusion,
            "detail": self.detail,
            "checks": [c.to_content() for c in self.checks],
        }


def _member(proof: Mapping[str, Any], key: str) -> Any:
    return proof.get(key)


def _validation_entries(proof: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = _member(proof, "validations")
    if not isinstance(raw, list):
        return []
    return [v for v in raw if isinstance(v, Mapping)]


def _validator_id(entry: Mapping[str, Any]) -> str | None:
    for key in ("validator", "validation_public_key", "master_key", "signing_key"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _match_check(
    proof: Mapping[str, Any], *, rail: str, tx_hash: str, ledger_index: int | None
) -> Check:
    proof_tx = _member(proof, "tx_hash")
    proof_rail = _member(proof, "rail")
    proof_index = _member(proof, "ledger_index")
    if not isinstance(proof_tx, str) or proof_tx.lower() != tx_hash.lower():
        return Check(
            CHECK_PROOF_MATCHES,
            CheckStatus.FAIL,
            f"the proof is for transaction {proof_tx!r}, the receipt names {tx_hash}",
        )
    if proof_rail != rail:
        return Check(
            CHECK_PROOF_MATCHES,
            CheckStatus.FAIL,
            f"the proof is for rail {proof_rail!r}, the receipt names {rail!r}",
        )
    if ledger_index is not None and proof_index != ledger_index:
        return Check(
            CHECK_PROOF_MATCHES,
            CheckStatus.FAIL,
            f"the proof is for ledger {proof_index}, the receipt names {ledger_index}",
        )
    return outcome(
        CHECK_PROOF_MATCHES,
        True,
        f"the proof is about {rail} transaction {tx_hash} in ledger {proof_index}",
    )


def _header_check(proof: Mapping[str, Any], rail: str) -> tuple[Check, str | None]:
    """Recompute the ledger hash from the header. Returns the check and the hash."""
    header = _member(proof, "ledger_header")
    claimed = _member(proof, "ledger_hash")
    rule = LEDGER_HASH_RULES.get(rail)
    if rule is None:
        return (
            no_data(
                CHECK_LEDGER_HEADER,
                f"this verifier has no ledger-hash rule for rail {rail!r}",
            ),
            claimed if isinstance(claimed, str) else None,
        )
    if not isinstance(header, Mapping):
        return (
            no_data(CHECK_LEDGER_HEADER, "the proof carries no ledger header"),
            claimed if isinstance(claimed, str) else None,
        )
    try:
        derived = rule(header)
    except (KeyError, ValueError, TypeError) as exc:
        return (
            Check(
                CHECK_LEDGER_HEADER,
                CheckStatus.FAIL,
                f"the ledger header does not hash: {exc}",
            ),
            None,
        )
    if not isinstance(claimed, str) or not claimed:
        return (
            outcome(
                CHECK_LEDGER_HEADER,
                True,
                f"the header hashes to {derived}; the proof names no ledger hash to compare",
            ),
            derived,
        )
    return (
        outcome(
            CHECK_LEDGER_HEADER,
            derived.lower() == claimed.lower(),
            f"the header hashes to {derived}, the proof names {claimed.lower()}",
        ),
        derived,
    )


VALIDATION_MESSAGE_RULES: Final[dict[str, Any]] = {RAIL_FAKE: fake_validation_message}
"""Rails whose validation messages this generic path reconstructs and checks.

XRPL is absent from this dict on purpose: it has its own rule,
:func:`_xrpl_quorum_check`, since a real ``STValidation`` is not a fixed
message shape — it is a captured blob re-serialized minus its own signature,
checked against a manifest chain, not a two-field message an Ed25519 key signs
directly. :data:`VALIDATION_MESSAGE_RULES` is what is left of the *generic*
path once XRPL has its own: today, only the fake rail.
"""


def _xrpl_quorum_check(
    proof: Mapping[str, Any],
    ledger_hash: str,
    trust: ValidatorTrust,
    entries: list[Mapping[str, Any]],
) -> Check:
    """Count *pinned master keys* whose manifest-verified ephemeral key signed this ledger.

    Every link is checked by :func:`~merkl.core.verify.xrpl.evaluate_validation`:
    the manifest's own two signatures, that its ephemeral key is the one that
    actually signed this validation, and that signature itself. A validator
    nobody pinned returns ``None`` and does not count either way — see
    ``validator-outside-the-pinned-list`` in ``merkl/core/vectors/xrpl/cases.json``.
    """
    agreed: set[str] = set()
    disagreed: list[str] = []
    unchecked = 0
    for entry in entries:
        verdict = evaluate_validation(
            entry, ledger_hash=ledger_hash, pinned_masters=trust.validators.keys()
        )
        if verdict is None:
            continue
        if verdict.outcome == "agree" and verdict.master_key is not None:
            agreed.add(verdict.master_key)
        elif verdict.outcome == "disagree":
            disagreed.append(verdict.master_key or "(unknown)")
        else:
            unchecked += 1

    total = len(trust.validators)
    if disagreed:
        return Check(
            CHECK_VALIDATOR_QUORUM,
            CheckStatus.FAIL,
            f"{len(disagreed)} pinned validator(s) did not sign {ledger_hash}: "
            f"{', '.join(sorted(set(disagreed))[:4])}",
        )
    if len(agreed) >= trust.quorum:
        return outcome(
            CHECK_VALIDATOR_QUORUM,
            True,
            f"{len(agreed)} of {total} pinned validators signed ledger {ledger_hash}, "
            f"quorum is {trust.quorum}",
        )
    if unchecked:
        return no_data(
            CHECK_VALIDATOR_QUORUM,
            f"{len(agreed)} of {total} pinned validators verified, {unchecked} more validation "
            "entries did not carry enough evidence (a raw validation blob and a manifest for "
            "it) to check — agreement counted, not proved",
        )
    return outcome(
        CHECK_VALIDATOR_QUORUM,
        False,
        f"{len(agreed)} of {total} pinned validators signed ledger {ledger_hash}, "
        f"quorum is {trust.quorum}",
    )


def _quorum_check(
    proof: Mapping[str, Any],
    ledger_hash: str | None,
    trust: ValidatorTrust | None,
    rail: str,
) -> Check:
    if trust is None or not trust.validators:
        return no_data(
            CHECK_VALIDATOR_QUORUM,
            "no validator key set was pinned, so nothing says whose agreement would count",
        )
    entries = _validation_entries(proof)
    if not entries:
        return no_data(
            CHECK_VALIDATOR_QUORUM,
            "the capture carries no validation messages",
        )
    if ledger_hash is None:
        return no_data(
            CHECK_VALIDATOR_QUORUM,
            "there is no ledger hash for the validations to agree about",
        )
    if rail == RAIL_XRPL:
        return _xrpl_quorum_check(proof, ledger_hash, trust, entries)

    message_rule = VALIDATION_MESSAGE_RULES.get(rail)
    agreed: set[str] = set()
    unchecked: set[str] = set()
    disagreed: list[str] = []
    for entry in entries:
        name = _validator_id(entry)
        if name is None or name not in trust.validators:
            continue
        claimed = entry.get("ledger_hash")
        if not isinstance(claimed, str) or claimed.lower() != ledger_hash.lower():
            disagreed.append(name)
            continue
        key = trust.validators[name]
        signature = entry.get("signature")
        index = entry.get("ledger_index")
        if (
            message_rule is None
            or not key
            or not isinstance(signature, str)
            or not isinstance(index, int)
        ):
            unchecked.add(name)
            continue
        try:
            valid = ed25519_verify(key, signature, message_rule(claimed, index))
        except (CryptoError, ValueError):
            valid = False
        if valid:
            agreed.add(name)
        else:
            disagreed.append(name)

    total = len(trust.validators)
    if disagreed:
        return Check(
            CHECK_VALIDATOR_QUORUM,
            CheckStatus.FAIL,
            f"{len(disagreed)} pinned validator(s) did not sign {ledger_hash}: "
            f"{', '.join(sorted(set(disagreed))[:4])}",
        )
    if unchecked:
        return no_data(
            CHECK_VALIDATOR_QUORUM,
            f"{len(unchecked)} of {total} pinned validators named this ledger, but the capture "
            f"carries no signature this verifier can check — agreement counted, not proved",
        )
    return outcome(
        CHECK_VALIDATOR_QUORUM,
        len(agreed) >= trust.quorum,
        f"{len(agreed)} of {total} pinned validators signed ledger {ledger_hash}, "
        f"quorum is {trust.quorum}",
    )


def _fake_tx_path_root(tx_hash: str, path: Mapping[str, Any]) -> str | None:
    """Fold a transaction id up the fake rail's toy binary tree. None when malformed."""
    siblings = path.get("siblings")
    directions = path.get("directions")
    if not isinstance(siblings, list) or not isinstance(directions, list):
        return None
    if len(siblings) != len(directions):
        return None
    try:
        current = bytes.fromhex(tx_hash)
    except ValueError:
        return None
    if len(current) != 32:
        return None
    for sibling, direction in zip(siblings, directions, strict=True):
        if not isinstance(sibling, str) or direction not in ("left", "right"):
            return None
        try:
            other = bytes.fromhex(sibling)
        except ValueError:
            return None
        if len(other) != 32:
            return None
        pair = current + other if direction == "right" else other + current
        current = hashlib.sha256(pair).digest()
    return current.hex()


def _xrpl_tx_path_root(tx_hash: str, path: Mapping[str, Any]) -> str | None:
    """Fold a transaction up XRPL's real 16-ary SHAMap. None when malformed.

    Unlike the fake rail's path, this recomputes the leaf itself from the
    transaction's own raw ``tx_blob``/``tx_meta`` (both carried inside ``path``,
    since they are what the leaf hash is *of*) rather than starting from a hash
    the proof merely hands over — see
    :func:`merkl.core.verify.xrpl.fold_tx_path`.
    """
    tx_blob = path.get("tx_blob")
    tx_meta = path.get("tx_meta")
    steps = path.get("steps")
    if not isinstance(tx_blob, str) or not isinstance(tx_meta, str) or not isinstance(steps, list):
        return None
    return fold_tx_path(tx_hash, tx_blob, tx_meta, steps)


TX_PATH_ROOT_RULES: Final[dict[str, Any]] = {
    RAIL_FAKE: _fake_tx_path_root,
    RAIL_XRPL: _xrpl_tx_path_root,
}
"""Rails whose transaction-set path this verifier can fold back to a root."""


def read_settlement_proof(
    proof: JSONValue,
    *,
    rail: str,
    tx_hash: str,
    ledger_index: int | None,
    trust: ValidatorTrust | None = None,
    live: bool = False,
) -> SettlementProofReading:
    """Read a settlement proof and say exactly how far it gets.

    ``live`` is the caller's assertion that it queried the rail itself and saw
    this transaction validated. It produces ``verified-live``, which is weaker
    than ``proven-offline`` on purpose: it trusts whoever answered the query.
    Nothing in a receipt can set it.
    """
    if not isinstance(proof, Mapping):
        state = LEDGER_VERIFIED_LIVE if live else LEDGER_UNCHECKED
        detail = (
            "a live rail query reported this transaction validated"
            if live
            else "no settlement proof was supplied with this receipt"
        )
        return SettlementProofReading(
            checks=(
                no_data(CHECK_PROOF_MATCHES, "no settlement proof was supplied"),
                no_data(CHECK_LEDGER_HEADER, "no settlement proof was supplied"),
                no_data(CHECK_VALIDATOR_QUORUM, "no settlement proof was supplied"),
            ),
            ledger_inclusion=state,
            detail=detail,
        )

    match = _match_check(proof, rail=rail, tx_hash=tx_hash, ledger_index=ledger_index)
    header, ledger_hash = _header_check(proof, rail)
    quorum = _quorum_check(proof, ledger_hash, trust, rail)
    checks = (match, header, quorum)

    missing = _member(proof, "missing")
    missing_names = [m for m in missing if isinstance(m, str)] if isinstance(missing, list) else []

    path = _member(proof, "tx_path")
    header_map = _member(proof, "ledger_header")
    tx_root = None
    if isinstance(header_map, Mapping):
        candidate = header_map.get("transaction_hash")
        tx_root = candidate if isinstance(candidate, str) else None
    path_ok = False
    path_detail = "the proof carries no path from this transaction to the ledger's transaction set"
    if isinstance(path, Mapping) and tx_root is not None:
        path_rule = TX_PATH_ROOT_RULES.get(rail)
        derived = path_rule(tx_hash, path) if path_rule is not None else None
        path_ok = derived is not None and derived.lower() == tx_root.lower()
        path_detail = (
            f"the transaction folds to the header's transaction root {tx_root.lower()}"
            if path_ok
            else f"the supplied path folds to {derived}, the header names {tx_root.lower()}"
        )

    if match.status is CheckStatus.FAIL:
        return SettlementProofReading(
            checks=checks,
            ledger_inclusion=LEDGER_SUPPLIED_UNVERIFIED,
            detail=match.detail,
        )
    if (
        path_ok
        and header.status is CheckStatus.PASS
        and quorum.status is CheckStatus.PASS
        and "shamap_path" not in missing_names
    ):
        return SettlementProofReading(
            checks=checks,
            ledger_inclusion=LEDGER_PROVEN_OFFLINE,
            detail=f"{quorum.detail}; {path_detail}",
        )
    if live:
        return SettlementProofReading(
            checks=checks,
            ledger_inclusion=LEDGER_VERIFIED_LIVE,
            detail="a live rail query reported this transaction validated",
        )
    gaps = ", ".join(missing_names) if missing_names else path_detail
    return SettlementProofReading(
        checks=checks,
        ledger_inclusion=LEDGER_SUPPLIED_UNVERIFIED,
        detail=f"the capture does not prove inclusion offline; missing: {gaps}",
    )
