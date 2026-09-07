"""Session, transparency log and evidence verification, in Python.

Everything a proof bundle claims, recomputed from the bundle itself: the action
leaves, their inclusion in the session root, the audit-log entry that seals that
root, the RFC 6962 proof that puts the entry in Merkl's log, the signed
checkpoint over that log, the continuation binding when a session succeeded
another, and — when the operator disclosed one — the evidence records whose raw
payloads must re-hash to the committed leaf fields.

Until this phase these checks existed only in JavaScript, inside a page merkl-api
rendered. That is one implementation of a normative format, and it lived in the
wrong repository. This is the second implementation the plan requires (D7), and
``merkl/core/verify/js/merkl-verify.js`` is the same algorithms again over the
same fixtures, so a divergence between them is a bug in one, never a difference.

The encodings are frozen (``merkl-api/docs/SPEC.md`` sections 2-8): the domain
tags ``merkl-leaf-v1``, ``merkl-binding-v1`` and ``merkl-entry-v1`` are not ours
to change. Two fields are worth restating because a non-Python verifier gets them
wrong: ``drift_score`` is Python's ``str()`` of the float, and ``timestamp`` is
the exact ISO 8601 string that was transmitted. Both are taken verbatim from the
record and never re-rendered.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.checks import Check, CheckStatus, VerificationResult, no_data, outcome
from merkl.core.crypto import CryptoError, ed25519_verify
from merkl.core.leaf import action_leaf
from merkl.core.merkle import MerkleProof
from merkl.shared.hashing import SHA256Hash, canonical_hash

__all__ = [
    "ActionReading",
    "CHECK_ACTIONS",
    "CHECK_AUDIT_ENTRY",
    "CHECK_CHECKPOINT_BODY",
    "CHECK_CHECKPOINT_SIGNATURE",
    "CHECK_CONTINUATION",
    "CHECK_EVIDENCE",
    "CHECK_LOG_INCLUSION",
    "CHECK_SESSION_ROOT",
    "EvidenceReading",
    "LogVerdict",
    "audit_entry_hash",
    "binding_leaf_hash",
    "checkpoint_body_matches",
    "continuation_reading",
    "evidence_records",
    "leaf_hash_of",
    "leaf_index_of",
    "rfc6962_leaf",
    "verify_evidence",
    "verify_log_bundle",
    "verify_log_inclusion",
]


# --------------------------------------------------------------------------- #
# Domain tags and check names
# --------------------------------------------------------------------------- #


BINDING_TAG: Final = b"merkl-binding-v1"
ENTRY_TAG: Final = b"merkl-entry-v1"
_NUL: Final = b"\x00"

CHECK_ACTIONS: Final = "log.actions"
CHECK_SESSION_ROOT: Final = "log.session_root"
CHECK_CONTINUATION: Final = "log.continuation"
CHECK_AUDIT_ENTRY: Final = "log.audit_entry"
CHECK_LOG_INCLUSION: Final = "log.inclusion"
CHECK_CHECKPOINT_BODY: Final = "log.checkpoint_body"
CHECK_CHECKPOINT_SIGNATURE: Final = "log.checkpoint_signature"
CHECK_EVIDENCE: Final = "log.evidence"

LOG_CHECKS: Final[tuple[str, ...]] = (
    CHECK_ACTIONS,
    CHECK_SESSION_ROOT,
    CHECK_CONTINUATION,
    CHECK_AUDIT_ENTRY,
    CHECK_LOG_INCLUSION,
    CHECK_CHECKPOINT_BODY,
    CHECK_CHECKPOINT_SIGNATURE,
)


def _u8be(value: Any) -> bytes:
    return int(value).to_bytes(8, "big")


def _uuid_bytes(value: str) -> bytes:
    raw = bytes.fromhex(value.replace("-", ""))
    if len(raw) != 16:
        raise ValueError("a workspace id is 16 bytes")
    return raw


# --------------------------------------------------------------------------- #
# Action leaves and session inclusion
# --------------------------------------------------------------------------- #


def leaf_hash_of(action: Mapping[str, Any]) -> str:
    """Recompute one action's ``merkl-leaf-v1`` hash from a bundle row.

    ``drift_score_str`` wins over ``drift_score`` when the bundle carries it: JSON
    number parsing loses the exact ``str()`` rendering the server hashed, and a
    verifier that re-renders it disagrees with the leaf while looking healthy.
    """
    drift = action.get("drift_score_str")
    if drift is None:
        drift = str(action.get("drift_score", 0.0))
    depends = action.get("depends_on") or []
    return action_leaf(
        action_id=str(action.get("action_id", "")),
        session_id=str(action.get("session_id", "")),
        action_type=str(action.get("action_type", "")),
        tool_name=str(action.get("tool_name", "")),
        input_hash=str(action.get("input_hash", "")),
        output_hash=str(action.get("output_hash", "")),
        timestamp=str(action.get("timestamp", "")),
        drift_score=str(drift),
        guardrail_result=str(action.get("guardrail_result", "")),
        display_name=str(action.get("display_name") or ""),
        depends_on=[str(d) for d in depends],
        status=str(action.get("status") or "success"),
        category=str(action.get("category") or ""),
    ).hex()


@dataclasses.dataclass(frozen=True)
class ActionReading:
    """One action row: does it hash to its leaf, and does its proof reach the root."""

    index: int
    action_id: str
    tool_name: str
    computed_leaf: str
    committed_leaf: str
    leaf_matches: bool
    proof_ok: bool
    derived_root: str
    receipt_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.leaf_matches and self.proof_ok

    def to_content(self) -> JSONObject:
        return {
            "index": self.index,
            "action_id": self.action_id,
            "tool_name": self.tool_name,
            "computed_leaf": self.computed_leaf,
            "committed_leaf": self.committed_leaf,
            "leaf_matches": self.leaf_matches,
            "proof_ok": self.proof_ok,
            "derived_root": self.derived_root,
            "receipt_id": self.receipt_id,
            "ok": self.ok,
        }


def leaf_index_of(position: int, action: Mapping[str, Any]) -> int:
    """Which leaf of the session tree this row is, not merely where it is listed.

    A full session export lists every action in leaf order, so the two are the
    same number and always were. A *scoped* bundle — one receipt and only the
    action that committed it (``docs/SPEC.md`` §9) — lists one row that is leaf
    5 of twelve, and reading its position would place it at leaf 0. The row's
    own proof already says which leaf it is; that is the answer, and the
    position is only the fallback for a bundle whose proof is missing.
    """
    proof = action.get("proof")
    if isinstance(proof, Mapping):
        declared = proof.get("leaf_index")
        if isinstance(declared, int) and not isinstance(declared, bool) and declared >= 0:
            return declared
    return position


def _read_action(index: int, action: Mapping[str, Any], root: str) -> ActionReading:
    try:
        computed = leaf_hash_of(action)
    except Exception:  # noqa: BLE001 - a row that will not hash is a failed check
        computed = ""
    committed = str(action.get("leaf_hash", ""))
    proof_raw = action.get("proof")
    derived = ""
    proof_ok = False
    if isinstance(proof_raw, Mapping) and committed:
        try:
            proof = MerkleProof.from_dict(dict(proof_raw))
            derived = proof.derive_root(SHA256Hash(bytes.fromhex(committed))).hex()
            proof_ok = derived == str(proof_raw.get("root", root))
        except (ValueError, KeyError, TypeError):
            proof_ok = False
    return ActionReading(
        index=index,
        action_id=str(action.get("action_id", "")),
        tool_name=str(action.get("tool_name", "")),
        computed_leaf=computed,
        committed_leaf=committed,
        leaf_matches=bool(computed) and computed == committed,
        proof_ok=proof_ok,
        derived_root=derived,
        receipt_id=action.get("receipt_id"),
    )


# --------------------------------------------------------------------------- #
# Continuation binding
# --------------------------------------------------------------------------- #


def binding_leaf_hash(parent_session_id: str, parent_root: str, reason: str) -> str:
    """``SHA-256("merkl-binding-v1" ‖ NUL ‖ parent_id ‖ parent_root ‖ reason)``."""
    return hashlib.sha256(
        BINDING_TAG
        + _NUL
        + parent_session_id.encode()
        + bytes.fromhex(parent_root)
        + reason.encode()
    ).hexdigest()


def continuation_reading(continuation: Mapping[str, Any]) -> Check:
    """Leaf 0 of a successor session must be the binding to its parent."""
    try:
        computed = binding_leaf_hash(
            str(continuation["parent_session_id"]),
            str(continuation["parent_root"]),
            str(continuation["reason"]),
        )
    except (KeyError, ValueError) as exc:
        return Check(CHECK_CONTINUATION, CheckStatus.FAIL, f"the binding does not hash: {exc}")
    committed = str(continuation.get("binding_leaf_hash", ""))
    if computed != committed:
        return Check(
            CHECK_CONTINUATION,
            CheckStatus.FAIL,
            f"the binding recomputes to {computed}, the bundle commits {committed}",
        )
    proof_raw = continuation.get("proof")
    if not isinstance(proof_raw, Mapping):
        return no_data(CHECK_CONTINUATION, "the bundle carries no proof for the binding leaf")
    try:
        proof = MerkleProof.from_dict(dict(proof_raw))
        derived = proof.derive_root(SHA256Hash(bytes.fromhex(committed))).hex()
    except (ValueError, KeyError, TypeError) as exc:
        return Check(
            CHECK_CONTINUATION, CheckStatus.FAIL, f"the binding proof is malformed: {exc}"
        )
    root = str(proof_raw.get("root", ""))
    return outcome(
        CHECK_CONTINUATION,
        derived == root,
        f"the binding leaf folds to {derived}, the successor root is {root}",
    )


# --------------------------------------------------------------------------- #
# Audit log entry
# --------------------------------------------------------------------------- #


def audit_entry_hash(entry: Mapping[str, Any]) -> str:
    """The audit-log entry hash.

    ``SHA-256("merkl-entry-v1" ‖ NUL ‖ workspace_id ‖ session_id ‖ session_root ‖
    leaf_count ‖ sealed_at_iso ‖ sequence ‖ prev_log_hash)``

    ``leaf_count`` and ``sequence`` are eight-byte big-endian; ``sealed_at_iso``
    is the exact string the server sealed with. Every hash member is raw bytes,
    not hex.
    """
    return hashlib.sha256(
        b"".join(
            (
                ENTRY_TAG,
                _NUL,
                _uuid_bytes(str(entry["workspace_id"])),
                str(entry["session_id"]).encode(),
                bytes.fromhex(str(entry["session_root"])),
                _u8be(entry["leaf_count"]),
                str(entry["sealed_at_iso"]).encode(),
                _u8be(entry["sequence"]),
                bytes.fromhex(str(entry["prev_log_hash"])),
            )
        )
    ).hexdigest()


def _audit_check(entry: Mapping[str, Any]) -> Check:
    try:
        computed = audit_entry_hash(entry)
    except (KeyError, ValueError, TypeError) as exc:
        return Check(CHECK_AUDIT_ENTRY, CheckStatus.FAIL, f"the entry does not hash: {exc}")
    committed = str(entry.get("current_hash", ""))
    return outcome(
        CHECK_AUDIT_ENTRY,
        computed == committed,
        f"the entry recomputes to {computed}, the bundle records {committed}",
    )


# --------------------------------------------------------------------------- #
# RFC 6962 log tree
# --------------------------------------------------------------------------- #


def rfc6962_leaf(entry_hash: str) -> bytes:
    """``SHA-256(0x00 ‖ entry_hash)`` — the log-tree leaf for one audit entry."""
    return hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).digest()


def _rfc6962_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_log_inclusion(inclusion: Mapping[str, Any]) -> tuple[bool, str]:
    """RFC 9162 section 2.1.3.2 inclusion verification. Returns (ok, detail)."""
    try:
        leaf = rfc6962_leaf(str(inclusion["entry_hash"]))
        if leaf.hex() != str(inclusion["leaf_hash"]):
            return False, "the log leaf is not SHA-256(0x00 || entry_hash)"
        fn = int(inclusion["sequence"])
        sn = int(inclusion["tree_size"]) - 1
        path = list(inclusion["path"])
    except (KeyError, ValueError, TypeError) as exc:
        return False, f"the inclusion proof is malformed: {exc}"
    if fn < 0 or fn > sn:
        return False, f"sequence {fn} is outside a tree of size {sn + 1}"
    node = leaf
    for sibling_hex in path:
        if sn == 0:
            return False, "the path is longer than the tree is deep"
        try:
            sibling = bytes.fromhex(str(sibling_hex))
        except ValueError:
            return False, "a path element is not hex"
        if fn % 2 == 1 or fn == sn:
            node = _rfc6962_node(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            node = _rfc6962_node(node, sibling)
        fn //= 2
        sn //= 2
    if sn != 0:
        return False, "the path ended before the root"
    root = str(inclusion.get("root_hash", ""))
    return node.hex() == root, f"the entry folds to {node.hex()}, the log root is {root}"


# --------------------------------------------------------------------------- #
# Signed checkpoint
# --------------------------------------------------------------------------- #


def checkpoint_body_matches(checkpoint: Mapping[str, Any]) -> tuple[bool, str]:
    """The signed note must claim the tree size and root the bundle states.

    A signature over a body that says something else is a valid signature over a
    different statement, which is the subtle version of no signature at all.
    """
    body = checkpoint.get("body")
    if not isinstance(body, str):
        return False, "the checkpoint carries no body"
    lines = body.split("\n")
    if len(lines) < 3:
        return False, "the signed note has fewer than three lines"
    if lines[0] != str(checkpoint.get("origin", "")):
        return False, f"the body's origin is {lines[0]!r}"
    if lines[1] != str(checkpoint.get("tree_size", "")):
        return False, f"the body's tree size is {lines[1]!r}"
    try:
        root = base64.b64decode(lines[2], validate=True).hex()
    except (ValueError, TypeError):
        return False, "the body's root is not base64"
    claimed = str(checkpoint.get("root_hash", ""))
    return root == claimed, f"the body claims root {root}, the bundle states {claimed}"


def _checkpoint_signature_check(checkpoint: Mapping[str, Any]) -> Check:
    body = checkpoint.get("body")
    key = checkpoint.get("public_key")
    signature = checkpoint.get("signature")
    if not isinstance(body, str) or not isinstance(key, str) or not isinstance(signature, str):
        return no_data(
            CHECK_CHECKPOINT_SIGNATURE, "the checkpoint carries no body, key or signature"
        )
    try:
        ok = ed25519_verify(key, signature, body.encode())
    except CryptoError as exc:
        return Check(CHECK_CHECKPOINT_SIGNATURE, CheckStatus.FAIL, str(exc))
    return outcome(
        CHECK_CHECKPOINT_SIGNATURE,
        ok,
        f"key {key[:16]}… {'signed' if ok else 'did not sign'} this checkpoint body",
    )


# --------------------------------------------------------------------------- #
# Evidence records
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class EvidenceReading:
    """One disclosed record held against the leaf the bundle committed."""

    action_id: str
    label: str
    verdict: str
    detail: str
    index: int | None = None

    def to_content(self) -> JSONObject:
        return {
            "action_id": self.action_id,
            "label": self.label,
            "verdict": self.verdict,
            "detail": self.detail,
            "index": self.index,
        }


def evidence_records(text: str) -> list[JSONValue]:
    """Parse a JSONL evidence file, skipping blank lines. Bad lines become ``None``."""
    records: list[JSONValue] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append(None)
    return records


def verify_evidence(
    records: Iterable[JSONValue], actions: Sequence[Mapping[str, Any]]
) -> tuple[EvidenceReading, ...]:
    """Re-hash each disclosed record's raw input and output against its leaf.

    The notary stores hashes, so this is the step that turns a hash back into a
    document: a record that matches is byte-identical to what ran, and one that
    does not was altered or fabricated. Records for actions outside this bundle
    are reported as unknown rather than as failures — they are not evidence about
    anything here.
    """
    by_id = {str(a.get("action_id", "")): (i, a) for i, a in enumerate(actions)}
    readings: list[EvidenceReading] = []
    for record in records:
        if not isinstance(record, Mapping):
            readings.append(EvidenceReading("", "(unparseable line)", "bad", "not valid JSON"))
            continue
        action_id = str(record.get("action_id", ""))
        hit = by_id.get(action_id)
        if hit is None:
            readings.append(
                EvidenceReading(
                    action_id,
                    action_id or "(no action_id)",
                    "unknown",
                    "no such action in this bundle",
                )
            )
            continue
        index, action = hit
        input_ok = canonical_hash(record.get("input")).hex() == str(action.get("input_hash", ""))
        output_ok = canonical_hash(record.get("output")).hex() == str(
            action.get("output_hash", "")
        )
        label = f"{action.get('tool_name', '?')} · {action_id[:8]}"
        if input_ok and output_ok:
            readings.append(
                EvidenceReading(
                    action_id, label, "ok", "input and output match the committed hashes", index
                )
            )
        else:
            detail = " ".join(
                part
                for part in (
                    "" if input_ok else "INPUT hash mismatch — record altered or fabricated.",
                    "" if output_ok else "OUTPUT hash mismatch — record altered or fabricated.",
                )
                if part
            )
            readings.append(EvidenceReading(action_id, label, "bad", detail, index))
    return tuple(readings)


# --------------------------------------------------------------------------- #
# The whole bundle
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class LogVerdict:
    """Every log-level check, plus the per-action detail a page renders."""

    result: VerificationResult
    actions: tuple[ActionReading, ...]
    evidence: tuple[EvidenceReading, ...] = ()

    @property
    def ok(self) -> bool:
        return self.result.ok

    @property
    def complete(self) -> bool:
        return self.result.complete

    def to_content(self) -> JSONObject:
        return {
            **self.result.to_content(),
            "actions": [a.to_content() for a in self.actions],
            "evidence": [e.to_content() for e in self.evidence],
        }


def verify_log_bundle(
    bundle: Mapping[str, Any], *, evidence: Iterable[JSONValue] = ()
) -> LogVerdict:
    """Verify a v1.1 or v1.2 proof bundle's session, log and checkpoint claims.

    A bundle that carries no transparency block is not failing — it is a level-1
    export, and the checks that need a log report ``not_implemented`` by name.
    That is plan D9 in one function: joining the log adds completeness, and its
    absence is stated rather than hidden.
    """
    session = bundle.get("session") if isinstance(bundle.get("session"), Mapping) else {}
    root = str(session.get("root_hash", "")) if session else ""
    raw_actions = bundle.get("actions")
    actions = (
        [a for a in raw_actions if isinstance(a, Mapping)] if isinstance(raw_actions, list) else []
    )

    readings = tuple(_read_action(leaf_index_of(i, a), a, root) for i, a in enumerate(actions))
    checks: list[Check] = []
    if not actions:
        checks.append(no_data(CHECK_ACTIONS, "this bundle carries no actions"))
    else:
        good = sum(1 for r in readings if r.ok)
        checks.append(
            outcome(
                CHECK_ACTIONS,
                good == len(readings),
                f"{good} of {len(readings)} actions rehash to their leaf and prove into the root",
            )
        )

    if not root:
        checks.append(no_data(CHECK_SESSION_ROOT, "the bundle states no session root"))
    else:
        roots = {r.derived_root for r in readings if r.proof_ok}
        checks.append(
            outcome(
                CHECK_SESSION_ROOT,
                bool(roots) and roots == {root},
                f"every verified proof lands on {root}"
                if roots == {root}
                else f"proofs land on {sorted(roots)}, the session states {root}",
            )
        )

    continuation = bundle.get("continuation")
    if isinstance(continuation, Mapping):
        checks.append(continuation_reading(continuation))
    else:
        checks.append(no_data(CHECK_CONTINUATION, "this session did not continue another one"))

    audit = bundle.get("audit_log")
    if isinstance(audit, Mapping):
        checks.append(_audit_check(audit))
    else:
        checks.append(no_data(CHECK_AUDIT_ENTRY, "this bundle carries no audit-log entry"))

    transparency = bundle.get("transparency")
    transparency = transparency if isinstance(transparency, Mapping) else {}
    inclusion = transparency.get("log_inclusion")
    if isinstance(inclusion, Mapping):
        ok, detail = verify_log_inclusion(inclusion)
        checks.append(outcome(CHECK_LOG_INCLUSION, ok, detail))
    else:
        checks.append(no_data(CHECK_LOG_INCLUSION, "this bundle carries no log inclusion proof"))

    checkpoint = transparency.get("checkpoint")
    if isinstance(checkpoint, Mapping):
        body_ok, body_detail = checkpoint_body_matches(checkpoint)
        checks.append(outcome(CHECK_CHECKPOINT_BODY, body_ok, body_detail))
        checks.append(_checkpoint_signature_check(checkpoint))
    else:
        checks.append(no_data(CHECK_CHECKPOINT_BODY, "this bundle carries no checkpoint"))
        checks.append(no_data(CHECK_CHECKPOINT_SIGNATURE, "this bundle carries no checkpoint"))

    evidence_readings = verify_evidence(evidence, actions)
    if evidence_readings:
        bad = sum(1 for e in evidence_readings if e.verdict == "bad")
        good = sum(1 for e in evidence_readings if e.verdict == "ok")
        checks.append(
            outcome(
                CHECK_EVIDENCE,
                bad == 0 and good > 0,
                f"{good} record(s) match their committed hashes, {bad} do not",
            )
        )

    return LogVerdict(
        result=VerificationResult(tuple(checks)),
        actions=readings,
        evidence=evidence_readings,
    )
