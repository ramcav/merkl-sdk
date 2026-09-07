"""Build the proof-bundle cases both verifiers must agree on.

Unlike the receipt vectors, the bundles here are not synthesized: they are real
exports from merkl-api's own test container, committed verbatim. That is the
point. A fixture the SDK generated would only prove the SDK agrees with itself;
these prove that ``merkl.core.verify.log`` and ``merkl-verify.js`` read what the
server actually writes, including the fields (``drift_score_str``, the exact
``timestamp`` string) where a re-rendered value silently disagrees.

Each case is one bundle plus the check statuses a conforming verifier reports.
The tamper cases are mutations applied here rather than committed as whole
bundles, so the diff shows what changed and the expectation cannot drift away
from the mutation it describes.

Regenerate with ``python -m merkl.core.vectors.bundles.generate``; ``--check``
fails when the committed ``cases.json`` is stale.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections.abc import Callable
from typing import Any, Final

from merkl.core.verify.log import verify_log_bundle

BUNDLES_DIR: Final = pathlib.Path(__file__).parent
CASES_FILE: Final = "cases.json"

SOURCES: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "session-v1.1",
        "session-v1.1.json",
        "A sealed five-action session exported at bundle v1.1: action leaves, "
        "inclusion proofs, the audit entry, the RFC 6962 log proof and the signed "
        "checkpoint. No continuation, so that check reports not_implemented.",
    ),
    (
        "continuation-v1.1",
        "continuation-v1.1.json",
        "A successor session whose leaf 0 is the binding to the parent it "
        "continued. Every check has inputs, so this bundle is the one that reports "
        "complete.",
    ),
    (
        "receipts-v1.2",
        "receipts-v1.2.json",
        "Bundle v1.2: the same session shape plus a receipts[] entry whose envelope "
        "hash is the transaction action's input_hash. The log checks are unchanged "
        "by the addition, which is what 'additive' has to mean.",
    ),
)


def _flip_last_hex(value: str) -> str:
    """One nibble of one hash, which is all it takes."""
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def _tamper_action_timestamp(bundle: dict[str, Any]) -> None:
    bundle["actions"][0]["timestamp"] = "2099-01-01T00:00:00+00:00"


def _tamper_action_leaf(bundle: dict[str, Any]) -> None:
    bundle["actions"][0]["leaf_hash"] = _flip_last_hex(bundle["actions"][0]["leaf_hash"])


def _tamper_proof_sibling(bundle: dict[str, Any]) -> None:
    proof = bundle["actions"][0]["proof"]
    if proof["siblings"]:
        proof["siblings"][0] = _flip_last_hex(proof["siblings"][0])
    else:  # a one-action session proves the leaf against itself
        proof["root"] = _flip_last_hex(proof["root"])


def _tamper_audit_sequence(bundle: dict[str, Any]) -> None:
    bundle["audit_log"]["sequence"] = int(bundle["audit_log"]["sequence"]) + 1


def _tamper_checkpoint_signature(bundle: dict[str, Any]) -> None:
    cp = bundle["transparency"]["checkpoint"]
    cp["signature"] = _flip_last_hex(cp["signature"])


def _tamper_checkpoint_body(bundle: dict[str, Any]) -> None:
    cp = bundle["transparency"]["checkpoint"]
    cp["tree_size"] = int(cp["tree_size"]) + 1


def _tamper_log_path(bundle: dict[str, Any]) -> None:
    inclusion = bundle["transparency"]["log_inclusion"]
    if inclusion["path"]:
        inclusion["path"][0] = _flip_last_hex(inclusion["path"][0])
    else:
        inclusion["root_hash"] = _flip_last_hex(inclusion["root_hash"])


def _tamper_binding_reason(bundle: dict[str, Any]) -> None:
    bundle["continuation"]["reason"] = "force_seal_but_not_really"


def _tamper_session_root(bundle: dict[str, Any]) -> None:
    bundle["session"]["root_hash"] = _flip_last_hex(bundle["session"]["root_hash"])


TAMPERS: Final[tuple[tuple[str, str, str, Callable[[dict[str, Any]], None], list[str]], ...]] = (
    (
        "action-timestamp-edited",
        "session-v1.1.json",
        "One action's timestamp was changed after the fact. The leaf no longer "
        "recomputes, so the action check fails even though every hash in the "
        "bundle is internally consistent with itself.",
        _tamper_action_timestamp,
        ["log.actions"],
    ),
    (
        "action-leaf-hash-swapped",
        "session-v1.1.json",
        "The committed leaf hash was replaced. Both the recompute and the "
        "inclusion proof land elsewhere.",
        _tamper_action_leaf,
        ["log.actions"],
    ),
    (
        "inclusion-proof-sibling-edited",
        "session-v1.1.json",
        "A sibling in the Merkle path was altered: the leaf is genuine, the path "
        "to the root is not.",
        _tamper_proof_sibling,
        ["log.actions"],
    ),
    (
        "audit-entry-resequenced",
        "session-v1.1.json",
        "The entry's position in the hash chain was changed, which changes its "
        "hash and breaks the chain that follows it.",
        _tamper_audit_sequence,
        ["log.audit_entry"],
    ),
    (
        "checkpoint-signature-forged",
        "session-v1.1.json",
        "The checkpoint signature was edited. The body still claims the right "
        "root, so only the signature check catches it.",
        _tamper_checkpoint_signature,
        ["log.checkpoint_signature"],
    ),
    (
        "checkpoint-body-disagrees",
        "session-v1.1.json",
        "The bundle claims a tree size the signed note does not. A real signature "
        "over a different statement is the subtle version of no signature at all.",
        _tamper_checkpoint_body,
        ["log.checkpoint_body"],
    ),
    (
        "log-inclusion-path-edited",
        "session-v1.1.json",
        "The RFC 6962 path no longer folds to the checkpoint's root.",
        _tamper_log_path,
        ["log.inclusion"],
    ),
    (
        "session-root-restated",
        "session-v1.1.json",
        "Every action proof still folds, but to a root the session no longer "
        "claims. The actions look healthy; the session does not.",
        _tamper_session_root,
        ["log.session_root"],
    ),
    (
        "continuation-reason-edited",
        "continuation-v1.1.json",
        "The reason a session was sealed is inside the binding leaf, so rewriting "
        "it breaks the link to the parent.",
        _tamper_binding_reason,
        ["log.continuation"],
    ),
)


def _statuses(bundle: dict[str, Any]) -> dict[str, str]:
    verdict = verify_log_bundle(bundle)
    return {c.name: c.status.value for c in verdict.result.checks}


def build() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for name, file, description in SOURCES:
        bundle = json.loads((BUNDLES_DIR / file).read_text())
        verdict = verify_log_bundle(bundle)
        cases.append(
            {
                "name": name,
                "file": file,
                "description": description,
                "tamper": None,
                "checks": _statuses(bundle),
                "actions": [a.to_content() for a in verdict.actions],
                "ok": verdict.ok,
                "complete": verdict.complete,
            }
        )
    for name, file, description, mutate, must_fail in TAMPERS:
        bundle = json.loads((BUNDLES_DIR / file).read_text())
        mutate(bundle)
        statuses = _statuses(bundle)
        failed = sorted(n for n, s in statuses.items() if s == "fail")
        if failed != sorted(must_fail):
            raise SystemExit(
                f"tamper case {name!r} declares {sorted(must_fail)} but the verifier "
                f"reports {failed}"
            )
        cases.append(
            {
                "name": name,
                "file": file,
                "description": description,
                "tamper": name,
                "bundle": bundle,
                "checks": statuses,
                "fails": failed,
                "ok": False,
                "complete": verify_log_bundle(bundle).complete,
            }
        )
    return {
        "description": (
            "Proof bundles exported by merkl-api, and mutations of them that must "
            "fail. Both verifiers report the same check names with the same "
            "statuses; a tamper case names every check that must read 'fail'."
        ),
        "spec": "merkl-api/docs/SPEC.md sections 2-9",
        "generator": "python -m merkl.core.vectors.bundles.generate",
        "cases": cases,
    }


def _serialize(content: dict[str, Any]) -> str:
    return json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    body = _serialize(build())
    path = BUNDLES_DIR / CASES_FILE
    if "--check" in argv:
        if not path.exists() or path.read_text() != body:
            print(f"{path} is stale; run python -m merkl.core.vectors.bundles.generate")
            return 1
        print(f"{path} is current")
        return 0
    path.write_text(body)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main(sys.argv[1:]))
