"""``merkl disclose`` — package what an auditor needs, and nothing else.

The operator side of the disclosure flow. Produces a folder to zip and send; the
auditor needs no tooling, no account and no network — they open verify.html in a
browser and drop evidence.jsonl on it.

Two things changed in phase 4. The page is now **rendered here** rather than
downloaded from the notary (plan D7), so a disclosure can be produced with the
notary offline, or with no notary at all. And ``--leaves`` makes the disclosure
selective at the receipt level as well as the session level: reveal the
instruction and the policy decision, withhold the amount, and the page still
proves the revealed leaves belong to that receipt and were not edited.

Selective by construction in both directions: undisclosed actions appear as
hashes and typed metadata, undisclosed leaves appear as hashes only, and neither
raw payload ever leaves the operator's machine.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

__all__ = ["build_disclosure_bundle", "disclose", "find_evidence_entry", "find_receipt"]


def find_evidence_entry(evidence_dir: Path, action_id: str) -> tuple[dict[str, Any], str] | None:
    """Scan the evidence dir for an entry with this action_id.

    Returns ``(entry, raw_line)`` so the disclosed line is byte-identical to what
    the hook wrote — re-serializing could change key order and confuse a diff,
    even though hashing is order-independent.
    """
    for path in sorted(evidence_dir.glob("*.jsonl")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if action_id not in line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("action_id") == action_id:
                    return entry, line.rstrip("\n")
    return None


def find_receipt(store: Path, action_id: str) -> dict[str, Any] | None:
    """The locally stored receipt whose session action is this one, if there is one."""
    if not store.is_dir():
        return None
    for path in sorted(store.glob("*.json")):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if receipt.get("action_id") == action_id:
            return dict(receipt)
    return None


def _disclosure_of(receipt: dict[str, Any], names: list[str]) -> dict[str, Any]:
    """Build a selective disclosure of a receipt from its stored form."""
    from merkl.core.receipt import Envelope, ReceiptLeaves
    from merkl.core.receipt import disclose as disclose_leaves

    envelope = Envelope.from_content(receipt["envelope"])
    leaves = ReceiptLeaves.from_contents(receipt["leaves"])
    return disclose_leaves(envelope, leaves, names).to_content()


def _fetch_bundle(
    endpoint: str, api_key: str, session_id: str
) -> tuple[dict[str, Any] | None, str]:
    """The notary's level-2 bundle, or a sentence saying why there is none."""
    import httpx

    try:
        response = httpx.get(
            f"{endpoint.rstrip('/')}/v1/sessions/{session_id}/export",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        return None, f"the notary at {endpoint} could not be reached ({exc}); level 1 only"
    if response.status_code == 422:
        return None, f"session {session_id} is not sealed yet; level 1 only"
    if not response.is_success:
        return None, f"the notary answered {response.status_code}; level 1 only"
    return dict(response.json()), "level 2: the session log, checkpoint and anchor are included"


def build_disclosure_bundle(
    *,
    entry: dict[str, Any],
    receipt: dict[str, Any] | None,
    leaves: list[str] | None,
    session_bundle: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the bundle the page will verify.

    Starts from the notary's session bundle when one was fetched, so the auditor
    gets the log, the checkpoint and the anchor. Falls back to a receipt-only
    bundle, which is a complete level-1 disclosure and says so — a disclosure
    that needed the notary to be up would not be much of a disclosure.
    """
    bundle: dict[str, Any] = session_bundle or {
        "version": "1.2",
        "session": None,
        "actions": [],
        "receipts": [],
    }
    if receipt is not None:
        if leaves:
            bundle["disclosure"] = _disclosure_of(receipt, leaves)
        else:
            existing = bundle.get("receipts")
            bundle["receipts"] = list(existing) if isinstance(existing, list) else []
            known = {
                (r.get("envelope") or {}).get("receipt_id")
                for r in bundle["receipts"]
                if isinstance(r, dict)
            }
            if (receipt.get("envelope") or {}).get("receipt_id") not in known:
                bundle["receipts"].append(receipt)
    bundle.setdefault("disclosed_action_id", entry.get("action_id"))
    return bundle


def disclose(
    action_id: str,
    *,
    evidence_dir: Path | None = None,
    receipt_dir: Path | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
    out_dir: Path | None = None,
    leaves: list[str] | None = None,
) -> Path:
    """Build a disclosure folder for one action. Returns the folder path.

    Raises SystemExit with a readable message on any failure — this is a CLI
    entry point, not a library API.
    """
    from merkl.core.verify.render import render_verify_html

    evidence_dir = evidence_dir or Path(
        os.environ.get("MERKL_EVIDENCE_DIR") or Path.home() / ".merkl" / "evidence"
    )
    receipt_dir = receipt_dir or Path(
        os.environ.get("MERKL_RECEIPT_DIR") or Path.home() / ".merkl" / "receipts"
    )
    endpoint = endpoint or os.environ.get("MERKL_ENDPOINT")
    api_key = api_key or os.environ.get("MERKL_API_KEY", "")

    if not evidence_dir.is_dir():
        sys.exit(f"Evidence dir not found: {evidence_dir} (set MERKL_EVIDENCE_DIR)")

    found = find_evidence_entry(evidence_dir, action_id)
    if found is None:
        sys.exit(
            f"No evidence entry for action {action_id} under {evidence_dir}.\n"
            "Evidence is written by the Merkl hook on the machine the agent ran on."
        )
    entry, raw_line = found
    session_id = entry["session_id"]

    receipt = find_receipt(receipt_dir, action_id)
    if leaves and receipt is None:
        sys.exit(
            f"--leaves needs a receipt, and there is none for action {action_id} in "
            f"{receipt_dir}. Only a co-signed transaction has leaves to disclose."
        )

    session_bundle: dict[str, Any] | None = None
    note = "level 1: no notary configured, so this is the receipt and the local evidence"
    if endpoint:
        session_bundle, note = _fetch_bundle(endpoint, api_key, session_id)

    bundle = build_disclosure_bundle(
        entry=entry, receipt=receipt, leaves=leaves, session_bundle=session_bundle
    )

    out = out_dir or Path(f"disclosure-{action_id[:8]}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "verify.html").write_text(render_verify_html(bundle), encoding="utf-8")
    (out / "evidence.jsonl").write_text(raw_line + "\n", encoding="utf-8")
    (out / "bundle.json").write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "README.txt").write_text(
        "Merkl disclosure\n"
        "================\n\n"
        f"Action:   {action_id}\n"
        f"Session:  {session_id}\n"
        f"Scope:    {note}\n"
        + (f"Leaves:   {', '.join(leaves)} (the rest are hashes only)\n" if leaves else "")
        + "\n"
        "Open verify.html in any browser. It works offline; nothing in it calls home.\n"
        "Drop evidence.jsonl on the page to check the raw record against the hashes\n"
        "committed in the tree.\n\n"
        "Prefer a terminal? `pip install merkl-sdk && merkl verify verify.html` runs the\n"
        "same checks in a second implementation, and bundle.json is the raw data both\n"
        "of them read.\n",
        encoding="utf-8",
    )

    print(f"Disclosure package: {out}/")
    print(f"  verify.html     the verifier, with the proof embedded — {note}")
    print("  bundle.json     the same data, for `merkl verify` or your own tooling")
    print(f"  evidence.jsonl  1 record: {entry.get('tool_name', '?')} action {action_id[:8]}…")
    if leaves:
        print(f"  disclosed leaves: {', '.join(leaves)}; every other leaf is a hash only")
    print()
    print("Send the folder. The auditor needs no install, no network and no account.")
    return out
