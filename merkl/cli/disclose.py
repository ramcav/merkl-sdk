"""``merkl disclose`` — package one action's evidence for an auditor.

The operator side of the disclosure flow. Produces a folder the operator
can zip and email; the auditor needs no tooling — they open verify.html
in any browser and drop evidence.jsonl on it.

    merkl disclose <action_id>
    → disclosure-<action_id[:8]>/
        verify.html      standalone verifier with the session's proof bundle
        evidence.jsonl   ONLY the disclosed action's raw record

Selective by construction: undisclosed actions appear in the bundle as
hashes and typed metadata only; their raw payloads never leave the
evidence dir.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx


def find_evidence_entry(evidence_dir: Path, action_id: str) -> tuple[dict, str] | None:
    """Scan the evidence dir for an entry with this action_id.

    Returns (entry, raw_line) so the disclosed line is byte-identical to
    what the hook wrote — re-serializing could change key order and
    confuse a diff, even though hashing is order-independent.
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


def disclose(
    action_id: str,
    *,
    evidence_dir: Path | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
    out_dir: Path | None = None,
) -> Path:
    """Build a disclosure folder for one action. Returns the folder path.

    Raises SystemExit with a readable message on any failure — this is a
    CLI entry point, not a library API.
    """
    evidence_dir = evidence_dir or Path(
        os.environ.get("MERKL_EVIDENCE_DIR") or Path.home() / ".merkl" / "evidence"
    )
    endpoint = (endpoint or os.environ.get("MERKL_ENDPOINT", "https://api.merkl.ai")).rstrip("/")
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

    resp = httpx.get(
        f"{endpoint}/v1/sessions/{session_id}/verify.html",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30.0,
    )
    if resp.status_code == 422:
        sys.exit(
            f"Session {session_id} is not sealed yet — seal it first:\n"
            f"  curl -X POST -H 'Authorization: Bearer <key>' "
            f"{endpoint}/v1/sessions/{session_id}/seal"
        )
    if not resp.is_success:
        sys.exit(f"Failed to fetch verifier ({resp.status_code}): {resp.text[:200]}")

    out = out_dir or Path(f"disclosure-{action_id[:8]}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "verify.html").write_text(resp.text, encoding="utf-8")
    (out / "evidence.jsonl").write_text(raw_line + "\n", encoding="utf-8")

    print(f"Disclosure package: {out}/")
    print(f"  verify.html     session {session_id[:8]}… proof bundle + verifier")
    print(f"  evidence.jsonl  1 record: {entry.get('tool_name', '?')} action {action_id[:8]}…")
    print()
    print("Send the folder to the auditor. They open verify.html in a browser")
    print("and drop evidence.jsonl on it — no install, no network, no account.")
    return out
