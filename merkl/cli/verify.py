"""``merkl verify`` — check a receipt, a bundle or a verify.html, offline.

The command an auditor runs when they would rather not trust a web page. It
reads the same files the page reads, runs the same checks the page runs, and
prints the same verdict in words. No network, ever: every trust anchor is a flag,
and a flag nobody passed becomes a named unchecked line rather than a pass.

Exit codes are the machine-readable half:

* ``0`` — nothing was contradicted
* ``1`` — a check failed, or ``--require-complete`` was asked for and something
  went unchecked
* ``2`` — the input could not be read at all

"Nothing was contradicted" is deliberately not the same as "everything was
checked". The second line of the output says which one you got.
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

from merkl.core.checks import CheckStatus
from merkl.core.receipt import Envelope
from merkl.core.verify.attestation import AttestationTrust
from merkl.core.verify.card import receipt_card, render_card
from merkl.core.verify.log import evidence_records, verify_log_bundle
from merkl.core.verify.receipt import ReceiptVerdict, receipt_from_content, verify_receipt
from merkl.core.verify.settlement import ValidatorTrust

__all__ = ["load_input", "verify_command"]

_BUNDLE_IN_PAGE = re.compile(r"^const BUNDLE = (.*);\s*$", re.MULTILINE)

_MARK = {
    CheckStatus.PASS: "  ok  ",
    CheckStatus.FAIL: " FAIL ",
    CheckStatus.NOT_IMPLEMENTED: "  --  ",
}


def load_input(path: Path) -> dict[str, Any]:
    """Read a bundle out of a ``.json`` file or a rendered ``verify.html``.

    A verify.html carries its bundle as a JSON literal, so the page an auditor
    was emailed is itself a valid input to this command. That is the point: the
    two entry points read the same bytes, and disagreeing with the page is
    something you can check rather than something you have to take on faith.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".html", ".htm"):
        match = _BUNDLE_IN_PAGE.search(text)
        if match is None:
            raise ValueError(f"{path} does not carry an embedded Merkl bundle")
        return dict(json.loads(match.group(1).replace("<\\/", "</")))
    data = json.loads(text)
    if isinstance(data, list):
        return {"version": "1.2", "receipts": data, "session": None, "actions": []}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not an object")
    if "envelope" in data and "leaves" in data:
        return {"version": "1.2", "receipts": [data], "session": None, "actions": []}
    return data


def _pcrs(values: list[str]) -> dict[int, str]:
    out: dict[int, str] = {}
    for item in values:
        index, _, digest = item.partition("=")
        out[int(index)] = digest.lower()
    return out


def _validators(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        name, _, key = item.partition("=")
        out[name] = key.lower()
    return out


def _load_json(path: Path | None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def _wrap(text: str, width: int = 78, indent: str = "  ") -> str:
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent
        current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return "\n".join(lines)


def _print_verdict(
    verdict: ReceiptVerdict,
    envelope: Envelope,
    contents: list[Any],
    *,
    show_all: bool,
) -> None:
    print()
    print(render_card(receipt_card(verdict, envelope, contents)))
    print()
    for c in verdict.result.checks:
        if not show_all and c.status is CheckStatus.PASS:
            continue
        print(f"{_MARK[c.status]} {c.name:<38} {c.detail}")
    if not show_all:
        passed = sum(1 for c in verdict.result.checks if c.status is CheckStatus.PASS)
        print(f"{'  ok  '} {passed} further checks passed (--all to list them)")


def verify_command(
    path: Path,
    *,
    as_json: bool = False,
    show_all: bool = False,
    require_complete: bool = False,
    policy: Path | None = None,
    admin_key: str | None = None,
    proof: Path | None = None,
    evidence: Path | None = None,
    pcr: list[str] | None = None,
    validator: list[str] | None = None,
    quorum: int = 0,
    now: str | None = None,
    max_age: int | None = None,
) -> int:
    """Verify one file and print the verdict. Returns the process exit code."""
    try:
        bundle = load_input(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2

    trust = None
    moment = None
    if pcr:
        trust = AttestationTrust(pcrs=_pcrs(pcr), max_age_seconds=max_age)
        moment = (
            datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))
            if now
            else datetime.datetime.now(tz=datetime.UTC)
        )
    validator_trust = None
    if validator:
        validator_trust = ValidatorTrust(validators=_validators(validator), quorum=quorum)

    policy_document = _load_json(policy)
    settlement_proof = _load_json(proof)
    records = evidence_records(evidence.read_text(encoding="utf-8")) if evidence else []

    session = bundle.get("session")
    session_bundle = bundle if isinstance(session, dict) else None
    log = verify_log_bundle(bundle, evidence=records) if session_bundle else None

    verdicts: list[tuple[ReceiptVerdict, Envelope, list[Any]]] = []
    for entry in bundle.get("receipts") or []:
        if not isinstance(entry, dict):
            continue
        try:
            envelope, leaves = receipt_from_content(entry)
        except Exception as exc:  # noqa: BLE001 - an unreadable receipt is a usage error
            print(f"receipt does not parse: {exc}", file=sys.stderr)
            return 2
        verdicts.append(
            (
                verify_receipt(
                    envelope,
                    leaves,
                    attestation_trust=trust,
                    now=moment,
                    validator_trust=validator_trust,
                    settlement_proof=settlement_proof or entry.get("settlement_proof"),
                    policy_document=policy_document or entry.get("policy_document"),
                    admin_public_key=admin_key,
                    session_bundle=session_bundle,
                ),
                envelope,
                leaves,
            )
        )

    if not verdicts and log is None:
        print(f"{path} carries neither a receipt nor a session", file=sys.stderr)
        return 2

    ok = all(v.ok for v, _, _ in verdicts) and (log.ok if log else True)
    complete = all(v.complete for v, _, _ in verdicts) and (log.complete if log else True)

    if as_json:
        print(
            json.dumps(
                {
                    "source": str(path),
                    "ok": ok,
                    "complete": complete,
                    "receipts": [v.to_content() for v, _, _ in verdicts],
                    "cards": [
                        receipt_card(v, env, leaves).to_content() for v, env, leaves in verdicts
                    ],
                    "log": log.to_content() if log else None,
                },
                indent=2,
            )
        )
    else:
        for verdict, envelope, leaves in verdicts:
            _print_verdict(verdict, envelope, leaves, show_all=show_all)
        if log is not None:
            print()
            print("session log")
            print("-" * 72)
            for c in log.result.checks:
                if not show_all and c.status is CheckStatus.PASS:
                    continue
                print(f"{_MARK[c.status]} {c.name:<38} {c.detail}")
            bad = [a for a in log.actions if not a.ok]
            print(f"{len(log.actions) - len(bad)} of {len(log.actions)} actions verified")
            for reading in log.evidence:
                print(f"  evidence {reading.verdict:<8} {reading.label}: {reading.detail}")
        print()
        print("nothing was contradicted" if ok else "SOMETHING WAS CONTRADICTED")
        if complete:
            print("every check ran")
        else:
            # Name them rather than describing them. "Some checks did not run"
            # is true of every unchecked receipt and tells a reader nothing
            # about which fact about this one is still open.
            for verdict, _, _ in verdicts:
                for entry in verdict.not_checked:
                    print(_wrap(f"not checked — {entry.label}: {entry.reason}", indent="  "))
            print("  none of them is a pass, and none of them is a failure")

    if not ok:
        return 1
    return 1 if require_complete and not complete else 0
