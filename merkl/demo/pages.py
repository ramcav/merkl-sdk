"""From a scenario to a page a stranger can open, and two verifiers over it.

A scenario that ends with the SDK saying "verified" has proved very little. This
module ends each one the way a dispute actually ends: a self-contained
``verify.html`` on disk, checked by the Python verifier and again by the
JavaScript one — two programs that share no code, reading the same file, and
required to agree.

The bundle carries the settlement proof and the signed policy document alongside
the receipt, because a page that cannot re-read the rules cannot tell you which
rule allowed the payment. It does **not** carry validator keys or PCR
measurements: those are what the *reader* pins, and a receipt that nominated the
measurements it should be judged against would be judging itself.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from merkl.adapters.fake import FakeLedger
from merkl.core.canonical import JSONObject
from merkl.core.checks import CheckStatus
from merkl.core.verify.receipt import ReceiptVerdict, receipt_from_content, verify_receipt
from merkl.core.verify.render import VERIFY_JS_PATH, render_verify_html
from merkl.core.verify.settlement import ValidatorTrust
from merkl.demo.scenarios import ScenarioResult
from merkl.sdk.receipts import ReceiptOutcome

NODE_CLI: Path = VERIFY_JS_PATH.parent / "cli.mjs"
"""``@merkl/verify``'s command line, inside the wheel next to the module."""


# -- material --------------------------------------------------------------- #


def receipt_entry(outcome: ReceiptOutcome, *, policy_document: JSONObject | None) -> JSONObject:
    """One ``receipts[]`` member of a bundle v1.2, with what a reader needs."""
    entry: JSONObject = {
        "envelope": outcome.envelope.to_content(),
        "leaves": list(outcome.receipt.leaves.contents()),
    }
    if outcome.proof is not None:
        entry["settlement_proof"] = outcome.proof.to_content()
    if policy_document is not None:
        entry["policy_document"] = policy_document
    return entry


def bundle_for(result: ScenarioResult) -> JSONObject:
    """A receipt-only bundle: complete at level 1, and needing no notary.

    Level 2 would add the session log, the notary's signature and the Bitcoin
    anchor. It is not what makes these receipts true — it is what makes the set
    of them complete — so a demo that runs with no notary at all is the honest
    default.
    """
    policy = result.rig.signed_policy.to_content()
    return {
        "version": "1.2",
        "session": None,
        "actions": [],
        "receipts": [receipt_entry(o, policy_document=policy) for o in result.outcomes],
    }


def validator_pins(result: ScenarioResult) -> dict[str, str]:
    """The keys a reader of *this* rail's proofs would have pinned in advance.

    On the fake network they are published here because the network exists only
    in this process. On XRPL they come from a UNL, and the reader is the one who
    decides which list to believe.
    """
    ledger = result.rig.ledger
    if not isinstance(ledger, FakeLedger):
        return {}
    return {v.name: v.public_key for v in ledger.validators}


# -- verification ------------------------------------------------------------ #


@dataclasses.dataclass(frozen=True)
class VerifierReading:
    """What one verifier said about one file."""

    verifier: str
    ok: bool
    complete: bool
    detail: str
    ran: bool = True

    @property
    def line(self) -> str:
        if not self.ran:
            return f"{self.verifier:<12} did not run — {self.detail}"
        verdict = "nothing contradicted" if self.ok else "CONTRADICTED"
        scope = "every check ran" if self.complete else "some checks had no material"
        return f"{self.verifier:<12} {verdict}; {scope}"


def load_page_bundle(path: Path) -> JSONObject:
    """Read the bundle back out of the rendered page, as a reader would."""
    from merkl.cli.verify import load_input

    return load_input(path)


def verify_with_python(path: Path, *, validators: dict[str, str], quorum: int) -> VerifierReading:
    """``merkl verify``'s checks, over the file that was written."""
    bundle = load_page_bundle(path)
    trust = ValidatorTrust(validators=validators, quorum=quorum) if validators else None
    receipts = bundle.get("receipts")
    verdicts: list[ReceiptVerdict] = []
    for entry in receipts if isinstance(receipts, list) else []:
        if not isinstance(entry, dict):
            continue
        envelope, leaves = receipt_from_content(entry)
        verdicts.append(
            verify_receipt(
                envelope,
                leaves,
                validator_trust=trust,
                settlement_proof=entry.get("settlement_proof"),
                policy_document=entry.get("policy_document"),
            )
        )
    ok = all(v.ok for v in verdicts)
    complete = all(v.complete for v in verdicts)
    unchecked = sorted(
        {
            c.name
            for v in verdicts
            for c in v.result.checks
            if c.status is CheckStatus.NOT_IMPLEMENTED
        }
    )
    failures = sorted({c.name for v in verdicts for c in v.result.failures})
    detail = ", ".join(failures) if failures else ", ".join(unchecked)
    return VerifierReading(verifier="merkl verify", ok=ok, complete=complete, detail=detail)


def verify_with_node(path: Path, *, validators: dict[str, str], quorum: int) -> VerifierReading:
    """The JavaScript verifier, in a subprocess, over the same file.

    A missing ``node`` is reported as *did not run*, never as a pass. Half the
    checking not happening is a fact about the run, and hiding it here would be
    the same mistake the verifier itself refuses to make.
    """
    node = shutil.which("node")
    if node is None:
        return VerifierReading(
            verifier="@merkl/verify",
            ok=False,
            complete=False,
            detail="node is not on PATH",
            ran=False,
        )
    argv = [node, str(NODE_CLI), str(path), "--json"]
    for name, key in validators.items():
        argv += ["--validator", f"{name}={key}"]
    if validators:
        argv += ["--quorum", str(quorum)]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode == 2:
        return VerifierReading(
            verifier="@merkl/verify",
            ok=False,
            complete=False,
            detail=proc.stderr.strip()[:200],
            ran=False,
        )
    report = json.loads(proc.stdout)
    failures = sorted(
        {
            c["name"]
            for r in report["receipts"]
            for c in r["checks"]
            if c["status"] == CheckStatus.FAIL.value
        }
    )
    unchecked = sorted(
        {
            c["name"]
            for r in report["receipts"]
            for c in r["checks"]
            if c["status"] == CheckStatus.NOT_IMPLEMENTED.value
        }
    )
    return VerifierReading(
        verifier="@merkl/verify",
        ok=bool(report["ok"]),
        complete=bool(report["complete"]),
        detail=", ".join(failures) if failures else ", ".join(unchecked),
    )


# -- the folder -------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PageReport:
    """One scenario, once it is a file on disk that two verifiers have read."""

    result: ScenarioResult
    page: Path
    bundle: Path
    readings: tuple[VerifierReading, ...]

    @property
    def agreed(self) -> bool:
        """Both verifiers ran, both found nothing contradicted, and they agree."""
        if len(self.readings) < 2 or not all(r.ran for r in self.readings):
            return False
        first = self.readings[0]
        return all(r.ok == first.ok and r.complete == first.complete for r in self.readings) and (
            first.ok
        )


def write_pages(
    results: Sequence[ScenarioResult],
    out_dir: Path,
    *,
    rail: str,
    quorum: int = 2,
    node: bool = True,
    validator_trust: dict[str, str] | None = None,
) -> list[PageReport]:
    """Render every scenario, then check each page with both verifiers.

    ``validator_trust``, when given, is used for every page instead of
    :func:`validator_pins` — the one set the *reader* pinned in advance for
    this whole run, the same way an XRPL UNL is audited once rather than
    per-transaction. Leave it ``None`` for the fake rail, whose validator
    keys exist only in this process and are read off each result instead.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "bundles").mkdir(exist_ok=True)
    reports: list[PageReport] = []
    for index, result in enumerate(results, start=1):
        stem = f"{index}-{result.name}"
        bundle = bundle_for(result)
        page_path = out_dir / f"{stem}.html"
        bundle_path = out_dir / "bundles" / f"{stem}.json"
        page_path.write_text(render_verify_html(bundle), encoding="utf-8")
        bundle_path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        pins = validator_trust if validator_trust is not None else validator_pins(result)
        readings = [verify_with_python(page_path, validators=pins, quorum=quorum)]
        if node:
            readings.append(verify_with_node(page_path, validators=pins, quorum=quorum))
        if pins:
            (out_dir / "bundles" / f"{stem}.validators.json").write_text(
                json.dumps({"validators": pins, "quorum": quorum}, indent=2) + "\n",
                encoding="utf-8",
            )
        reports.append(
            PageReport(
                result=result,
                page=page_path,
                bundle=bundle_path,
                readings=tuple(readings),
            )
        )
    (out_dir / "index.html").write_text(render_index(reports, rail=rail), encoding="utf-8")
    (out_dir / "README.txt").write_text(readme(reports, rail=rail), encoding="utf-8")
    return reports


def readme(reports: Sequence[PageReport], *, rail: str) -> str:
    lines = [
        "Merkl co-signer — five scenarios",
        "================================",
        "",
        f"Rail: {rail}",
        "",
        "Open index.html, or any of the numbered pages, in a browser. They work",
        "offline. Nothing in them calls home, and none of them needs an account.",
        "",
        "Each page carries the receipts one scenario produced, the settlement proof",
        "captured when it settled, and the signed policy document the signer decided",
        "against. The page recomputes every hash in front of you.",
        "",
    ]
    for index, report in enumerate(reports, start=1):
        lines.append(f"{index}. {report.result.title}")
        lines.append(f"   {report.result.question}")
        lines.append(f"   {report.page.name}")
        for reading in report.readings:
            lines.append(f"     {reading.line}")
        lines.append("")
    lines += [
        "Check them yourself, two ways:",
        "",
        "  merkl verify 1-benign-payment.html --all",
        "  npx @merkl/verify 1-benign-payment.html --all",
        "",
        "The two implementations share no code. If they ever disagreed, one of them",
        "would be wrong, and you would be the one who found out.",
        "",
    ]
    return "\n".join(lines)


_INDEX_CSS = """
:root { color-scheme: light dark; }
body { margin: 0 auto; padding: 2.5rem 1.25rem; max-width: 46rem;
  font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
p.lede { margin: 0 0 2rem; opacity: .75; }
ol { padding-left: 1.25rem; }
li { margin-bottom: 1.5rem; }
a { font-weight: 600; }
.q { opacity: .75; }
.v { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; opacity: .7; }
footer { margin-top: 2.5rem; font-size: .9rem; opacity: .75; }
code { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
"""


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_index(reports: Sequence[PageReport], *, rail: str) -> str:
    """A plain contents page. The verifiers are the interesting part, not this."""
    items: list[str] = []
    for report in reports:
        readings = "<br>".join(_escape(r.line) for r in report.readings)
        items.append(
            f'<li><a href="{_escape(report.page.name)}">{_escape(report.result.title)}</a>'
            f'<div class="q">{_escape(report.result.question)}</div>'
            f'<div class="v">{readings}</div></li>'
        )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Merkl — five scenarios</title>"
        f"<style>{_INDEX_CSS}</style></head><body>"
        "<h1>Five things an agent tried to pay for</h1>"
        f'<p class="lede">Each page is one scenario, run end to end on the '
        f"<strong>{_escape(rail)}</strong> rail. Open one and check it yourself; "
        "it works offline.</p>"
        "<ol>" + "".join(items) + "</ol>"
        "<footer>Every page was also checked from a terminal by both implementations "
        "of the verifier — <code>merkl verify</code> in Python and "
        "<code>@merkl/verify</code> in JavaScript — over these same files.</footer>"
        "</body></html>\n"
    )


def summary_lines(reports: Sequence[PageReport]) -> list[str]:
    """What to print at the end of a run."""
    lines: list[str] = []
    for index, report in enumerate(reports, start=1):
        lines.append(f"{index}. {report.result.title}  ({report.page.name})")
        for note in report.result.notes:
            lines.append(f"     {note}")
        for reading in report.readings:
            lines.append(f"     {reading.line}")
    return lines


__all__ = [
    "NODE_CLI",
    "PageReport",
    "VerifierReading",
    "bundle_for",
    "load_page_bundle",
    "readme",
    "receipt_entry",
    "render_index",
    "summary_lines",
    "validator_pins",
    "verify_with_node",
    "verify_with_python",
    "write_pages",
]
