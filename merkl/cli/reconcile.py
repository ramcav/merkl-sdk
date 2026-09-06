"""``merkl reconcile`` — treasury outflows against receipts, both directions (D17).

Two questions, and the second is the one that matters:

1. Does every receipt correspond to a transaction the rail actually validated?
   A receipt for a payment that never happened is a bookkeeping error.
2. Does every outflow from the treasury correspond to a receipt? **An outflow
   with no receipt is money that left without a co-signed authorization behind
   it** — the failure the whole system exists to make visible. Checking only the
   first direction would let exactly that through.

Receipts come from the local store first and the notary second, so an operator
can reconcile their own treasury without anyone's server being up. The notary
side is a plain HTTP GET against `/v1/receipts`; when that route is not there
yet the command says so and reconciles against what is local, rather than
reporting a clean slate it did not establish.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

__all__ = ["Reconciliation", "reconcile", "reconcile_command"]


@dataclasses.dataclass(frozen=True)
class Reconciliation:
    """What matched, and — the important half — what did not."""

    matched: tuple[tuple[str, str], ...]
    outflows_without_receipts: tuple[dict[str, Any], ...]
    receipts_without_outflows: tuple[dict[str, Any], ...]
    anchor_mismatches: tuple[tuple[str, str, str], ...]

    @property
    def clean(self) -> bool:
        return not (
            self.outflows_without_receipts
            or self.receipts_without_outflows
            or self.anchor_mismatches
        )

    def to_content(self) -> dict[str, Any]:
        return {
            "clean": self.clean,
            "matched": [{"tx_hash": tx, "receipt_id": rid} for tx, rid in self.matched],
            "outflows_without_receipts": list(self.outflows_without_receipts),
            "receipts_without_outflows": list(self.receipts_without_outflows),
            "anchor_mismatches": [
                {"tx_hash": tx, "observed_anchor": observed, "receipt_left": left}
                for tx, observed, left in self.anchor_mismatches
            ],
        }


def _tx_of(receipt: dict[str, Any]) -> str:
    envelope = receipt.get("envelope") or {}
    leaves = receipt.get("leaves") or []
    settlement = leaves[4] if len(leaves) > 4 and isinstance(leaves[4], dict) else {}
    return str(
        settlement.get("tx_hash") or receipt.get("tx_hash") or envelope.get("tx_hash") or ""
    )


def _left_of(receipt: dict[str, Any]) -> str:
    envelope = receipt.get("envelope") or {}
    return str(envelope.get("left") or receipt.get("left") or "")


def reconcile(
    outflows: Iterable[dict[str, Any]], receipts: Sequence[dict[str, Any]]
) -> Reconciliation:
    """Match validated outflows to receipts by transaction id, both ways.

    The anchor is checked as well as the identity: a receipt whose LEFT is not
    what the ledger carried is a receipt about a different authorization, even
    when the transaction ids agree.
    """
    by_tx = {_tx_of(r).upper(): r for r in receipts if _tx_of(r)}
    seen: set[str] = set()
    matched: list[tuple[str, str]] = []
    missing_receipts: list[dict[str, Any]] = []
    mismatches: list[tuple[str, str, str]] = []

    for outflow in outflows:
        tx = str(outflow.get("tx_hash", "")).upper()
        receipt = by_tx.get(tx)
        if receipt is None:
            missing_receipts.append(dict(outflow))
            continue
        seen.add(tx)
        envelope = receipt.get("envelope") or {}
        receipt_id = str(envelope.get("receipt_id") or receipt.get("receipt_id") or "")
        matched.append((tx, receipt_id))
        anchor = str(outflow.get("anchor") or "").lower()
        left = _left_of(receipt).lower()
        if anchor and left and anchor != left:
            mismatches.append((tx, anchor, left))

    orphans = [r for tx, r in by_tx.items() if tx not in seen]
    return Reconciliation(
        matched=tuple(matched),
        outflows_without_receipts=tuple(missing_receipts),
        receipts_without_outflows=tuple(orphans),
        anchor_mismatches=tuple(mismatches),
    )


def _local_receipts(store: Path, treasury: str) -> list[dict[str, Any]]:
    if not store.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(store.glob("*.json")):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(receipt, dict):
            continue
        envelope = receipt.get("envelope") or {}
        if envelope.get("treasury") in (treasury, None) or receipt.get("treasury") == treasury:
            out.append(receipt)
    return out


def _notary_receipts(
    endpoint: str, api_key: str, treasury: str
) -> tuple[list[dict[str, Any]], str | None]:
    """Receipts the notary holds, or a reason it could not say."""
    import httpx

    try:
        response = httpx.get(
            f"{endpoint.rstrip('/')}/v1/receipts",
            params={"treasury": treasury},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        return [], f"the notary at {endpoint} could not be reached: {exc}"
    if response.status_code == 404:
        return [], (
            f"the notary at {endpoint} has no /v1/receipts route yet — reconciled against "
            "local receipts only, which is not the same as reconciled"
        )
    if not response.is_success:
        return [], f"the notary answered {response.status_code}: {response.text[:120]}"
    body = response.json()
    items = body.get("items") if isinstance(body, dict) else body
    return [r for r in (items or []) if isinstance(r, dict)], None


def reconcile_command(
    treasury: str,
    *,
    history: Path | None = None,
    store: Path | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
    as_json: bool = False,
) -> int:
    """Reconcile one treasury. Returns the process exit code.

    ``history`` is a JSON file of validated outflows. It is a file rather than a
    live rail query on purpose: this command does no network work of its own
    beyond the optional notary lookup, so it runs in an air-gapped audit. Produce
    the file with the rail adapter, or with the exchange's own export.
    """
    store = store or Path(
        os.environ.get("MERKL_RECEIPT_DIR") or Path.home() / ".merkl" / "receipts"
    )
    if history is None:
        print(
            "pass --history <file.json>: a JSON array of validated outflows "
            '({"tx_hash", "destination", "value", "asset", "ledger_index", "anchor"}). '
            "merkl.adapters.xrpl's history() writes exactly that shape.",
            file=sys.stderr,
        )
        return 2
    try:
        raw = json.loads(history.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {history}: {exc}", file=sys.stderr)
        return 2
    outflows = raw.get("outflows") if isinstance(raw, dict) else raw
    if not isinstance(outflows, list):
        print(f"{history} must hold an array of outflows", file=sys.stderr)
        return 2

    receipts = _local_receipts(store, treasury)
    note: str | None = None
    endpoint = endpoint or os.environ.get("MERKL_ENDPOINT")
    if endpoint:
        remote, note = _notary_receipts(
            endpoint, api_key or os.environ.get("MERKL_API_KEY", ""), treasury
        )
        known = {_tx_of(r).upper() for r in receipts}
        receipts.extend(r for r in remote if _tx_of(r).upper() not in known)
    else:
        note = "no notary is configured, so only local receipts were compared"

    report = reconcile(outflows, receipts)
    if as_json:
        print(json.dumps({"treasury": treasury, "note": note, **report.to_content()}, indent=2))
        return 0 if report.clean else 1

    print(f"treasury {treasury}")
    print(f"  {len(outflows)} validated outflows, {len(receipts)} receipts")
    print(f"  {len(report.matched)} matched")
    if note:
        print(f"  note: {note}")
    if report.outflows_without_receipts:
        print()
        print(f"  {len(report.outflows_without_receipts)} OUTFLOWS WITH NO RECEIPT")
        print("  Money left the treasury with no co-signed authorization on file.")
        for outflow in report.outflows_without_receipts[:20]:
            print(
                f"    {outflow.get('tx_hash', '?')}  {outflow.get('value', '?')} "
                f"{outflow.get('asset', '?')} to {outflow.get('destination', '?')}"
            )
    if report.receipts_without_outflows:
        print()
        print(f"  {len(report.receipts_without_outflows)} receipts with no matching outflow")
        print("  A receipt for a payment this history does not show. Check the window first.")
        for receipt in report.receipts_without_outflows[:20]:
            envelope = receipt.get("envelope") or {}
            print(f"    {envelope.get('receipt_id', '?')}  tx {_tx_of(receipt) or '(none)'}")
    if report.anchor_mismatches:
        print()
        print(f"  {len(report.anchor_mismatches)} anchor mismatches")
        print("  The ledger carried a commitment that is not this receipt's LEFT.")
        for tx, observed, left in report.anchor_mismatches[:20]:
            print(f"    {tx}  ledger {observed}  receipt {left}")
    print()
    print("  clean" if report.clean else "  NOT CLEAN")
    return 0 if report.clean else 1
