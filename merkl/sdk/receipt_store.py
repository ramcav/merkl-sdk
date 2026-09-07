"""``LocalReceiptStore`` — the operator's own copy, on the operator's own disk.

A receipt that only exists inside somebody else's server is a receipt you cannot
produce when you need it most. This writes each one to ``~/.merkl/receipts``,
beside the raw payloads the Claude Code hook writes to ``~/.merkl/evidence``, in
exactly the shape ``merkl disclose`` and ``merkl receipt show`` already read: a
JSON object with ``envelope``, ``leaves``, and — this is the part that was
missing — the ``settlement_proof`` captured at settlement time.

Why the proof matters here. The settlement leaf commits only a
``settlement_proof_ref``, a short pointer. The ledger header, the transaction and
the validators' signatures that let a reader establish ledger inclusion *offline*
are not in the receipt and never were; they are captured by the rail adapter at
submit time. Without them written down, every disclosure made from this machine
reads ``ledger inclusion: unchecked — no settlement proof was supplied``, and the
strongest claim the format can make is unavailable to the one person who
actually has the evidence.

Failures are not swallowed. A payment has already settled by the time anything
here runs, so this cannot undo one, but a disk that would not take the record is
something the operator has to be told about rather than discover at audit time.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

from merkl.core.canonical import JSONObject
from merkl.core.rail import SettlementProof
from merkl.core.receipt import Envelope, ReceiptLeaves
from merkl.shared.hashing import canonical_hash

__all__ = ["LocalReceiptStore", "receipt_store_dir"]

_ENV_DIR: Final = "MERKL_RECEIPT_DIR"


def receipt_store_dir(explicit: Path | None = None) -> Path:
    """Where local receipts live: ``$MERKL_RECEIPT_DIR`` or ``~/.merkl/receipts``.

    The same resolution ``merkl receipt show`` and ``merkl disclose`` use, kept
    in one place so a reader and a writer can never disagree about the folder.
    """
    return explicit or Path(os.environ.get(_ENV_DIR) or Path.home() / ".merkl" / "receipts")


class LocalReceiptStore:
    """:class:`~merkl.core.ports.ReceiptStorePort` over a folder of JSON files.

    Also a :class:`~merkl.core.ports.SettlementProofStorePort`: the proof is
    merged into the receipt's own file rather than kept in a second one, so a
    disclosure is one file to find and the proof cannot be separated from the
    receipt it is about.
    """

    def __init__(self, directory: Path | None = None) -> None:
        self._dir = receipt_store_dir(directory)

    @property
    def directory(self) -> Path:
        return self._dir

    def path_for(self, receipt_id: str) -> Path:
        return self._dir / f"{receipt_id}.json"

    async def put(self, envelope: Envelope, leaves: ReceiptLeaves) -> None:
        content = envelope.to_content()
        locator = envelope.session_locator
        record: JSONObject = {
            "receipt_id": envelope.receipt_id,
            "envelope": content,
            "envelope_hash": canonical_hash(content).hex(),
            "leaves": list(leaves.contents()),
            "session_id": locator.session_id if locator else None,
            "leaf_index": locator.leaf_index if locator else None,
        }
        self._merge(envelope.receipt_id, record)

    async def put_settlement_proof(self, receipt_id: str, proof: SettlementProof) -> None:
        self._merge(receipt_id, {"settlement_proof": proof.to_content()})

    async def get(self, receipt_id: str) -> tuple[Envelope, ReceiptLeaves] | None:
        record = self._read(self.path_for(receipt_id))
        if record is None:
            return None
        return (
            Envelope.from_content(record["envelope"]),
            ReceiptLeaves.from_contents(record["leaves"]),
        )

    async def list(
        self, treasury: str, agent_id: str | None = None, since: str | None = None
    ) -> list[Envelope]:
        """Every stored envelope for a treasury, newest id last.

        ``since`` is accepted for the port's shape and not applied: a stored
        receipt has no timestamp of its own that this store may trust, and
        inventing one from the file's mtime would be a fact about the disk
        rather than about the payment.
        """
        found: list[Envelope] = []
        if not self._dir.is_dir():
            return found
        for path in sorted(self._dir.glob("*.json")):
            record = self._read(path)
            if record is None:
                continue
            try:
                envelope = Envelope.from_content(record["envelope"])
            except Exception:  # noqa: BLE001 - a foreign file is not this store's error
                continue
            if envelope.treasury != treasury:
                continue
            if agent_id is not None and envelope.agent_id != agent_id:
                continue
            found.append(envelope)
        return found

    # -- disk -------------------------------------------------------------- #

    def _merge(self, receipt_id: str, members: JSONObject) -> None:
        """Write these members into the receipt's file, keeping what is there.

        A merge rather than a replace because the two writers arrive at
        different moments: the receipt when the flow finishes, the proof when
        the capture is complete. Whichever lands second must not erase the
        first.
        """
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self.path_for(receipt_id)
        record: dict[str, Any] = dict(self._read(path) or {})
        record.update(members)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    def _read(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return dict(data) if isinstance(data, dict) else None
