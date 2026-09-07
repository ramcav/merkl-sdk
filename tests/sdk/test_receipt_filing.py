"""Filing a receipt: the proof goes with it, to the notary and to the disk.

The gap this closes is narrow and expensive. Leaf 4 commits a
``settlement_proof_ref`` — a pointer, sixteen characters of transaction hash —
and nothing else about the ledger. Everything a reader needs to establish
inclusion *offline* (the header, the transaction, the validators' signatures) is
captured by the rail adapter at submit time and existed nowhere but in memory.
So every receipt filed by this SDK read ``ledger inclusion: unchecked — no
settlement proof was supplied``, on a payment whose proof had been captured
successfully and then dropped on the floor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from merkl.core.rail import SettlementProof
from merkl.core.receipt import Envelope, ReceiptLeaves
from merkl.core.verify.receipt import receipt_from_content, verify_receipt
from merkl.sdk.receipt_store import LocalReceiptStore, receipt_store_dir
from tests.scenarios.harness import build_rig

pytestmark = pytest.mark.asyncio


class RecordingNotary:
    """A notary that remembers what it was handed, and can refuse."""

    def __init__(self, *, fail: str | None = None) -> None:
        self.receipts: list[dict[str, Any]] = []
        self.late_proofs: list[tuple[str, SettlementProof]] = []
        self._fail = fail

    async def file_receipt(
        self,
        envelope: Envelope,
        leaves: ReceiptLeaves,
        *,
        settlement_proof: SettlementProof | None = None,
    ) -> None:
        if self._fail:
            raise RuntimeError(self._fail)
        self.receipts.append(
            {
                "receipt_id": envelope.receipt_id,
                "envelope": envelope.to_content(),
                "leaves": list(leaves.contents()),
                "settlement_proof": settlement_proof,
            }
        )

    async def file_settlement_proof(self, receipt_id: str, proof: SettlementProof) -> None:
        if self._fail:
            raise RuntimeError(self._fail)
        self.late_proofs.append((receipt_id, proof))


class OldReceiptStore:
    """A store written before proofs had a port. It must keep working."""

    def __init__(self) -> None:
        self.receipts: list[str] = []

    async def put(self, envelope: Envelope, leaves: ReceiptLeaves) -> None:
        self.receipts.append(envelope.receipt_id)


class TestTheBuilderFilesTheProof:
    async def test_a_settled_receipt_reaches_the_notary_with_its_capture(
        self, tmp_path: Path
    ) -> None:
        notary = RecordingNotary()
        rig = build_rig(tmp_path, notary=notary)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())

        assert outcome.settled and outcome.proof is not None
        assert outcome.notary_error is None
        assert len(notary.receipts) == 1
        filed = notary.receipts[0]
        assert filed["receipt_id"] == outcome.receipt.envelope.receipt_id
        assert filed["settlement_proof"] is outcome.proof

    async def test_the_filed_proof_is_the_one_the_receipt_leaf_points_at(
        self, tmp_path: Path
    ) -> None:
        """A proof filed against the wrong payment is worse than none at all."""
        notary = RecordingNotary()
        rig = build_rig(tmp_path, notary=notary)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())

        proof = notary.receipts[0]["settlement_proof"]
        settlement = outcome.receipt.leaves.settlement
        assert settlement is not None
        assert proof.proof_ref() == settlement.settlement_proof_ref
        assert proof.tx_hash == settlement.tx_hash

    async def test_a_refusal_files_a_receipt_and_no_proof(self, tmp_path: Path) -> None:
        notary = RecordingNotary()
        rig = build_rig(tmp_path, notary=notary, blocklist=("rSUPPLIER0000000000000000000000000",))
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(destination="rBLOCKED")
        )

        assert not outcome.settled
        assert len(notary.receipts) == 1
        assert notary.receipts[0]["settlement_proof"] is None

    async def test_a_notary_that_is_down_does_not_fail_a_settled_payment(
        self, tmp_path: Path
    ) -> None:
        """Plan D12: the witness is not on the path, and cannot become one."""
        notary = RecordingNotary(fail="connection refused")
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, notary=notary, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())

        assert outcome.settled
        assert outcome.notary_error is not None
        assert "connection refused" in outcome.notary_error
        # And the record is not lost: the local copy has it, proof included.
        record = json.loads(store.path_for(outcome.receipt.envelope.receipt_id).read_text())
        assert record["settlement_proof"]["tx_hash"] == outcome.settlement.tx_hash

    async def test_no_notary_configured_is_not_an_error(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert outcome.settled and outcome.notary_error is None


class TestTheLateProof:
    async def test_a_capture_completed_afterwards_still_reaches_its_receipt(
        self, tmp_path: Path
    ) -> None:
        """Validations collected late are the same evidence, arriving later."""
        notary = RecordingNotary()
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, notary=notary, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        receipt_id = outcome.receipt.envelope.receipt_id

        assert outcome.proof is not None
        completed = SettlementProof(
            rail=outcome.proof.rail,
            tx_hash=outcome.proof.tx_hash,
            ledger_index=outcome.proof.ledger_index,
            ledger_hash=outcome.proof.ledger_hash,
            ledger_header=outcome.proof.ledger_header,
            transaction=outcome.proof.transaction,
            tx_path=outcome.proof.tx_path,
            validations=(*outcome.proof.validations, {"late": True}),
            captured=(*outcome.proof.captured, "a validation collected after the fact"),
        )
        error = await rig.builder.attach_settlement_proof(receipt_id, completed)

        assert error is None
        assert notary.late_proofs == [(receipt_id, completed)]
        stored = json.loads(store.path_for(receipt_id).read_text())["settlement_proof"]
        assert stored["validations"][-1] == {"late": True}

    async def test_a_late_proof_the_notary_refuses_is_reported_not_raised(
        self, tmp_path: Path
    ) -> None:
        notary = RecordingNotary(fail="422 unprocessable")
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store, notary=notary)
        proof = SettlementProof(rail="fake", tx_hash="AB" * 32, ledger_index=7)

        error = await rig.builder.attach_settlement_proof("rcp-late", proof)

        assert error is not None and "422" in error
        # Filed locally regardless: the notary's opinion is not the record.
        assert json.loads(store.path_for("rcp-late").read_text())["settlement_proof"]

    async def test_a_late_proof_with_no_notary_is_still_kept_locally(self, tmp_path: Path) -> None:
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store)
        proof = SettlementProof(rail="fake", tx_hash="CD" * 32, ledger_index=9)

        assert await rig.builder.attach_settlement_proof("rcp-offline", proof) is None
        assert json.loads(store.path_for("rcp-offline").read_text())["settlement_proof"]


class TestTheLocalCopy:
    async def test_the_receipt_file_carries_the_proof_beside_the_leaves(
        self, tmp_path: Path
    ) -> None:
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store)
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(), reasoning=rig.reasoning()
        )
        path = store.path_for(outcome.receipt.envelope.receipt_id)

        assert path.is_file()
        record = json.loads(path.read_text())
        assert record["envelope"] == outcome.receipt.envelope.to_content()
        assert len(record["leaves"]) == 7
        assert record["settlement_proof"]["rail"] == "fake"

    async def test_that_file_is_enough_to_reach_proven_offline_with_no_notary(
        self, tmp_path: Path
    ) -> None:
        """The whole point: the operator's own disk answers the ledger question.

        `merkl disclose` builds its bundle out of exactly this file, so what a
        reader gets offline is decided here.
        """
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        record = json.loads(store.path_for(outcome.receipt.envelope.receipt_id).read_text())

        envelope, leaves = receipt_from_content(record)
        verdict = verify_receipt(
            envelope, leaves, settlement_proof=record["settlement_proof"], validator_trust=None
        )
        assert verdict.ledger_inclusion != "unchecked"
        assert "no settlement proof was supplied" not in verdict.ledger_inclusion_detail

    async def test_the_proof_never_overwrites_the_receipt_written_before_it(
        self, tmp_path: Path
    ) -> None:
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        receipt_id = outcome.receipt.envelope.receipt_id

        await rig.builder.attach_settlement_proof(
            receipt_id, SettlementProof(rail="fake", tx_hash="EF" * 32, ledger_index=11)
        )
        record = json.loads(store.path_for(receipt_id).read_text())
        assert record["envelope"] == outcome.receipt.envelope.to_content()
        assert record["settlement_proof"]["ledger_index"] == 11

    async def test_a_store_written_before_proofs_had_a_port_keeps_working(
        self, tmp_path: Path
    ) -> None:
        """Extend, migrate with downgrade, never replace in place."""
        store = OldReceiptStore()
        rig = build_rig(tmp_path, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert store.receipts == [outcome.receipt.envelope.receipt_id]

    async def test_the_store_reads_back_what_it_wrote(self, tmp_path: Path) -> None:
        store = LocalReceiptStore(tmp_path / "receipts")
        rig = build_rig(tmp_path, receipt_store=store)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())

        found = await store.get(outcome.receipt.envelope.receipt_id)
        assert found is not None
        envelope, _ = found
        assert envelope.root == outcome.receipt.envelope.root
        listed = await store.list(envelope.treasury)
        assert [e.receipt_id for e in listed] == [envelope.receipt_id]
        assert await store.list("rSOMEONE-ELSE") == []
        assert await store.get("no-such-receipt") is None


class TestWhereTheFolderIs:
    async def test_it_defaults_beside_the_evidence_log(self) -> None:
        assert receipt_store_dir() == Path.home() / ".merkl" / "receipts"

    async def test_the_environment_overrides_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MERKL_RECEIPT_DIR", "/tmp/merkl-receipts-test")
        assert receipt_store_dir() == Path("/tmp/merkl-receipts-test")

    async def test_an_explicit_path_wins_over_both(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MERKL_RECEIPT_DIR", "/tmp/ignored")
        assert receipt_store_dir(Path("/tmp/explicit")) == Path("/tmp/explicit")
