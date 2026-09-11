"""``HttpNotary``: the two routes, the two bodies, and what a refusal does.

``docs/INTERFACES-P4.md`` section 2 is normative for both bodies. These assert
the wire shapes rather than the adapter's internals, because the shapes are the
contract with merkl-api and the internals are not.
"""

from __future__ import annotations

import json

import httpx
import pytest

from merkl.adapters.notary import HttpNotary, NotaryError
from merkl.core.rail import SettlementProof
from merkl.core.receipt import Envelope, ReceiptLeaves
from merkl.core.vectors import VECTORS_DIR

pytestmark = pytest.mark.asyncio

RECEIPTS = json.loads((VECTORS_DIR / "receipts.json").read_text())["cases"]


def _receipt() -> tuple[Envelope, ReceiptLeaves]:
    """The committed `allow-settled` vector — a real receipt, not a stand-in."""
    case = next(c for c in RECEIPTS if c["name"] == "allow-settled")
    return Envelope.from_content(case["envelope"]), ReceiptLeaves.from_contents(case["leaves"])


def _proof() -> SettlementProof:
    return SettlementProof(
        rail="xrpl",
        tx_hash="AB" * 32,
        ledger_index=20546663,
        ledger_hash="CD" * 32,
        captured=("ledger_header", "transaction"),
        missing=("shamap_path",),
    )


def _notary(handler: object, **kwargs: object) -> tuple[HttpNotary, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)  # type: ignore[operator]

    client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    return HttpNotary("http://notary.test/", client=client, **kwargs), seen  # type: ignore[arg-type]


class TestFilingAReceipt:
    async def test_the_proof_rides_along_in_the_same_request(self) -> None:
        """One round trip, not two — and never a receipt whose proof got lost."""
        notary, seen = _notary(lambda _: httpx.Response(201, json={}))
        envelope, leaves = _receipt()

        await notary.file_receipt(envelope, leaves, settlement_proof=_proof())

        assert len(seen) == 1
        request = seen[0]
        assert str(request.url) == "http://notary.test/v1/receipts"
        body = json.loads(request.content)
        assert body["envelope"] == envelope.to_content()
        assert len(body["leaves"]) == 7
        assert body["settlement_proof"]["rail"] == "xrpl"
        assert body["settlement_proof"]["proof"]["tx_hash"] == "AB" * 32
        assert body["settlement_proof"]["proof"]["missing"] == ["shamap_path"]

    async def test_a_receipt_with_no_proof_sends_no_member_rather_than_a_null(self) -> None:
        """An absent member is absent. A null would read as "there was none"."""
        notary, seen = _notary(lambda _: httpx.Response(201, json={}))
        envelope, leaves = _receipt()

        await notary.file_receipt(envelope, leaves)

        assert "settlement_proof" not in json.loads(seen[0].content)

    async def test_an_open_challenge_rides_along_too(self) -> None:
        """The only way the notary can learn this receipt is waiting on a person."""
        notary, seen = _notary(lambda _: httpx.Response(201, json={}))
        envelope, leaves = _receipt()

        await notary.file_receipt(
            envelope,
            leaves,
            pending_escalation={
                "challenge": "ab" * 32,
                "expires_at": "2026-09-10T12:00:00Z",
                "quorum": 2,
            },
        )

        body = json.loads(seen[0].content)
        assert body["pending_escalation"] == {
            "challenge": "ab" * 32,
            "expires_at": "2026-09-10T12:00:00Z",
            "quorum": 2,
        }
        assert "settlement_proof" not in body, "an escalated receipt has settled nothing"

    async def test_a_receipt_with_no_escalation_sends_no_member_rather_than_a_null(self) -> None:
        notary, seen = _notary(lambda _: httpx.Response(201, json={}))
        envelope, leaves = _receipt()

        await notary.file_receipt(envelope, leaves, settlement_proof=_proof())

        assert "pending_escalation" not in json.loads(seen[0].content)

    async def test_the_api_key_goes_in_the_header_merkl_api_reads(self) -> None:
        notary, seen = _notary(lambda _: httpx.Response(201, json={}), api_key="mk_test")
        envelope, leaves = _receipt()

        await notary.file_receipt(envelope, leaves)

        assert seen[0].headers["X-Merkl-API-Key"] == "mk_test"

    async def test_a_refusal_names_the_status_and_the_route(self) -> None:
        notary, _ = _notary(lambda _: httpx.Response(422, text="leaves must be seven"))
        envelope, leaves = _receipt()

        with pytest.raises(NotaryError) as raised:
            await notary.file_receipt(envelope, leaves)
        assert "422" in str(raised.value)
        assert "/v1/receipts" in str(raised.value)

    async def test_an_unreachable_notary_is_a_notary_error_not_an_httpx_one(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        notary, _ = _notary(refuse)
        envelope, leaves = _receipt()

        with pytest.raises(NotaryError) as raised:
            await notary.file_receipt(envelope, leaves)
        assert "could not be reached" in str(raised.value)


class TestFilingALateProof:
    async def test_it_goes_to_the_receipts_own_route(self) -> None:
        notary, seen = _notary(lambda _: httpx.Response(201, json={}))

        await notary.file_settlement_proof("01a07969-bcd5-7e37-b01b-90b057ef8d94", _proof())

        assert str(seen[0].url) == (
            "http://notary.test/v1/receipts/01a07969-bcd5-7e37-b01b-90b057ef8d94/settlement-proof"
        )
        body = json.loads(seen[0].content)
        assert body == {"rail": "xrpl", "proof": _proof().to_content()}

    async def test_a_refusal_of_a_late_proof_raises_too(self) -> None:
        notary, _ = _notary(lambda _: httpx.Response(404, text="no such receipt"))

        with pytest.raises(NotaryError):
            await notary.file_settlement_proof("rcp-missing", _proof())
