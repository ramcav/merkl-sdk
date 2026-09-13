"""What a trade cost, read out of the ledger's own metadata.

A receipt that copied the intent's ceiling into its settled facts would prove
nothing about the ledger. These are the two derivations that make ``spent`` and
``delivered`` evidence rather than restatement, held against real XRPL metadata
shapes — an AccountRoot balance change for XRP, a RippleState line for an issued
asset, sign-corrected for which side of the line the treasury holds.

No network. The live proof is the opt-in testnet run.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.models.response import Response, ResponseStatus, ResponseType

from merkl.adapters.xrpl import history
from merkl.adapters.xrpl.adapter import amount_from_xrpl, delivered_amount, spent_amount
from merkl.core.intent import Amount, IssuedCurrency

TREASURY = "rK8ZsqAcfkNoFzJQhApwb8Do4GhJ1nFxiy"
ISSUER = "r4CXXMKNR7rwFkpTuWafNREL5SPmhkaV1r"
RLUSD_HEX = "524C555344000000000000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer=ISSUER)


def account_root(before: str, after: str, account: str = TREASURY) -> dict[str, Any]:
    return {
        "ModifiedNode": {
            "LedgerEntryType": "AccountRoot",
            "FinalFields": {"Account": account, "Balance": after},
            "PreviousFields": {"Balance": before},
        }
    }


def ripple_state(before: str, after: str, *, treasury_is_low: bool) -> dict[str, Any]:
    low, high = (TREASURY, ISSUER) if treasury_is_low else (ISSUER, TREASURY)
    return {
        "ModifiedNode": {
            "LedgerEntryType": "RippleState",
            "FinalFields": {
                "Balance": {"currency": RLUSD_HEX, "issuer": "r" + "r" * 32, "value": after},
                "LowLimit": {"currency": RLUSD_HEX, "issuer": low, "value": "0"},
                "HighLimit": {"currency": RLUSD_HEX, "issuer": high, "value": "1000000000"},
            },
            "PreviousFields": {
                "Balance": {"currency": RLUSD_HEX, "issuer": "r" + "r" * 32, "value": before}
            },
        }
    }


class TestDelivered:
    def test_it_reads_the_metadata_and_not_the_request(self) -> None:
        meta = {"delivered_amount": "1000000000"}
        assert delivered_amount(meta) == Amount(value="1000", currency="XRP")

    def test_an_issued_delivery_comes_back_with_its_readable_code(self) -> None:
        meta = {"delivered_amount": {"currency": RLUSD_HEX, "issuer": ISSUER, "value": "250"}}
        assert delivered_amount(meta) == Amount(value="250", currency=RLUSD)

    def test_metadata_that_does_not_say_yields_nothing(self) -> None:
        assert delivered_amount({}) is None
        assert delivered_amount(None) is None

    def test_a_malformed_amount_yields_nothing_rather_than_a_guess(self) -> None:
        assert amount_from_xrpl({"currency": RLUSD_HEX}) is None
        assert amount_from_xrpl("not drops") is None


class TestSpent:
    def test_xrp_comes_off_the_account_root_with_the_fee_removed(self) -> None:
        """A fee is not part of the trade. Counting it would overstate the price."""
        meta = {"AffectedNodes": [account_root("100000000", "50000000")]}
        assert spent_amount(meta, TREASURY, Decimal(30)) == Amount(
            value="49.99997", currency="XRP"
        )

    def test_another_account_s_balance_change_is_not_the_treasury_s(self) -> None:
        meta = {"AffectedNodes": [account_root("100000000", "50000000", account=ISSUER)]}
        assert spent_amount(meta, TREASURY, Decimal(30)) is None

    def test_an_issued_asset_comes_off_the_trust_line_the_treasury_paid_from(self) -> None:
        meta = {"AffectedNodes": [ripple_state("1000", "507.5", treasury_is_low=True)]}
        assert spent_amount(meta, TREASURY, Decimal(30)) == Amount(value="492.5", currency=RLUSD)

    def test_the_high_side_of_a_line_is_sign_corrected(self) -> None:
        """A line's Balance is the low account's holding; the high account's is its negation.

        Without the correction a sale reads as a purchase, which is the one
        mistake that would put the wrong number on a receipt and still look
        plausible.
        """
        meta = {"AffectedNodes": [ripple_state("-1000", "-507.5", treasury_is_low=False)]}
        assert spent_amount(meta, TREASURY, Decimal(30)) == Amount(value="492.5", currency=RLUSD)

    def test_a_line_that_grew_is_not_a_cost(self) -> None:
        meta = {"AffectedNodes": [ripple_state("500", "1000", treasury_is_low=True)]}
        assert spent_amount(meta, TREASURY, Decimal(0)) is None

    def test_metadata_without_the_nodes_yields_nothing(self) -> None:
        assert spent_amount({}, TREASURY, Decimal(0)) is None
        assert spent_amount({"AffectedNodes": "not a list"}, TREASURY, Decimal(0)) is None
        assert spent_amount(None, TREASURY, Decimal(0)) is None


def _response(monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]) -> None:
    async def fake_request(self: AsyncJsonRpcClient, request: Any) -> Response:
        return Response(status=ResponseStatus.SUCCESS, result=result, type=ResponseType.RESPONSE)

    monkeypatch.setattr(AsyncJsonRpcClient, "request", fake_request)


def _self_payment(**overrides: Any) -> dict[str, Any]:
    tx: dict[str, Any] = {
        "TransactionType": "Payment",
        "Account": TREASURY,
        "Destination": TREASURY,
        "Amount": "1000000000",
        "SendMax": {"currency": RLUSD_HEX, "issuer": ISSUER, "value": "500"},
        "Fee": "30",
    }
    tx.update(overrides)
    return {
        "account": TREASURY,
        "transactions": [
            {
                "hash": "AB" * 32,
                "ledger_index": 94_211_402,
                "close_time_iso": "2026-01-02T03:21:12Z",
                "tx_json": tx,
                "meta": {
                    "TransactionResult": "tesSUCCESS",
                    "delivered_amount": "1000000000",
                    "AffectedNodes": [ripple_state("1000", "507.5", treasury_is_low=True)],
                },
            }
        ],
    }


@pytest.mark.asyncio
class TestHistoryReadsATradeAsATrade:
    async def test_the_outflow_is_the_sell_side_actually_spent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _response(monkeypatch, _self_payment())
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        assert len(outflows) == 1
        outflow = outflows[0]
        assert outflow.value == "492.5"
        assert outflow.asset == f"RLUSD.{ISSUER}"
        assert outflow.is_swap

    async def test_the_delivered_amount_comes_back_as_the_inflow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _response(monkeypatch, _self_payment())
        outflow = (await history(TREASURY, json_rpc_url="https://example.invalid"))[0]
        assert outflow.inflow_value == "1000"
        assert outflow.inflow_asset == "XRP"

    async def test_send_max_stands_in_when_the_cost_cannot_be_derived(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An upper bound never understates an outflow, and that is the failure that matters."""
        result = _self_payment()
        result["transactions"][0]["meta"]["AffectedNodes"] = []
        _response(monkeypatch, result)
        outflow = (await history(TREASURY, json_rpc_url="https://example.invalid"))[0]
        assert outflow.value == "500"
        assert outflow.asset == f"RLUSD.{ISSUER}"

    async def test_a_plain_payment_is_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = _self_payment(Destination="rhCbJaTnphB8wuYDT6ksStRPZ1oNEAw8A9")
        del result["transactions"][0]["tx_json"]["SendMax"]
        _response(monkeypatch, result)
        outflow = (await history(TREASURY, json_rpc_url="https://example.invalid"))[0]
        assert outflow.value == "1000"
        assert outflow.asset == "XRP"
        assert outflow.inflow_value is None
        assert not outflow.is_swap

    async def test_a_self_payment_with_no_send_max_is_not_a_trade(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _self_payment()
        del result["transactions"][0]["tx_json"]["SendMax"]
        _response(monkeypatch, result)
        outflow = (await history(TREASURY, json_rpc_url="https://example.invalid"))[0]
        assert not outflow.is_swap
        assert outflow.value == "1000"
