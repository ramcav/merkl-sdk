"""The wallet-free XRPL history helper — read-only rail history for the notary.

``merkl.adapters.xrpl.history`` is the module-level counterpart to
``XrplSettlementAdapter.history``: it never touches a wallet or a signing key,
because the caller — the merkl-api notary, in particular — must never hold
one. Both share exactly one parser (``_outflows_from_response`` in
``merkl.adapters.xrpl.adapter``), so this file is mostly proof that the
wallet-free path reads the ledger the same way the wallet-holding one does.

The fixture is a real, trimmed ``account_tx`` response recorded from XRPL
testnet against the treasury the demo scenarios use — public ledger data
only, no seed or private key anywhere in it. No network here; the opt-in
network test lives in ``tests/scenarios/test_xrpl_testnet.py``
(``MERKL_XRPL_TESTNET=1``), where it also checks that this helper agrees with
the adapter's own ``history()`` against the live ledger.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.models.response import Response, ResponseStatus, ResponseType

from merkl.adapters.xrpl import history

pytestmark = pytest.mark.asyncio

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "xrpl_account_tx.json").read_text())
TREASURY = FIXTURE["result"]["account"]

# The two outgoing Payments in the fixture, oldest first by ledger_index.
HASH_OLDER = "B291EE73BC558EA105CAD4DA1A3FE1C5C330AEB3451AF1C343FE2A9A93DCC897"
HASH_NEWER = "C83A860F31EDAE52CBE8EC1BA44881BE1C8D65CC0A6CF8D2104D50F1761795D5"
ANCHOR_NEWER = "de13cdc45cc9c2de5c1c63189b895b631ef8b9c0697f8f3a1839aac2e08e77df"


def _mock_request(
    monkeypatch: pytest.MonkeyPatch, result: dict[str, Any] = FIXTURE["result"]
) -> None:
    async def fake_request(self: AsyncJsonRpcClient, request: Any) -> Response:
        return Response(status=ResponseStatus.SUCCESS, result=result, type=ResponseType.RESPONSE)

    monkeypatch.setattr(AsyncJsonRpcClient, "request", fake_request)


class TestHistoryIsWalletFree:
    async def test_the_helper_takes_no_wallet_or_key_argument(self) -> None:
        import inspect

        params = inspect.signature(history).parameters
        assert set(params) == {"treasury", "since", "json_rpc_url", "ledger_index_min"}

    async def test_the_module_never_imports_a_wallet_or_signing_type(self) -> None:
        import merkl.adapters.xrpl.adapter as module

        source = Path(module.__file__).read_text()
        # The class that needs one is fine; the free function must not.
        history_source = source[source.index("async def history(") :]
        assert "Wallet" not in history_source
        assert "sign(" not in history_source


class TestHistoryFromARecordedResponse:
    async def test_only_outgoing_successful_payments_from_the_treasury_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_request(monkeypatch)
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        assert {o.tx_hash for o in outflows} == {HASH_OLDER, HASH_NEWER}
        assert all(o.treasury == TREASURY for o in outflows)

    async def test_an_accountset_and_an_incoming_payment_are_excluded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fixture also carries an AccountSet and a payment *into* the treasury."""
        _mock_request(monkeypatch)
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        assert len(outflows) == 2

    async def test_the_amount_is_a_decimal_string_in_xrp_not_drops(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_request(monkeypatch)
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        newer = next(o for o in outflows if o.tx_hash == HASH_NEWER)
        assert newer.value == "1"
        assert newer.asset == "XRP"
        assert newer.destination == "rUrkGPnQ26cUHGQRFqCs5Dh8zw8tyoycyZ"

    async def test_the_merkl_memo_is_read_back_as_the_anchor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_request(monkeypatch)
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        newer = next(o for o in outflows if o.tx_hash == HASH_NEWER)
        assert newer.anchor == ANCHOR_NEWER

    async def test_close_time_falls_back_to_ripple_time_when_no_iso_field(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This recorded response has no close_time_iso — every entry uses `date`."""
        _mock_request(monkeypatch)
        outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        assert all(o.close_time.endswith("Z") for o in outflows)

    async def test_since_filters_out_the_older_payment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_request(monkeypatch)
        all_outflows = await history(TREASURY, json_rpc_url="https://example.invalid")
        older = next(o for o in all_outflows if o.tx_hash == HASH_OLDER)
        newer = next(o for o in all_outflows if o.tx_hash == HASH_NEWER)
        assert older.close_time < newer.close_time

        recent_only = await history(
            TREASURY, newer.close_time, json_rpc_url="https://example.invalid"
        )
        assert {o.tx_hash for o in recent_only} == {HASH_NEWER}

    async def test_a_treasury_with_no_matching_transactions_is_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _mock_request(monkeypatch)
        outflows = await history("rSOMEONEELSE0000000000000000000000", json_rpc_url="https://x")
        assert outflows == []


class TestHistoryBound:
    """`ledger_index_min` bounds the account_tx read; unbounded reads -1."""

    async def test_the_bound_reaches_account_tx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        async def fake_request(self: AsyncJsonRpcClient, request: Any) -> Response:
            seen["ledger_index_min"] = request.ledger_index_min
            return Response(
                status=ResponseStatus.SUCCESS,
                result={"transactions": []},
                type=ResponseType.RESPONSE,
            )

        monkeypatch.setattr(AsyncJsonRpcClient, "request", fake_request)

        await history(TREASURY, json_rpc_url="https://xrpl.example", ledger_index_min=94211337)

        assert seen["ledger_index_min"] == 94211337

    async def test_no_bound_reads_as_far_back_as_the_node_has(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, object] = {}

        async def fake_request(self: AsyncJsonRpcClient, request: Any) -> Response:
            seen["ledger_index_min"] = request.ledger_index_min
            return Response(
                status=ResponseStatus.SUCCESS,
                result={"transactions": []},
                type=ResponseType.RESPONSE,
            )

        monkeypatch.setattr(AsyncJsonRpcClient, "request", fake_request)

        await history(TREASURY, json_rpc_url="https://xrpl.example")

        assert seen["ledger_index_min"] == -1
