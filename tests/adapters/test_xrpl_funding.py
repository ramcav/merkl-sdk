"""Funding a mainnet treasury — the arithmetic, and the wait.

There is no faucet on mainnet, so ``merkl treasury init`` prints an address and
a number and then watches the ledger. Both halves are worth pinning: a minimum
that is wrong by an owner reserve strands a half-configured account, and a wait
that treats "the account does not exist" as "the balance is zero" would report
the wrong thing to somebody staring at a withdrawal screen.

No network here. The client is a fake that answers ``account_info`` from a
script, which is also what lets the sequence unfunded → underfunded → funded run
in a millisecond.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from merkl.adapters.xrpl.bootstrap import (
    DROPS_PER_XRP,
    Reserves,
    account_drops,
    await_funding,
    read_reserves,
)

MAINNET_RESERVES = Reserves(base=Decimal("1"), owner=Decimal("0.2"))


class FakeResponse:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result


class FakeClient:
    """One canned ``account_info`` answer per call, in order; the last one repeats."""

    def __init__(self, *balances: int | None, reserves: tuple[str, str] | None = None) -> None:
        self._balances = list(balances) or [None]
        self._reserves = reserves
        self.calls = 0

    async def request(self, request: Any) -> FakeResponse:
        self.calls += 1
        if self._reserves is not None and type(request).__name__ == "ServerInfo":
            base, owner = self._reserves
            ledger = {"reserve_base_xrp": base, "reserve_inc_xrp": owner}
            return FakeResponse({"info": {"validated_ledger": ledger}})
        balance = self._balances[min(self.calls - 1, len(self._balances) - 1)]
        if balance is None:
            return FakeResponse({"error": "actNotFound", "account": "r..."})
        return FakeResponse({"account_data": {"Balance": str(balance)}})


class TestTheArithmetic:
    def test_a_treasury_with_no_trust_lines_needs_base_plus_one_owner_plus_fees(self) -> None:
        assert MAINNET_RESERVES.minimum(0) == Decimal("2.2")

    def test_each_trust_line_adds_an_owner_reserve(self) -> None:
        assert MAINNET_RESERVES.minimum(2) == Decimal("2.6")

    def test_the_drops_form_is_the_same_number(self) -> None:
        assert MAINNET_RESERVES.minimum_drops(1) == int(Decimal("2.4") * DROPS_PER_XRP)

    def test_the_explanation_itemises_everything_in_the_total(self) -> None:
        rows = "\n".join(MAINNET_RESERVES.explain(2))
        assert "base reserve" in rows
        assert "signer list" in rows
        assert "trust lines           0.4 XRP  (2 x 0.2)" in rows
        assert "permanently locked" in rows
        assert "fund at least         2.6 XRP" in rows

    def test_no_trust_lines_means_no_trust_line_row(self) -> None:
        assert not any("trust lines" in row for row in MAINNET_RESERVES.explain(0))

    @pytest.mark.asyncio
    async def test_the_reserves_come_from_the_node_rather_than_a_remembered_number(self) -> None:
        client = FakeClient(reserves=("10", "2"))
        reserves = await read_reserves("https://example.invalid", client=client)
        assert reserves == Reserves(base=Decimal("10"), owner=Decimal("2"))


@pytest.mark.asyncio
class TestTheWait:
    async def test_an_account_the_ledger_has_never_heard_of_reads_as_none(self) -> None:
        assert await account_drops("rNOBODY", client=FakeClient(None)) is None

    async def test_a_funded_account_reads_its_drops(self) -> None:
        assert await account_drops("rSOMEBODY", client=FakeClient(25_000_000)) == 25_000_000

    async def test_it_waits_through_unfunded_and_underfunded_and_returns_the_balance(self) -> None:
        client = FakeClient(None, 1_000_000, 5_000_000)
        seen: list[int | None] = []
        naps: list[float] = []

        async def sleep(seconds: float) -> None:
            naps.append(seconds)

        balance = await await_funding(
            "rTREASURY",
            2_200_000,
            client=client,
            sleep=sleep,
            on_poll=seen.append,
            poll_seconds=5.0,
        )

        assert balance == 5_000_000
        assert seen == [None, 1_000_000], "it distinguishes 'no account' from 'not enough'"
        assert naps == [5.0, 5.0]

    async def test_a_node_that_raises_is_a_poll_that_reported_nothing(self) -> None:
        """The keys are already on disk. A hiccup must not end the run."""

        class Flaky(FakeClient):
            async def request(self, request: Any) -> FakeResponse:
                self.calls += 1
                if self.calls == 1:
                    raise TimeoutError("the node did not answer")
                return FakeResponse({"account_data": {"Balance": "9000000"}})

        seen: list[int | None] = []

        async def sleep(_seconds: float) -> None:
            return None

        balance = await await_funding(
            "rTREASURY", 2_200_000, client=Flaky(), sleep=sleep, on_poll=seen.append
        )
        assert balance == 9_000_000
        assert seen == [None]

    async def test_an_already_funded_account_never_sleeps(self) -> None:
        naps: list[float] = []

        async def sleep(seconds: float) -> None:  # pragma: no cover - must not run
            naps.append(seconds)

        assert await await_funding("r", 1, client=FakeClient(2), sleep=sleep) == 2
        assert naps == []
