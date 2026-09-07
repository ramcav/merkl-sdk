"""Rule state: immutable, sequenced, and impossible to spend twice."""

from __future__ import annotations

from decimal import Decimal

import pytest

from merkl.core.canonical import shift_instant
from merkl.core.policy.state import (
    LedgerState,
    NonceEntry,
    Outflow,
    SpendEntry,
    SpendStatus,
    StateError,
    reconcile,
)

NOW = "2026-01-02T03:00:00Z"
TREASURY = "rTREASURY0000000000000000000000000"


def entry(reservation_id: str = "r1", value: str = "250.00", at: str = NOW, **kw) -> SpendEntry:
    return SpendEntry(
        reservation_id=reservation_id,
        agent_id=kw.pop("agent_id", "agent-ap"),
        asset=kw.pop("asset", "RLUSD.rISSUER"),
        value=value,
        at=at,
        **kw,
    )


class TestSequence:
    def test_every_mutation_advances_the_sequence(self) -> None:
        state = LedgerState(treasury=TREASURY)
        assert state.sequence == 0
        state = state.with_reservation(entry())
        assert state.sequence == 1
        state = state.with_settlement("r1", "TX1")
        assert state.sequence == 2

    def test_a_mutation_returns_a_new_value(self) -> None:
        state = LedgerState(treasury=TREASURY)
        after = state.with_reservation(entry())
        assert state.entries == ()
        assert len(after.entries) == 1

    def test_a_reservation_id_cannot_be_reused(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        with pytest.raises(StateError, match="already exists"):
            state.with_reservation(entry())

    def test_a_nonce_cannot_be_reused(self) -> None:
        nonce = NonceEntry(agent_id="agent-ap", nonce="n1", expires_at=shift_instant(NOW, 600))
        state = LedgerState(treasury=TREASURY).with_nonce(nonce)
        with pytest.raises(StateError, match="already used"):
            state.with_nonce(nonce)


class TestWindow:
    def test_reservations_count_from_the_moment_they_exist(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        total = state.view().spent_within(
            agent_id="agent-ap", asset="RLUSD.rISSUER", since=shift_instant(NOW, -60), until=NOW
        )
        assert total == Decimal("250.00")

    def test_settling_relabels_rather_than_counting_again(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        settled = state.with_settlement("r1", "TX1")
        window = {
            "agent_id": "agent-ap",
            "asset": "RLUSD.rISSUER",
            "since": shift_instant(NOW, -60),
            "until": NOW,
        }
        assert settled.view().spent_within(**window) == state.view().spent_within(**window)
        assert settled.entry("r1").status == SpendStatus.SETTLED.value

    def test_releasing_removes_the_amount(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        released = state.with_release("r1")
        assert released.view().spent_within(
            agent_id="agent-ap", asset="RLUSD.rISSUER", since=shift_instant(NOW, -60), until=NOW
        ) == Decimal(0)

    def test_a_settled_reservation_cannot_be_released(self) -> None:
        """Money that moved cannot be un-counted; that is the whole limit."""
        state = (
            LedgerState(treasury=TREASURY).with_reservation(entry()).with_settlement("r1", "TX1")
        )
        with pytest.raises(StateError, match="settled"):
            state.with_release("r1")


class TestPruning:
    def test_old_entries_and_expired_nonces_are_forgotten(self) -> None:
        state = (
            LedgerState(treasury=TREASURY)
            .with_reservation(entry("old", at=shift_instant(NOW, -90000)))
            .with_reservation(entry("recent", at=NOW))
            .with_nonce(
                NonceEntry(agent_id="a", nonce="stale", expires_at=shift_instant(NOW, -10))
            )
            .with_nonce(NonceEntry(agent_id="a", nonce="live", expires_at=shift_instant(NOW, 10)))
        )
        pruned = state.pruned(now=NOW, keep_seconds=86400)
        assert [e.reservation_id for e in pruned.entries] == ["recent"]
        assert [n.nonce for n in pruned.nonces] == ["live"]
        assert pruned.sequence > state.sequence

    def test_pruning_nothing_does_not_advance_the_sequence(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        assert state.pruned(now=NOW, keep_seconds=86400) is state


class TestSnapshot:
    def test_state_round_trips_through_json(self) -> None:
        state = (
            LedgerState(treasury=TREASURY)
            .with_reservation(entry(commitment="ab" * 32))
            .with_settlement("r1", "TX1")
            .with_nonce(NonceEntry(agent_id="a", nonce="n", expires_at=NOW))
        )
        assert LedgerState.from_content(state.to_content()) == state


class TestReconciliation:
    def outflow(self, tx_hash: str, anchor: str | None = None) -> Outflow:
        return Outflow(
            tx_hash=tx_hash,
            treasury=TREASURY,
            destination="rSUPPLIER0000000000000000000000000",
            value="250.00",
            asset="RLUSD.rISSUER",
            ledger_index=1,
            close_time=NOW,
            anchor=anchor,
        )

    def test_a_settled_reservation_matches_its_transaction(self) -> None:
        state = (
            LedgerState(treasury=TREASURY).with_reservation(entry()).with_settlement("r1", "TX1")
        )
        report = reconcile(state, [self.outflow("TX1")])
        assert report.clean
        assert report.matched == ("TX1",)

    def test_an_outflow_matches_by_anchor_when_the_hash_was_never_recorded(self) -> None:
        """Survives a crash between submitting and recording: the memo identifies it."""
        state = LedgerState(treasury=TREASURY).with_reservation(entry(commitment="ab" * 32))
        report = reconcile(state, [self.outflow("TX9", anchor="ab" * 32)])
        assert report.clean
        assert report.unsettled_reservations == ()

    def test_an_outflow_nobody_authorized_is_reported(self) -> None:
        state = LedgerState(treasury=TREASURY)
        report = reconcile(state, [self.outflow("TXUNKNOWN")])
        assert not report.clean
        assert report.stale_snapshot
        assert report.unmatched_outflows == ("TXUNKNOWN",)

    def test_a_reservation_the_rail_has_not_seen_is_reported_separately(self) -> None:
        state = LedgerState(treasury=TREASURY).with_reservation(entry())
        report = reconcile(state, [])
        assert report.clean, "an unsettled reservation is not an unauthorized outflow"
        assert report.unsettled_reservations == ("r1",)
