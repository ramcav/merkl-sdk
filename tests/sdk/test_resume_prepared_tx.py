"""Resuming an escalation in a process that never prepared the payment.

The bug, in one sentence: ``_settle`` prepared the transaction *again*, the rail
autofilled it from the ledger as it is now, and the bytes no longer matched the
ones the policy key signed minutes earlier — so a payment a person had just
approved was refused with ``the anchored transaction differs from the bytes the
policy key signed``. Inside one process ``execute`` never noticed, because every
adapter memoises its autofill against the intent's nonce; across processes there
is nothing to memoise.

The fix keeps the bytes instead of rebuilding them. What is *not* relaxed is the
comparison: whether the transaction came from a fresh ``prepare`` or from
recorded content, it is submitted only if it is byte-identical to what the signer
signed. These tests hold that line from both sides — a rail whose autofill has
moved on still settles, and a tampered record still does not.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from merkl.core.rail import UnsignedTx
from merkl.core.receipt import PolicyOutcome
from merkl.sdk.receipts import ReceiptBuildError
from tests.scenarios.harness import approvals_for, build_rig

pytestmark = pytest.mark.asyncio

NOT_THE_SIGNED_BYTES = "differs from the bytes the policy key signed"
"""The refusal that is the last word, whichever road produced the transaction."""


class DriftingRail:
    """A rail that forgets, the way a fresh process does.

    Wraps the in-memory adapter and drops its memoised sequence between the
    propose and the resume, so the second ``prepare`` autofills afresh — exactly
    what the XRPL adapter does against a ledger that has closed thirty blocks
    since somebody was asked to approve something.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.prepares = 0
        self.rebuilds = 0

    def forget(self) -> None:
        self._inner._sequences.clear()

    async def prepare(self, intent: Any, commitment: str, **context: Any) -> UnsignedTx:
        self.prepares += 1
        return await self._inner.prepare(intent, commitment, **context)

    async def anchored_from_content(self, content: dict[str, Any], commitment: str) -> UnsignedTx:
        self.rebuilds += 1
        return await self._inner.anchored_from_content(content, commitment)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


async def escalate(rig: Any) -> Any:
    """One payment over the human threshold, left waiting."""
    outcome = await rig.builder.execute(
        instruction=rig.instruction(), intent=rig.intent(value="900.00")
    )
    assert outcome.outcome == PolicyOutcome.ESCALATE.value
    return outcome


class TestWhatThePendingOutcomeCarries:
    async def test_an_escalating_outcome_hands_back_the_prepared_transaction(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        outcome = await escalate(rig)

        assert outcome.prepared_tx is not None
        rebuilt = UnsignedTx.from_content(outcome.prepared_tx)
        assert rebuilt.commitment == "00" * 32, "still the placeholder; it authorizes nothing"
        assert rebuilt.treasury == rig.policy.treasury

    async def test_a_settled_payment_carries_none(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert outcome.settled
        assert outcome.prepared_tx is None

    async def test_a_denied_payment_carries_none(self, tmp_path: Path) -> None:
        """It is over. The transaction it would have been is not worth keeping."""
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(destination="rSTRANGER")
        )
        assert outcome.outcome == PolicyOutcome.DENY.value
        assert outcome.prepared_tx is None


class TestResumingAcrossTheDrift:
    async def test_a_rail_that_has_moved_on_still_settles_the_approved_payment(
        self, tmp_path: Path
    ) -> None:
        """The regression, end to end."""
        rig = build_rig(tmp_path)
        rail = DriftingRail(rig.rail)
        rig = dataclasses.replace(rig, rail=rail)
        rig.builder._rail = rail

        pending = await escalate(rig)
        challenge = pending.pending_escalation["challenge"]
        rail.forget()  # a new process, a new ledger

        decision = rig.engine.approve(
            challenge,
            [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())],
            pending.prepared_tx,
        )
        outcome = await rig.builder.resume(
            instruction=rig.instruction(),
            intent=rig.intent(value="900.00"),
            decision=decision,
            prepared_tx=pending.prepared_tx,
        )

        assert outcome.settled, outcome.reason
        assert rail.rebuilds == 1, "it rebuilt rather than prepared"

    async def test_without_it_the_same_resume_is_refused(self, tmp_path: Path) -> None:
        """The bug itself, pinned — so nobody quietly removes the argument."""
        rig = build_rig(tmp_path)
        rail = DriftingRail(rig.rail)
        rig = dataclasses.replace(rig, rail=rail)
        rig.builder._rail = rail

        pending = await escalate(rig)
        challenge = pending.pending_escalation["challenge"]
        rail.forget()

        decision = rig.engine.approve(
            challenge,
            [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())],
            pending.prepared_tx,
        )
        with pytest.raises(ReceiptBuildError, match=NOT_THE_SIGNED_BYTES):
            await rig.builder.resume(
                instruction=rig.instruction(), intent=rig.intent(value="900.00"), decision=decision
            )

    async def test_a_rail_that_has_not_drifted_is_unaffected_either_way(
        self, tmp_path: Path
    ) -> None:
        """Today's behaviour, kept: no ``prepared_tx``, same process, still settles."""
        rig = build_rig(tmp_path)
        pending = await escalate(rig)
        challenge = pending.pending_escalation["challenge"]

        decision = rig.engine.approve(
            challenge,
            [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())],
            pending.prepared_tx,
        )
        outcome = await rig.builder.resume(
            instruction=rig.instruction(), intent=rig.intent(value="900.00"), decision=decision
        )
        assert outcome.settled

    async def test_a_tampered_prepared_tx_is_refused_rather_than_submitted(
        self, tmp_path: Path
    ) -> None:
        """The equality check is still the last word, whichever road got here."""
        rig = build_rig(tmp_path)
        pending = await escalate(rig)
        challenge = pending.pending_escalation["challenge"]
        decision = rig.engine.approve(
            challenge,
            [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())],
            pending.prepared_tx,
        )

        tampered = dict(pending.prepared_tx)
        payload = bytearray(bytes.fromhex(str(tampered["signing_payload"])))
        payload[0] ^= 0xFF  # one bit, outside the anchor
        tampered["signing_payload"] = bytes(payload).hex()

        with pytest.raises(ReceiptBuildError, match=NOT_THE_SIGNED_BYTES):
            await rig.builder.resume(
                instruction=rig.instruction(),
                intent=rig.intent(value="900.00"),
                decision=decision,
                prepared_tx=tampered,
            )

    async def test_a_prepared_tx_from_a_different_payment_is_refused(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        pending = await escalate(rig)
        challenge = pending.pending_escalation["challenge"]
        decision = rig.engine.approve(
            challenge,
            [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())],
            pending.prepared_tx,
        )
        somebody_else = await rig.rail.prepare(rig.intent(value="11.00"), "00" * 32)

        with pytest.raises(ReceiptBuildError, match=NOT_THE_SIGNED_BYTES):
            await rig.builder.resume(
                instruction=rig.instruction(),
                intent=rig.intent(value="900.00"),
                decision=decision,
                prepared_tx=somebody_else.to_content(),
            )
