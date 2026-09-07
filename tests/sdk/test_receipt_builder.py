"""ReceiptBuilder: the order of the flow, and the join into a session."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome, escalation_challenge
from merkl.sdk.decorators import reset_current_session, set_current_session
from merkl.sdk.receipts import ReceiptBuildError
from merkl.shared.hashing import canonical_hash
from tests.scenarios.harness import approvals_for, build_rig

pytestmark = pytest.mark.asyncio


class RecordingSession:
    """Just enough of SessionContext to see what the builder committed."""

    def __init__(self, session_id: str = "01936b2e-1111-7000-8000-0001") -> None:
        self.session_id = session_id
        self.actions: list[dict[str, Any]] = []

    @property
    def action_count(self) -> int:
        return len(self.actions)

    async def record_action(self, **kwargs: Any) -> dict[str, Any]:
        leaf_index = len(self.actions)
        self.actions.append(kwargs)
        return {"action_id": f"action-{len(self.actions)}", "leaf_index": leaf_index}


class TestSessionJoin:
    async def test_a_settled_payment_becomes_one_transaction_action(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        session = RecordingSession()
        token = set_current_session(session)
        try:
            outcome = await rig.builder.execute(
                instruction=rig.instruction(),
                intent=rig.intent(),
                reasoning=rig.reasoning(),
                depends_on="human-input-action-1",
            )
        finally:
            reset_current_session(token)

        assert len(session.actions) == 1
        action = session.actions[0]
        assert action["action_type"] == "transaction"
        assert action["tool_name"] == "fake.payment"
        assert action["guardrail_result"] == "passed"
        assert action["status"] == "success"
        assert action["depends_on"] == ["human-input-action-1"]
        assert outcome.action_id == "action-1"

    async def test_the_action_input_hash_is_the_envelope_hash(self, tmp_path: Path) -> None:
        """That equality is what makes the receipt a member of the session tree."""
        rig = build_rig(tmp_path)
        session = RecordingSession()
        token = set_current_session(session)
        try:
            outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        finally:
            reset_current_session(token)
        recorded = canonical_hash(session.actions[0]["input_data"])
        assert recorded.hex() == outcome.receipt.envelope_hash().hex()

    async def test_the_envelope_carries_a_session_locator_the_notary_can_resolve(
        self, tmp_path: Path
    ) -> None:
        """Without this, merkl-api's ``_link_session`` has nothing to join on.

        The locator names where the envelope hash actually landed — this
        session, at the leaf index the action is about to get — so the notary
        can find the action a stored receipt claims to belong to
        (``docs/INTERFACES-P4.md`` sec 2, ``StoreReceiptService._link_session``).
        """
        rig = build_rig(tmp_path)
        session = RecordingSession()
        token = set_current_session(session)
        try:
            # A prior action already occupies leaf 0, as a real session's
            # human_input action would before a payment is proposed.
            await session.record_action(tool_name="human_input", input_data="pay it")
            outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        finally:
            reset_current_session(token)

        locator = outcome.receipt.envelope.session_locator
        assert locator is not None
        assert locator.session_id == session.session_id
        assert locator.leaf_index == 1  # the transaction is the second action
        assert session.actions[1]["input_data"]["session_locator"] == {
            "session_id": session.session_id,
            "leaf_index": 1,
        }
        # The locator is inside the envelope that was hashed, not bolted on after.
        recorded = canonical_hash(session.actions[1]["input_data"])
        assert recorded.hex() == outcome.receipt.envelope_hash().hex()

    async def test_a_denial_is_recorded_as_a_blocked_action(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        session = RecordingSession()
        token = set_current_session(session)
        try:
            outcome = await rig.builder.execute(
                instruction=rig.instruction("drain it"),
                intent=rig.intent(
                    value="90000.00", destination="rATTACKER0000000000000000000000000"
                ),
            )
        finally:
            reset_current_session(token)
        action = session.actions[0]
        assert action["guardrail_result"] == "blocked"
        assert action["status"] == "blocked"
        assert outcome.outcome == PolicyOutcome.DENY.value

    async def test_no_session_means_no_join_and_no_error(self, tmp_path: Path) -> None:
        """The join is optional and one-way: a notary that is down cannot stop a payment."""
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert outcome.action_id is None
        assert outcome.settled


class TestBindingChecks:
    async def test_it_refuses_to_submit_when_the_rail_changes_the_bytes(
        self, tmp_path: Path
    ) -> None:
        """The caller's own check that the transaction is the one that was signed."""
        rig = build_rig(tmp_path)
        real_prepare = rig.rail.prepare
        calls = {"n": 0}

        async def drifting_prepare(intent, commitment, **_context):
            unsigned = await real_prepare(intent, commitment, **_context)
            calls["n"] += 1
            if calls["n"] == 1:
                return unsigned
            payload = bytearray(unsigned.payload_bytes)
            payload[0] ^= 0xFF
            return dataclasses.replace(unsigned, signing_payload=bytes(payload).hex())

        rig.rail.prepare = drifting_prepare  # type: ignore[method-assign]
        with pytest.raises(ReceiptBuildError, match="differs from the bytes"):
            await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())

    async def test_the_reservation_is_released_when_it_refuses(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        real_prepare = rig.rail.prepare
        calls = {"n": 0}

        async def drifting_prepare(intent, commitment, **_context):
            unsigned = await real_prepare(intent, commitment, **_context)
            calls["n"] += 1
            if calls["n"] == 1:
                return unsigned
            payload = bytearray(unsigned.payload_bytes)
            payload[0] ^= 0xFF
            return dataclasses.replace(unsigned, signing_payload=bytes(payload).hex())

        rig.rail.prepare = drifting_prepare  # type: ignore[method-assign]
        with pytest.raises(ReceiptBuildError):
            await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert rig.engine._state.snapshot().entries == ()


class TestSignerIsTheAuthority:
    async def test_the_builder_cannot_pass_a_decision_in(self, tmp_path: Path) -> None:
        """If this ever becomes possible, the policy authority has moved to the caller."""
        import inspect

        from merkl.sdk.receipts import ReceiptBuilder

        signature = inspect.signature(ReceiptBuilder.execute)
        assert "decision" not in signature.parameters
        assert "outcome" not in signature.parameters
        assert "tier" not in signature.parameters

    async def test_the_proposal_carries_the_placeholder_not_a_commitment(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        seen: list[str] = []
        real_propose = rig.signer.propose

        async def watching(request):
            seen.append(request["params"]["prepared_tx"]["commitment"])
            return await real_propose(request)

        rig.signer.propose = watching  # type: ignore[method-assign]
        await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert seen == [ANCHOR_PLACEHOLDER_HEX]


class TestPendingEscalation:
    """What a caller needs to open a human queue entry from a still-pending
    decision — nothing in the receipt's own leaves names the challenge until
    it resolves (RECEIPT-SPEC.md), so ``execute()`` hands it over separately."""

    async def test_an_unresolved_escalation_carries_challenge_expiry_and_quorum(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        intent = rig.intent(value="600.00")  # over the 500.00 human threshold
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=intent)

        assert outcome.outcome == "escalate"
        pending = outcome.pending_escalation
        assert pending is not None
        assert pending["challenge"] == escalation_challenge(outcome.receipt.leaves).hex()
        assert pending["quorum"] == 2  # the default rig policy's human tier
        assert isinstance(pending["expires_at"], str)

    async def test_a_denial_carries_no_pending_escalation(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(
            instruction=rig.instruction("drain it"),
            intent=rig.intent(value="90000.00", destination="rATTACKER0000000000000000000000000"),
        )
        assert outcome.outcome == "deny"
        assert outcome.pending_escalation is None

    async def test_a_settled_payment_carries_no_pending_escalation(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        outcome = await rig.builder.execute(instruction=rig.instruction(), intent=rig.intent())
        assert outcome.settled
        assert outcome.pending_escalation is None

    async def test_resuming_to_a_settlement_clears_the_pending_escalation(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        instruction = rig.instruction()
        intent = rig.intent(value="600.00")
        pending = await rig.builder.execute(instruction=instruction, intent=intent)
        challenge = escalation_challenge(pending.receipt.leaves).hex()
        decision = await rig.signer.approve(
            challenge, approvals_for(challenge, at=rig.clock.now())
        )

        outcome = await rig.builder.resume(
            instruction=instruction, intent=intent, decision=decision
        )
        assert outcome.settled
        assert outcome.pending_escalation is None


class TestResume:
    """Picking a payment back up after its decision was reached elsewhere.

    ``approve``/``reject`` decide once: the signer drops its pending
    escalation the moment one caller's assertion completes the quorum
    (docs/SIGNER-RPC.md §4), so a notary relaying a human's approval through
    its own API is often that caller, not this process. ``resume()`` is how
    the agent finishes the same flow ``execute()`` would have, from the raw
    decision such a relay hands back.
    """

    async def test_an_out_of_band_allow_settles(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        instruction = rig.instruction()
        intent = rig.intent(value="600.00")  # over the 500.00 human threshold
        pending = await rig.builder.execute(instruction=instruction, intent=intent)
        assert pending.outcome == "escalate"

        # The challenge is a pure function of the pending receipt's own
        # leaves — a caller never needs the escalate response's own copy of
        # it, which is exactly the position a resumed flow is in.
        challenge = escalation_challenge(pending.receipt.leaves).hex()

        # Someone else's relay reaches the signer directly; resume() never
        # does, and gets nothing but the raw result to work from.
        decision = await rig.signer.approve(
            challenge, approvals_for(challenge, at=rig.clock.now())
        )
        assert decision["outcome"] == "allow"

        outcome = await rig.builder.resume(
            instruction=instruction, intent=intent, decision=decision
        )
        assert outcome.settled
        assert outcome.receipt.leaves.result.outcome == "settled"
        escalation = outcome.receipt.leaves.policy_decision.escalation
        assert escalation is not None
        assert len(escalation.approvals) == 2

    async def test_an_out_of_band_deny_still_files_a_receipt(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        instruction = rig.instruction()
        intent = rig.intent(value="600.00")
        pending = await rig.builder.execute(instruction=instruction, intent=intent)
        challenge = escalation_challenge(pending.receipt.leaves).hex()

        decision = await rig.signer.reject(
            challenge, approvals_for(challenge, at=rig.clock.now())[:1]
        )
        assert decision["outcome"] == "deny"

        outcome = await rig.builder.resume(
            instruction=instruction, intent=intent, decision=decision
        )
        assert not outcome.settled
        assert outcome.receipt.leaves.result.outcome == "denied"

    async def test_resume_joins_the_session_the_same_way_execute_does(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        instruction = rig.instruction()
        intent = rig.intent(value="600.00")
        pending = await rig.builder.execute(instruction=instruction, intent=intent)
        challenge = escalation_challenge(pending.receipt.leaves).hex()
        decision = await rig.signer.approve(
            challenge, approvals_for(challenge, at=rig.clock.now())
        )

        session = RecordingSession()
        token = set_current_session(session)
        try:
            outcome = await rig.builder.resume(
                instruction=instruction, intent=intent, decision=decision
            )
        finally:
            reset_current_session(token)

        assert len(session.actions) == 1
        locator = outcome.receipt.envelope.session_locator
        assert locator is not None
        assert locator.session_id == session.session_id
