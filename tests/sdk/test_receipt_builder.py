"""ReceiptBuilder: the order of the flow, and the join into a session."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome
from merkl.sdk.decorators import reset_current_session, set_current_session
from merkl.sdk.receipts import ReceiptBuildError
from merkl.shared.hashing import canonical_hash
from tests.scenarios.harness import build_rig

pytestmark = pytest.mark.asyncio


class RecordingSession:
    """Just enough of SessionContext to see what the builder committed."""

    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []

    async def record_action(self, **kwargs: Any) -> dict[str, Any]:
        self.actions.append(kwargs)
        return {"action_id": f"action-{len(self.actions)}", "leaf_index": len(self.actions) - 1}


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

        async def drifting_prepare(intent, commitment):
            unsigned = await real_prepare(intent, commitment)
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

        async def drifting_prepare(intent, commitment):
            unsigned = await real_prepare(intent, commitment)
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
