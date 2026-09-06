"""``reject`` — an escalation refused, and the refusal signed (plan D11).

A rejection is evidence. Somebody with standing to approve chose not to, and
that fact belongs in the record exactly as an approval does. An escalation that
simply stops being mentioned proves nothing about whether anyone looked at it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from merkl.core.canonical import shift_instant
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome
from merkl.signer.auth import sign_request
from merkl.signer.engine import SignerError
from merkl.signer.server import RpcRouter
from tests.scenarios.harness import AGENT, AGENT_ID, Rig, approvals_for, build_rig

pytestmark = pytest.mark.asyncio


async def _escalate(rig: Rig) -> str:
    """Propose one payment over the human threshold; the escalation stays pending.

    Deliberately not driven through ``ReceiptBuilder``: the builder resolves an
    escalation as it goes, and ``reject`` exists for the ones still waiting.
    """
    intent = rig.intent(value="900.00")
    unsigned = await rig.rail.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
    request = sign_request(
        method="propose",
        agent_id=AGENT_ID,
        nonce="n-" + rig.clock.now(),
        expires_at=shift_instant(rig.clock.now(), 300),
        params={
            "instruction": rig.instruction("pay the quarterly retainer").to_content(),
            "intent": intent.to_content(),
            "prepared_tx": unsigned.to_content(),
        },
        agent_public_key=AGENT.public_key,
        sign=AGENT.sign,
    )
    decision = rig.engine.propose(request.to_content())
    assert decision["outcome"] == PolicyOutcome.ESCALATE.value
    return str(decision["challenge"])


class TestReject:
    async def test_a_signed_rejection_denies_and_records_who_refused(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        assertions = [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())]

        decision = rig.engine.reject(challenge, assertions)

        assert decision["outcome"] == PolicyOutcome.DENY.value
        assert "rejected by" in decision["detail"]
        assert "alice@example.com" in decision["detail"]
        escalation = decision["decision"]["escalation"]
        assert escalation["challenge"] == challenge
        assert len(escalation["approvals"]) == 2, "the signed refusals are in leaf 2"

    async def test_the_reservation_is_released_rather_than_left_to_expire(
        self, tmp_path: Path
    ) -> None:
        """A window that stays full is a denial of service the approver did not intend."""
        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        before = rig.engine.health()["state_sequence"]
        rig.engine.reject(
            challenge, [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())]
        )
        assert rig.engine.health()["state_sequence"] > before

    async def test_an_unsigned_rejection_is_refused(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        with pytest.raises(SignerError, match="a rejection is signed"):
            rig.engine.reject(challenge, [])

    async def test_a_rejection_by_someone_the_policy_does_not_name_still_denies(
        self, tmp_path: Path
    ) -> None:
        """It denies — but the detail says no assertion verified, rather than naming a signer."""
        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        stranger = [
            {
                "approver_id": "mallory@example.com",
                "credential_type": "ed25519",
                "signature": "00" * 64,
                "signed_at": rig.clock.now(),
            }
        ]
        decision = rig.engine.reject(challenge, stranger)
        assert decision["outcome"] == PolicyOutcome.DENY.value
        assert "no assertion verifies" in decision["detail"]

    async def test_an_unknown_challenge_is_an_error_not_a_silent_deny(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        with pytest.raises(SignerError, match="no escalation is pending"):
            rig.engine.reject("ab" * 32, [])

    async def test_the_rpc_router_exposes_reject(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        router = RpcRouter(rig.engine)
        decision = router.dispatch(
            "reject",
            {
                "challenge": challenge,
                "assertions": [
                    a.to_content() for a in approvals_for(challenge, at=rig.clock.now())
                ],
            },
        )
        assert decision["outcome"] == PolicyOutcome.DENY.value

    async def test_the_dev_client_speaks_it_too(self, tmp_path: Path) -> None:
        from merkl.adapters.signer_dev.client import LocalSignerClient

        rig = build_rig(tmp_path)
        challenge = await _escalate(rig)
        client = LocalSignerClient(rig.engine)
        decision = await client.reject(challenge, approvals_for(challenge, at=rig.clock.now()))
        assert decision["outcome"] == PolicyOutcome.DENY.value
