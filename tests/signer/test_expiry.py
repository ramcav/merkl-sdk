"""An escalation nobody answers gives its reservation back when it expires.

An escalation reserves its amount against the window when it is raised, and
``approve``/``reject`` used to be the only things that released it. One that
simply expired therefore counted forever, and every later proposal failed its
window cap. The engine now sweeps expired escalations at the start of every
``propose``, ``approve``, ``reject`` and ``health``, and on demand
(``sweep_expired``, which the notary follower calls on each poll).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from merkl.core.canonical import shift_instant
from merkl.core.rail import ANCHOR_PLACEHOLDER_HEX
from merkl.core.receipt import PolicyOutcome
from merkl.signer.auth import sign_request
from merkl.signer.server import RpcRouter
from tests.scenarios.harness import AGENT, AGENT_ID, Rig, approvals_for, build_rig

pytestmark = pytest.mark.asyncio

ESCALATION_SECONDS = 3600


async def _propose(rig: Rig, value: str) -> dict:  # type: ignore[type-arg]
    intent = rig.intent(value=value)
    unsigned = await rig.rail.prepare(intent, ANCHOR_PLACEHOLDER_HEX)
    request = sign_request(
        method="propose",
        agent_id=AGENT_ID,
        nonce="n-" + rig.clock.now() + value,
        expires_at=shift_instant(rig.clock.now(), 300),
        params={
            "instruction": rig.instruction("pay the retainer").to_content(),
            "intent": intent.to_content(),
            "prepared_tx": unsigned.to_content(),
        },
        agent_public_key=AGENT.public_key,
        sign=AGENT.sign,
    )
    return rig.engine.propose(request.to_content())


class TestSweep:
    async def test_a_reservation_is_released_after_expiry_with_no_call(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        await _propose(rig, "900.00")
        assert len(rig.engine._pending) == 1
        before = rig.engine.health()["state_sequence"]

        rig.clock.advance(ESCALATION_SECONDS + 1)
        assert rig.engine.sweep_expired() == 1

        assert len(rig.engine._pending) == 0
        assert rig.engine._state.sequence > before, "the release was persisted"

    async def test_nothing_is_swept_before_it_expires(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        await _propose(rig, "900.00")
        rig.clock.advance(ESCALATION_SECONDS - 1)
        assert rig.engine.sweep_expired() == 0
        assert len(rig.engine._pending) == 1

    async def test_the_window_no_longer_counts_an_expired_escalation(self, tmp_path: Path) -> None:
        """Window is 2500: two 900s fit, a third (2700) does not — until one expires."""
        rig = build_rig(tmp_path)
        await _propose(rig, "900.00")
        rig.clock.advance(1)
        await _propose(rig, "900.00")
        rig.clock.advance(1)
        refused = await _propose(rig, "900.00")
        assert refused["outcome"] == PolicyOutcome.DENY.value, "2700 > the 2500 window"

        rig.clock.advance(ESCALATION_SECONDS)  # the first two lapse; propose sweeps
        allowed = await _propose(rig, "900.00")
        assert allowed["outcome"] == PolicyOutcome.ESCALATE.value

    async def test_health_sweeps_too(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        await _propose(rig, "900.00")
        rig.clock.advance(ESCALATION_SECONDS + 1)
        assert rig.engine.health()["pending_escalations"] == 0

    async def test_approving_an_expired_escalation_is_still_refused_as_expired(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        challenge = str((await _propose(rig, "900.00"))["challenge"])
        rig.clock.advance(ESCALATION_SECONDS + 1)
        rig.engine.sweep_expired()  # already gone from the pending map

        decision = rig.engine.approve(
            challenge, [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())]
        )

        assert decision["outcome"] == PolicyOutcome.DENY.value
        assert "expired" in decision["detail"]

    async def test_approving_an_expired_one_that_was_never_swept_is_refused_too(
        self, tmp_path: Path
    ) -> None:
        rig = build_rig(tmp_path)
        challenge = str((await _propose(rig, "900.00"))["challenge"])
        rig.clock.advance(ESCALATION_SECONDS + 1)
        decision = rig.engine.approve(
            challenge, [a.to_content() for a in approvals_for(challenge, at=rig.clock.now())]
        )
        assert "expired" in decision["detail"]

    async def test_the_router_exposes_the_sweep(self, tmp_path: Path) -> None:
        rig = build_rig(tmp_path)
        await _propose(rig, "900.00")
        rig.clock.advance(ESCALATION_SECONDS + 1)
        assert RpcRouter(rig.engine).dispatch_local("sweep_expired", {}) == {"swept": 1}
