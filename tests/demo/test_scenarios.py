"""The five demo scenarios, exercised through ``merkl.demo`` directly.

``tests/scenarios/test_scenarios.py`` already asserts the underlying behaviour
against its own rig. This module tests the *demo's* copy of that wiring: the
``require()`` helper actually raises when a scenario's story breaks (asserts
would silently disappear under ``python -O``), and every scenario's receipts
verify on their own terms, the way a stranger opening the page would check them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from merkl.core.receipt import CheckStatus, PolicyOutcome
from merkl.demo.rig import approvals_for
from merkl.demo.scenarios import (
    SCENARIOS,
    FakeEnvironment,
    ScenarioError,
    benign_payment,
    injection_drain,
    over_threshold_approval,
    reference_mismatch,
    require,
    run_all,
    run_scenario,
    structuring,
)


def _env(tmp_path: Path) -> FakeEnvironment:
    return FakeEnvironment(home=tmp_path)


def _assert_verifies(outcome: object, *, settled: bool) -> None:
    result = outcome.verify()  # type: ignore[attr-defined]
    assert result.failures == (), [(c.name, c.detail) for c in result.failures]
    deferred = {c.name for c in result.deferred}
    assert "signer.attestation" in deferred
    if settled:
        for name in (
            "policy.signature",
            "intent.matches_settled_fields",
            "settlement.anchor_equals_left",
            "settlement.signed_blob",
        ):
            check = result.get(name)
            assert check is not None and check.status is CheckStatus.PASS, name


class TestRequire:
    def test_a_true_condition_passes_quietly(self) -> None:
        require(True, "never raised")

    def test_a_false_condition_raises_scenario_error(self) -> None:
        with pytest.raises(ScenarioError, match="the story broke"):
            require(False, "the story broke")


class TestBenignPayment:
    pytestmark = pytest.mark.asyncio

    async def test_it_settles_and_the_receipt_verifies(self, tmp_path: Path) -> None:
        result = await benign_payment(_env(tmp_path))
        assert result.verdicts == ("allow",)
        (outcome,) = result.outcomes
        assert outcome.settled
        _assert_verifies(outcome, settled=True)


class TestInjectionDrain:
    pytestmark = pytest.mark.asyncio

    async def test_it_is_denied_and_the_refusal_verifies(self, tmp_path: Path) -> None:
        result = await injection_drain(_env(tmp_path))
        assert result.verdicts == ("deny",)
        (outcome,) = result.outcomes
        assert not outcome.settled
        _assert_verifies(outcome, settled=False)

    async def test_the_solo_signature_story_is_still_true(self, tmp_path: Path) -> None:
        """The scenario's own claim: the rail needs two signatures, not one."""
        from merkl.adapters.fake import FakeRailError
        from merkl.core.rail import Signature

        env = _env(tmp_path)
        rig = env.rig("solo-check")
        intent = rig.intent(value="250.00")
        unsigned = await rig.rail.prepare(intent, "0" * 64)
        partial = await rig.rail.agent_sign(unsigned)
        solo = await rig.rail.attach_policy_signature(
            partial, Signature(public_key="ab" * 32, signature="cd" * 64)
        )
        with pytest.raises(FakeRailError):
            await rig.rail.submit(solo)


class TestOverThresholdApproval:
    pytestmark = pytest.mark.asyncio

    async def test_two_of_three_settles_and_verifies(self, tmp_path: Path) -> None:
        result = await over_threshold_approval(_env(tmp_path))
        assert result.verdicts == ("allow",)
        (outcome,) = result.outcomes
        assert outcome.settled
        assert outcome.decision.escalation is not None
        assert len(outcome.decision.escalation.approvals) == 2
        _assert_verifies(outcome, settled=True)

    async def test_one_approval_is_not_a_quorum_and_the_scenario_says_so(
        self, tmp_path: Path
    ) -> None:
        """A broken story raises here rather than lying about what happened."""
        env = _env(tmp_path)
        rig = env.rig("under-quorum")

        class OneApprover:
            async def enqueue(self, escalation: object) -> None: ...

            async def collect(self, challenge: str) -> object:
                return approvals_for(challenge, at=rig.clock.now())[:1]

        rig.builder.approvals = OneApprover()
        outcome = await rig.builder.execute(
            instruction=rig.instruction(), intent=rig.intent(value=env.amounts.over_threshold)
        )
        assert outcome.outcome == PolicyOutcome.DENY.value


class TestStructuring:
    pytestmark = pytest.mark.asyncio

    async def test_the_window_trips_before_the_limit(self, tmp_path: Path) -> None:
        result = await structuring(_env(tmp_path))
        assert result.verdicts[-1] == "deny"
        assert all(v == "allow" for v in result.verdicts[:-1])
        for outcome in result.outcomes:
            _assert_verifies(outcome, settled=outcome.settled)


class TestReferenceMismatch:
    pytestmark = pytest.mark.asyncio

    async def test_the_wrong_invoice_is_denied_and_the_right_one_settles(
        self, tmp_path: Path
    ) -> None:
        result = await reference_mismatch(_env(tmp_path))
        assert result.verdicts == ("deny", "allow")
        wrong, right = result.outcomes
        _assert_verifies(wrong, settled=False)
        _assert_verifies(right, settled=True)


class TestRunAll:
    pytestmark = pytest.mark.asyncio

    async def test_all_five_run_and_agree_with_their_own_expectations(
        self, tmp_path: Path
    ) -> None:
        results = await run_all(_env(tmp_path))
        assert [r.name for r in results] == [s.name for s in SCENARIOS]

    async def test_run_scenario_raises_when_the_verdicts_disagree_with_the_story(
        self, tmp_path: Path
    ) -> None:
        """A scenario recorded as ``expect=("allow",)`` that actually denied is a bug."""
        from merkl.demo import scenarios as scenarios_module

        broken = scenarios_module.SCENARIOS[0]
        wrong_expectation = scenarios_module.Scenario(
            name=broken.name,
            title=broken.title,
            question=broken.question,
            run=broken.run,
            expect=("deny",),  # the benign payment always allows
        )
        with pytest.raises(ScenarioError, match="expected"):
            await run_scenario(wrong_expectation, _env(tmp_path))
