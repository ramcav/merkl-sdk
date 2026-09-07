"""The policy engine — deterministic, pure, and the only thing that decides.

``evaluate`` is a function of its arguments and nothing else: the same intent,
policy, state view, risk score and instant always produce the same decision, down
to the order and wording of the rules. That is what makes a receipt re-runnable
by someone who was not there — hand them the policy document and the decision
leaf and they reach the same verdict or the receipt is wrong.

There is no model in this path (charter). There is no clock either: ``now`` is
passed in, so a decision can be replayed at the instant it was made.

A denial is a **decision**, not an exception (plan D14). It has rules, a verdict
and a receipt. Raising would lose all three, and a payment refused with no
evidence is indistinguishable from a payment that never happened.
"""

from __future__ import annotations

import dataclasses
import enum
from decimal import Decimal
from typing import Any, Final

from merkl.core.canonical import (
    JSONObject,
    decimal_string,
    parse_decimal,
    parse_instant,
    shift_instant,
)
from merkl.core.intent import Intent
from merkl.core.policy.document import (
    AgentSection,
    EscalationTier,
    PolicyDocument,
    asset_key,
)
from merkl.core.policy.state import StateView
from merkl.core.receipt import Escalation, PolicyDecision, PolicyOutcome, PolicyRule


class RuleOutcome(enum.StrEnum):
    """What one rule said. ``SKIP`` is a rule the policy did not configure."""

    PASS = "pass"
    FAIL = "fail"
    ESCALATE = "escalate"
    SKIP = "skip"


RULE_POLICY_VERSION: Final = "policy_version"
RULE_TREASURY: Final = "treasury"
RULE_AGENT_KNOWN: Final = "agent_known"
RULE_INTENT_EXPIRY: Final = "intent_expiry"
RULE_DESTINATION: Final = "destination_allowlist"
RULE_ASSET: Final = "asset_allowlist"
RULE_REFERENCE: Final = "reference_binding"
RULE_RISK: Final = "risk_score"
RULE_PER_TX_CAP: Final = "per_tx_cap"
RULE_WINDOW: Final = "window_cap"
RULE_TIER: Final = "tier_threshold"

RULE_ORDER: Final[tuple[str, ...]] = (
    RULE_POLICY_VERSION,
    RULE_TREASURY,
    RULE_AGENT_KNOWN,
    RULE_INTENT_EXPIRY,
    RULE_DESTINATION,
    RULE_ASSET,
    RULE_REFERENCE,
    RULE_RISK,
    RULE_PER_TX_CAP,
    RULE_WINDOW,
    RULE_TIER,
)
"""The order rules run in, which is the order they appear in the receipt."""


@dataclasses.dataclass(frozen=True)
class RiskScore:
    """A destination's risk, as a decimal string in ``[0, 1]``.

    A string, not a float: this number is compared to a policy threshold and then
    written into a receipt, and a payments system that rounds is a payments system
    that argues about the rounding later.
    """

    value: str = "0"
    source: str = "none"

    def __post_init__(self) -> None:
        decimal_string(self.value, "risk_score.value", positive=False)

    @property
    def decimal(self) -> Decimal:
        return parse_decimal(self.value, "risk_score.value")


@dataclasses.dataclass(frozen=True)
class ReservationRequest:
    """What the signer must reserve if it acts on this decision."""

    asset: str
    value: str
    at: str


@dataclasses.dataclass(frozen=True)
class EscalationRequest:
    """The challenge parameters for a decision that needs people (plan D11).

    The challenge digest itself is ``LEFT_pre`` and is not computed here: it needs
    leaves 0 and 3, which are the signer's business. The engine says *how many*
    approvals and *until when*.
    """

    quorum: int
    expires_at: str


@dataclasses.dataclass(frozen=True)
class Decision:
    """The signer's verdict, in the exact shape of receipt leaf 2.

    ``to_content()`` is byte-identical to the leaf's content, so the thing that
    decided and the thing that was committed can never drift apart.
    """

    policy_hash: str
    rules: tuple[PolicyRule, ...]
    outcome: str
    tier: str
    escalation: EscalationRequest | None = None
    reservation: ReservationRequest | None = None
    risk_score: RiskScore = dataclasses.field(default_factory=RiskScore)

    @property
    def allowed(self) -> bool:
        return self.outcome == PolicyOutcome.ALLOW.value

    @property
    def denied(self) -> bool:
        return self.outcome == PolicyOutcome.DENY.value

    @property
    def escalated(self) -> bool:
        return self.outcome == PolicyOutcome.ESCALATE.value

    @property
    def failed_rules(self) -> tuple[PolicyRule, ...]:
        return tuple(r for r in self.rules if r.outcome == RuleOutcome.FAIL.value)

    def reason(self) -> str:
        """One line naming why, for a log or an error message."""
        if self.failed_rules:
            return "; ".join(f"{r.name}: {r.detail}" for r in self.failed_rules)
        if self.escalated:
            return "; ".join(
                r.detail for r in self.rules if r.outcome == RuleOutcome.ESCALATE.value
            )
        return "every rule passed"

    def to_leaf(self, escalation: Escalation | None = None) -> PolicyDecision:
        """Receipt leaf 2. ``escalation`` carries the collected approvals, if any."""
        return PolicyDecision(
            policy_hash=self.policy_hash,
            rules=self.rules,
            outcome=self.outcome,
            tier=self.tier,
            escalation=escalation,
        )

    def to_content(self) -> JSONObject:
        return self.to_leaf().to_content()

    def finalised(self, *, outcome: str, rules: tuple[PolicyRule, ...] | None = None) -> Decision:
        """The same decision with a new verdict — an escalation that people resolved."""
        return dataclasses.replace(self, outcome=outcome, rules=rules or self.rules)


def _rule(name: str, outcome: RuleOutcome, detail: str) -> PolicyRule:
    return PolicyRule(name=name, outcome=outcome.value, detail=detail)


def _describe(currency: Any) -> str:
    return asset_key(currency)


def evaluate(
    intent: Intent,
    policy: PolicyDocument,
    state: StateView,
    risk_score: RiskScore,
    now: str,
) -> Decision:
    """Run every rule in order and return the decision.

    The agent is identified by the public key in the intent, looked up in the
    policy — never by a name the caller supplies. Leaf 1 therefore carries the
    key the decision was made against, and a request that swapped agent
    identities would be deciding under a key it does not hold.
    """
    policy_hash = policy.policy_hash()
    rules: list[PolicyRule] = []
    section = _section_for(policy, intent.agent_public_key)

    rules.append(_version_rule(intent, policy))
    rules.append(_treasury_rule(intent, policy))
    rules.append(_agent_rule(section, intent))
    rules.append(_expiry_rule(intent, now))

    if section is None:
        return _deny(policy_hash, rules, risk_score)

    rules.append(_destination_rule(intent, section))
    rules.append(_asset_rule(intent, section))
    rules.append(_reference_rule(intent, section))
    rules.append(_risk_rule(risk_score, policy))
    rules.append(_cap_rule(intent, section))
    rules.extend(_window_rules(intent, section, state, now))

    if any(r.outcome == RuleOutcome.FAIL.value for r in rules):
        return _deny(policy_hash, rules, risk_score)

    tier_rule, escalate = _tier_rule(intent, policy)
    rules.append(tier_rule)

    reservation = ReservationRequest(
        asset=asset_key(intent.amount.currency), value=intent.amount.value, at=now
    )
    if escalate:
        human = policy.tiers.human
        return Decision(
            policy_hash=policy_hash,
            rules=tuple(rules),
            outcome=PolicyOutcome.ESCALATE.value,
            tier=EscalationTier.HUMAN.value,
            escalation=EscalationRequest(
                quorum=human.quorum,
                expires_at=shift_instant(now, human.expires_seconds, "now"),
            ),
            reservation=reservation,
            risk_score=risk_score,
        )
    return Decision(
        policy_hash=policy_hash,
        rules=tuple(rules),
        outcome=PolicyOutcome.ALLOW.value,
        tier=EscalationTier.INSTANT.value,
        reservation=reservation,
        risk_score=risk_score,
    )


def _deny(policy_hash: str, rules: list[PolicyRule], risk_score: RiskScore) -> Decision:
    return Decision(
        policy_hash=policy_hash,
        rules=tuple(rules),
        outcome=PolicyOutcome.DENY.value,
        tier=EscalationTier.INSTANT.value,
        risk_score=risk_score,
    )


def _section_for(policy: PolicyDocument, agent_public_key: str) -> AgentSection | None:
    for section in policy.agents:
        if section.public_key == agent_public_key:
            return section
    return None


def _version_rule(intent: Intent, policy: PolicyDocument) -> PolicyRule:
    ok = intent.policy_version == policy.version
    return _rule(
        RULE_POLICY_VERSION,
        RuleOutcome.PASS if ok else RuleOutcome.FAIL,
        f"intent names policy {intent.policy_version}, signer holds {policy.version}",
    )


def _treasury_rule(intent: Intent, policy: PolicyDocument) -> PolicyRule:
    ok = intent.treasury == policy.treasury
    return _rule(
        RULE_TREASURY,
        RuleOutcome.PASS if ok else RuleOutcome.FAIL,
        (
            f"treasury {intent.treasury} is the one this policy governs"
            if ok
            else f"intent pays from {intent.treasury}, policy governs {policy.treasury}"
        ),
    )


def _agent_rule(section: AgentSection | None, intent: Intent) -> PolicyRule:
    if section is None:
        return _rule(
            RULE_AGENT_KNOWN,
            RuleOutcome.FAIL,
            f"no agent in this policy holds key {intent.agent_public_key[:16]}…",
        )
    return _rule(
        RULE_AGENT_KNOWN,
        RuleOutcome.PASS,
        f"key belongs to agent {section.agent_id}",
    )


def _expiry_rule(intent: Intent, now: str) -> PolicyRule:
    expired = parse_instant(now, "now") > parse_instant(intent.expires_at, "intent.expires_at")
    return _rule(
        RULE_INTENT_EXPIRY,
        RuleOutcome.FAIL if expired else RuleOutcome.PASS,
        (
            f"intent expired at {intent.expires_at}, now {now}"
            if expired
            else f"intent is valid until {intent.expires_at}"
        ),
    )


def _destination_rule(intent: Intent, section: AgentSection) -> PolicyRule:
    if not section.allowlist_destinations:
        return _rule(
            RULE_DESTINATION,
            RuleOutcome.FAIL,
            f"{section.agent_id} has no allowed destinations, so it may pay nobody",
        )
    ok = intent.destination in section.allowlist_destinations
    return _rule(
        RULE_DESTINATION,
        RuleOutcome.PASS if ok else RuleOutcome.FAIL,
        (
            f"{intent.destination} is on the allowlist"
            if ok
            else f"{intent.destination} is not on {section.agent_id}'s allowlist"
        ),
    )


def _asset_rule(intent: Intent, section: AgentSection) -> PolicyRule:
    currency = intent.amount.currency
    ok = section.allows_asset(currency)
    return _rule(
        RULE_ASSET,
        RuleOutcome.PASS if ok else RuleOutcome.FAIL,
        (
            f"{_describe(currency)} is an allowed asset"
            if ok
            else f"{_describe(currency)} is not an asset {section.agent_id} may move"
        ),
    )


def _reference_rule(intent: Intent, section: AgentSection) -> PolicyRule:
    binding = section.reference_binding
    reference = intent.reference
    if reference is None:
        if binding.required:
            return _rule(
                RULE_REFERENCE,
                RuleOutcome.FAIL,
                "this agent's payments must reference a document, and none was supplied",
            )
        return _rule(RULE_REFERENCE, RuleOutcome.SKIP, "no reference binding configured")
    if binding.allowed_kinds and reference.kind not in binding.allowed_kinds:
        return _rule(
            RULE_REFERENCE,
            RuleOutcome.FAIL,
            f"reference kind {reference.kind!r} is not one of {list(binding.allowed_kinds)}",
        )
    if binding.allowlist and reference.id not in binding.allowlist:
        return _rule(
            RULE_REFERENCE,
            RuleOutcome.FAIL,
            f"reference {reference.id!r} is not on the allowlist",
        )
    if binding.hashes:
        if reference.hash is None:
            return _rule(
                RULE_REFERENCE,
                RuleOutcome.FAIL,
                f"reference {reference.id!r} carries no document hash to match",
            )
        if reference.hash not in binding.hashes:
            return _rule(
                RULE_REFERENCE,
                RuleOutcome.FAIL,
                f"reference {reference.id!r} hashes to a document this policy does not know",
            )
    return _rule(
        RULE_REFERENCE,
        RuleOutcome.PASS,
        f"{reference.kind} {reference.id} satisfies the reference binding",
    )


def _risk_rule(risk_score: RiskScore, policy: PolicyDocument) -> PolicyRule:
    threshold = policy.risk.value
    over = risk_score.decimal >= threshold
    return _rule(
        RULE_RISK,
        RuleOutcome.FAIL if over else RuleOutcome.PASS,
        (
            f"risk {risk_score.value} ({risk_score.source}) is at or above "
            f"the threshold {policy.risk.threshold}"
            if over
            else f"risk {risk_score.value} ({risk_score.source}) is below "
            f"the threshold {policy.risk.threshold}"
        ),
    )


def _cap_rule(intent: Intent, section: AgentSection) -> PolicyRule:
    cap = section.cap_for(intent.amount.currency)
    if cap is None:
        return _rule(
            RULE_PER_TX_CAP,
            RuleOutcome.FAIL,
            f"no per-transaction cap for {_describe(intent.amount.currency)}; "
            "an asset with no cap has no limit, so this is a denial",
        )
    over = intent.amount.decimal > cap.value
    return _rule(
        RULE_PER_TX_CAP,
        RuleOutcome.FAIL if over else RuleOutcome.PASS,
        (
            f"{intent.amount.value} exceeds the per-transaction cap {cap.amount} "
            f"{_describe(cap.asset)}"
            if over
            else f"{intent.amount.value} is within the per-transaction cap {cap.amount} "
            f"{_describe(cap.asset)}"
        ),
    )


def _window_rules(
    intent: Intent, section: AgentSection, state: StateView, now: str
) -> list[PolicyRule]:
    windows = section.windows_for(intent.amount.currency)
    if not windows:
        return [_rule(RULE_WINDOW, RuleOutcome.SKIP, "no window rule for this asset")]
    key = asset_key(intent.amount.currency)
    rules: list[PolicyRule] = []
    for window in windows:
        since = shift_instant(now, -window.seconds, "now")
        used = state.spent_within(agent_id=section.agent_id, asset=key, since=since, until=now)
        projected = used + intent.amount.decimal
        over = projected > window.value
        rules.append(
            _rule(
                RULE_WINDOW,
                RuleOutcome.FAIL if over else RuleOutcome.PASS,
                (
                    f"{projected} in the last {window.seconds}s would exceed the "
                    f"{window.amount} {_describe(window.asset)} window "
                    f"({used} already authorized, including in-flight)"
                    if over
                    else f"{projected} of {window.amount} {_describe(window.asset)} "
                    f"in the last {window.seconds}s ({used} already authorized)"
                ),
            )
        )
    return rules


def _tier_rule(intent: Intent, policy: PolicyDocument) -> tuple[PolicyRule, bool]:
    threshold = policy.tiers.human.threshold_for(intent.amount.currency)
    if threshold is None:
        return (
            _rule(
                RULE_TIER,
                RuleOutcome.PASS,
                f"no human-approval threshold for {_describe(intent.amount.currency)}; "
                "instant tier",
            ),
            False,
        )
    escalate = intent.amount.decimal >= threshold.value
    return (
        _rule(
            RULE_TIER,
            RuleOutcome.ESCALATE if escalate else RuleOutcome.PASS,
            (
                f"{intent.amount.value} is at or above the human-approval threshold "
                f"{threshold.amount} {_describe(threshold.asset)}"
                if escalate
                else f"{intent.amount.value} is below the human-approval threshold "
                f"{threshold.amount} {_describe(threshold.asset)}"
            ),
        ),
        escalate,
    )
