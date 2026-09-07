"""The policy engine: deterministic, exhaustive, and a denial is a decision."""

from __future__ import annotations

from decimal import Decimal

import pytest

from merkl.core.canonical import shift_instant
from merkl.core.intent import Amount, Intent, IssuedCurrency, Reference, SwapBuy, SwapSell
from merkl.core.policy.document import (
    AgentSection,
    ApproverCredential,
    AssetLimit,
    HumanTier,
    PolicyDocument,
    ReferenceBinding,
    RiskRule,
    Tiers,
    WindowRule,
    asset_key,
)
from merkl.core.policy.engine import (
    RULE_ASSET,
    RULE_DESTINATION,
    RULE_INTENT_EXPIRY,
    RULE_MAY_SWAP,
    RULE_ORDER,
    RULE_PER_TX_CAP,
    RULE_POLICY_VERSION,
    RULE_REFERENCE,
    RULE_RISK,
    RULE_TIER,
    RULE_TREASURY,
    RULE_WINDOW,
    RiskScore,
    evaluate,
)
from merkl.core.policy.state import SpendEntry, StateView
from merkl.core.receipt import PolicyDecision
from merkl.core.vectors import fixtures

NOW = "2026-01-02T03:00:00Z"
TREASURY = "rTREASURY0000000000000000000000000"
SUPPLIER = "rSUPPLIER0000000000000000000000000"
ATTACKER = "rATTACKER0000000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")
AGENT_KEY = fixtures.ed25519_public_hex(fixtures.ed25519_key("engine-agent"))
INVOICE = "a" * 64


def policy(**overrides) -> PolicyDocument:
    section = AgentSection(
        agent_id="agent-ap",
        public_key=AGENT_KEY,
        allowlist_destinations=(SUPPLIER,),
        allowlist_assets=(RLUSD,),
        per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
        windows=(WindowRule(asset=RLUSD, amount="2500.00", seconds=86400),),
        reference_binding=ReferenceBinding(
            required=True, allowed_kinds=("invoice",), hashes=(INVOICE,)
        ),
    )
    fields = {
        "version": "2026.01.0",
        "treasury": TREASURY,
        "rail": "xrpl",
        "agents": (overrides.pop("section", section),),
        "admin_public_key": "ab" * 32,
        "tiers": Tiers(
            human=HumanTier(
                thresholds=(AssetLimit(asset=RLUSD, amount="500.00"),),
                quorum=2,
                expires_seconds=3600,
            )
        ),
        "risk": RiskRule(threshold="0.75"),
        "approvers": (
            ApproverCredential(
                id="alice",
                credential_type="ed25519",
                public_key=fixtures.ed25519_public_hex(fixtures.ed25519_key("engine-alice")),
            ),
            ApproverCredential(
                id="bob",
                credential_type="ed25519",
                public_key=fixtures.ed25519_public_hex(fixtures.ed25519_key("engine-bob")),
            ),
        ),
    }
    fields.update(overrides)
    return PolicyDocument(**fields)


def intent(**overrides) -> Intent:
    fields = {
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": SUPPLIER,
        "amount": Amount(value="250.00", currency=RLUSD),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT_KEY,
        "nonce": "0123456789abcdef",
        "expires_at": shift_instant(NOW, 600),
        "reference": Reference(kind="invoice", id="INV-1", hash=INVOICE),
    }
    fields.update(overrides)
    return Intent(**fields)


def view(*entries: SpendEntry) -> StateView:
    return StateView(treasury=TREASURY, entries=entries)


def decide(**overrides):
    given_policy = overrides.pop("policy", None) or policy()
    state = overrides.pop("state", None) or view()
    risk = overrides.pop("risk", None) or RiskScore()
    now = overrides.pop("now", NOW)
    return evaluate(intent(**overrides), given_policy, state, risk, now)


def outcome_of(decision, name: str) -> str:
    return next(r.outcome for r in decision.rules if r.name == name)


class TestDeterminism:
    def test_the_same_inputs_give_the_same_decision(self) -> None:
        assert decide().to_content() == decide().to_content()

    def test_the_decision_serialises_as_receipt_leaf_two(self) -> None:
        decision = decide()
        assert PolicyDecision.from_content(decision.to_content()).to_content() == (
            decision.to_content()
        )

    def test_rules_run_in_the_documented_order(self) -> None:
        names = [r.name for r in decide().rules]
        assert names == [n for n in RULE_ORDER if n in names]


class TestAllow:
    def test_a_clean_payment_is_allowed_on_the_instant_tier(self) -> None:
        decision = decide()
        assert decision.allowed
        assert decision.tier == "instant"
        assert decision.reservation is not None
        assert decision.reservation.asset == asset_key(RLUSD)
        assert decision.reservation.value == "250.00"


class TestDeny:
    def test_a_denial_is_a_decision_not_an_exception(self) -> None:
        decision = decide(destination=ATTACKER)
        assert decision.denied
        assert decision.rules
        assert decision.reservation is None
        assert outcome_of(decision, RULE_DESTINATION) == "fail"

    @pytest.mark.parametrize(
        ("overrides", "rule"),
        [
            ({"destination": ATTACKER}, RULE_DESTINATION),
            ({"amount": Amount(value="5000.00", currency=RLUSD)}, RULE_PER_TX_CAP),
            ({"amount": Amount(value="250.00", currency="XRP")}, RULE_ASSET),
            ({"policy_version": "1999.01.0"}, RULE_POLICY_VERSION),
            ({"treasury": ATTACKER}, RULE_TREASURY),
            ({"reference": None}, RULE_REFERENCE),
            (
                {"reference": Reference(kind="invoice", id="INV-1", hash="b" * 64)},
                RULE_REFERENCE,
            ),
            ({"reference": Reference(kind="receipt", id="INV-1", hash=INVOICE)}, RULE_REFERENCE),
        ],
    )
    def test_each_rule_can_deny(self, overrides: dict, rule: str) -> None:
        decision = decide(**overrides)
        assert decision.denied, decision.reason()
        assert outcome_of(decision, rule) == "fail"

    def test_an_expired_intent_is_denied(self) -> None:
        decision = decide(now=shift_instant(NOW, 3600))
        assert decision.denied
        assert outcome_of(decision, RULE_INTENT_EXPIRY) == "fail"

    def test_risk_at_the_threshold_denies(self) -> None:
        decision = decide(risk=RiskScore(value="0.75", source="screening"))
        assert decision.denied
        assert outcome_of(decision, RULE_RISK) == "fail"

    def test_an_asset_with_no_cap_is_denied_rather_than_unlimited(self) -> None:
        section = AgentSection(
            agent_id="agent-ap",
            public_key=AGENT_KEY,
            allowlist_destinations=(SUPPLIER,),
            allowlist_assets=(RLUSD,),
            per_tx_cap=(),
        )
        decision = decide(policy=policy(section=section))
        assert decision.denied
        assert outcome_of(decision, RULE_PER_TX_CAP) == "fail"

    def test_an_agent_the_policy_does_not_know_is_denied(self) -> None:
        decision = decide(agent_public_key="cd" * 32)
        assert decision.denied
        assert decision.reservation is None


class TestWindow:
    def _entry(self, value: str, at: str) -> SpendEntry:
        return SpendEntry(
            reservation_id=f"r-{value}-{at}",
            agent_id="agent-ap",
            asset=asset_key(RLUSD),
            value=value,
            at=at,
        )

    def test_in_flight_reservations_count(self) -> None:
        state = view(*(self._entry("800.00", shift_instant(NOW, -60 * i)) for i in range(3)))
        decision = decide(state=state, amount=Amount(value="200.00", currency=RLUSD))
        assert decision.denied
        assert outcome_of(decision, RULE_WINDOW) == "fail"
        assert "in-flight" in next(r.detail for r in decision.rules if r.name == RULE_WINDOW)

    def test_spend_outside_the_window_does_not_count(self) -> None:
        state = view(*(self._entry("800.00", shift_instant(NOW, -90000)) for _ in range(3)))
        assert decide(state=state).allowed

    def test_the_window_is_exact_at_its_boundary(self) -> None:
        state = view(self._entry("2250.00", shift_instant(NOW, -10)))
        assert decide(state=state, amount=Amount(value="250.00", currency=RLUSD)).allowed
        assert decide(state=state, amount=Amount(value="250.01", currency=RLUSD)).denied

    def test_another_agent_spends_from_its_own_window(self) -> None:
        entry = SpendEntry(
            reservation_id="other",
            agent_id="agent-payroll",
            asset=asset_key(RLUSD),
            value="2500.00",
            at=NOW,
        )
        assert decide(state=view(entry)).allowed

    def test_no_window_rule_is_reported_as_skipped_not_passed(self) -> None:
        section = AgentSection(
            agent_id="agent-ap",
            public_key=AGENT_KEY,
            allowlist_destinations=(SUPPLIER,),
            allowlist_assets=(RLUSD,),
            per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
            reference_binding=ReferenceBinding(),
        )
        decision = decide(policy=policy(section=section), reference=None)
        assert outcome_of(decision, RULE_WINDOW) == "skip"


class TestEscalation:
    def test_at_the_threshold_it_escalates(self) -> None:
        decision = decide(amount=Amount(value="500.00", currency=RLUSD))
        assert decision.escalated
        assert decision.tier == "human"
        assert outcome_of(decision, RULE_TIER) == "escalate"

    def test_the_escalation_carries_quorum_and_an_expiry(self) -> None:
        decision = decide(amount=Amount(value="900.00", currency=RLUSD))
        assert decision.escalation is not None
        assert decision.escalation.quorum == 2
        assert decision.escalation.expires_at == shift_instant(NOW, 3600)

    def test_an_escalated_payment_still_reserves(self) -> None:
        """Otherwise five parallel escalations each see an empty window."""
        decision = decide(amount=Amount(value="900.00", currency=RLUSD))
        assert decision.reservation is not None
        assert Decimal(decision.reservation.value) == Decimal("900.00")

    def test_caps_apply_to_escalated_payments_too(self) -> None:
        decision = decide(amount=Amount(value="5000.00", currency=RLUSD))
        assert decision.denied, "over the per-tx cap is a denial, not an escalation"

    def test_no_threshold_for_the_asset_means_instant(self) -> None:
        decision = decide(policy=policy(tiers=Tiers(human=HumanTier())))
        assert decision.allowed
        assert decision.tier == "instant"


# --------------------------------------------------------------------------- #
# Trading (phase 14)
# --------------------------------------------------------------------------- #

XRP = "XRP"


def trading_section(**overrides) -> AgentSection:
    fields = {
        "agent_id": "agent-ap",
        "public_key": AGENT_KEY,
        "allowlist_destinations": (SUPPLIER,),
        "allowlist_assets": (RLUSD, XRP),
        "per_tx_cap": (AssetLimit(asset=RLUSD, amount="1000.00"),),
        "windows": (WindowRule(asset=RLUSD, amount="2500.00", seconds=86400),),
        "may_swap": True,
    }
    fields.update(overrides)
    return AgentSection(**fields)


def swap_intent(**overrides) -> Intent:
    fields = {
        "type": "swap",
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": TREASURY,
        "sell": SwapSell(currency=RLUSD, max_amount="250.00"),
        "buy": SwapBuy(currency=XRP, amount="500"),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT_KEY,
        "nonce": "0123456789abcdef",
        "expires_at": shift_instant(NOW, 600),
    }
    fields.update(overrides)
    return Intent(**fields)


def rule(decision, name: str):
    return next(r for r in decision.rules if r.name == name)


class TestMaySwap:
    def test_a_trade_by_an_agent_without_the_grant_is_denied(self) -> None:
        document = policy(section=trading_section(may_swap=False))
        decision = evaluate(swap_intent(), document, view(), RiskScore(), NOW)
        assert decision.denied
        assert rule(decision, RULE_MAY_SWAP).outcome == "fail"
        assert rule(decision, RULE_MAY_SWAP).detail == "agent may not trade"

    def test_the_grant_lets_the_same_trade_through(self) -> None:
        decision = evaluate(
            swap_intent(), policy(section=trading_section()), view(), RiskScore(), NOW
        )
        assert decision.allowed
        assert rule(decision, RULE_MAY_SWAP).outcome == "pass"

    def test_a_payment_skips_the_rule_entirely(self) -> None:
        decision = evaluate(intent(), policy(section=trading_section()), view(), RiskScore(), NOW)
        assert rule(decision, RULE_MAY_SWAP).outcome == "skip"
        assert rule(decision, RULE_MAY_SWAP).detail == "not a trade"

    def test_the_rule_runs_in_its_documented_position(self) -> None:
        decision = evaluate(
            swap_intent(), policy(section=trading_section()), view(), RiskScore(), NOW
        )
        names = [r.name for r in decision.rules]
        assert names.index(RULE_MAY_SWAP) < names.index(RULE_DESTINATION)
        assert set(names) <= set(RULE_ORDER)


class TestTradeRulesReadTheSellSide:
    def test_the_destination_allowlist_does_not_apply_to_a_trade(self) -> None:
        decision = evaluate(
            swap_intent(), policy(section=trading_section()), view(), RiskScore(), NOW
        )
        assert rule(decision, RULE_DESTINATION).outcome == "skip"

    def test_both_sides_of_a_trade_must_be_allowlisted(self) -> None:
        document = policy(section=trading_section())
        forbidden = swap_intent(
            buy=SwapBuy(currency=IssuedCurrency(code="EURC", issuer=TREASURY), amount="1")
        )
        decision = evaluate(forbidden, document, view(), RiskScore(), NOW)
        assert decision.denied
        assert rule(decision, RULE_ASSET).outcome == "fail"
        assert "EURC" in rule(decision, RULE_ASSET).detail

    def test_selling_an_asset_the_agent_may_not_hold_is_denied(self) -> None:
        section = trading_section(
            allowlist_assets=(XRP, IssuedCurrency(code="EURC", issuer=TREASURY)),
            per_tx_cap=(AssetLimit(asset=XRP, amount="1000.00"),),
            windows=(),
        )
        document = policy(section=section, tiers=Tiers(human=HumanTier(thresholds=())))
        decision = evaluate(swap_intent(), document, view(), RiskScore(), NOW)
        assert decision.denied
        assert rule(decision, RULE_ASSET).outcome == "fail"

    def test_the_cap_is_read_against_the_sell_ceiling(self) -> None:
        document = policy(section=trading_section())
        over = swap_intent(sell=SwapSell(currency=RLUSD, max_amount="1000.01"))
        decision = evaluate(over, document, view(), RiskScore(), NOW)
        assert decision.denied
        assert rule(decision, RULE_PER_TX_CAP).outcome == "fail"
        assert "1000.01 exceeds" in rule(decision, RULE_PER_TX_CAP).detail

    def test_a_big_buy_for_a_small_sell_is_not_capped(self) -> None:
        """The bought side is not an outflow. A cheap asset is not a large payment."""
        document = policy(section=trading_section())
        decision = evaluate(
            swap_intent(buy=SwapBuy(currency=XRP, amount="9999999")),
            document,
            view(),
            RiskScore(),
            NOW,
        )
        assert decision.allowed

    def test_the_window_counts_the_sell_ceiling(self) -> None:
        document = policy(section=trading_section())
        spent = SpendEntry(
            reservation_id="r-1",
            agent_id="agent-ap",
            asset=asset_key(RLUSD),
            value="2400.00",
            at=NOW,
        )
        decision = evaluate(swap_intent(), document, view(spent), RiskScore(), NOW)
        assert decision.denied
        assert rule(decision, RULE_WINDOW).outcome == "fail"

    def test_the_tier_threshold_escalates_on_the_sell_ceiling(self) -> None:
        document = policy(section=trading_section())
        decision = evaluate(
            swap_intent(sell=SwapSell(currency=RLUSD, max_amount="600.00")),
            document,
            view(),
            RiskScore(),
            NOW,
        )
        assert decision.escalated
        assert rule(decision, RULE_TIER).outcome == "escalate"

    def test_a_reservation_is_taken_in_the_sold_asset(self) -> None:
        decision = evaluate(
            swap_intent(), policy(section=trading_section()), view(), RiskScore(), NOW
        )
        assert decision.reservation is not None
        assert decision.reservation.asset == asset_key(RLUSD)
        assert decision.reservation.value == "250.00"

    def test_the_same_inputs_reach_the_same_decision(self) -> None:
        document = policy(section=trading_section())
        first = evaluate(swap_intent(), document, view(), RiskScore(), NOW)
        second = evaluate(swap_intent(), document, view(), RiskScore(), NOW)
        assert first.to_content() == second.to_content()
