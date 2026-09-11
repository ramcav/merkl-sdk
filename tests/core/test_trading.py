"""Trading: the intent shape, the grant, and the arithmetic that bounds a trade.

One file for the core half of phase 14, because the claims are one claim seen
from four sides: a trade's *outflow is its sell ceiling*, and everything that
bounds a payment bounds a trade by reading that one number.

The engine and codec halves live beside their own modules
(``tests/core/policy/test_engine.py``, ``tests/signer/test_payload_codec.py``);
what is here is the shape of a swap intent, the ``may_swap`` grant and the
policy_hash it must not disturb, and the settled facts a verifier holds a trade to.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.core.canonical import ContentError
from merkl.core.checks import CheckStatus
from merkl.core.intent import (
    INTENT_TYPE_SWAP,
    Amount,
    Intent,
    IntentError,
    IssuedCurrency,
    Reference,
    SwapBuy,
    SwapSell,
)
from merkl.core.leaf import receipt_leaf
from merkl.core.policy.document import (
    AgentSection,
    AssetLimit,
    PolicyDocument,
    PolicyError,
    unenforceable_rules,
)
from merkl.core.receipt import (
    CHECK_INTENT_MATCHES_SETTLED,
    BalanceDelta,
    Envelope,
    Instruction,
    PolicyDecision,
    PolicyRule,
    Receipt,
    ReceiptLeaves,
    Result,
    Settlement,
)
from merkl.core.vectors import fixtures
from merkl.core.verify.card import rate_string, receipt_card
from merkl.core.verify.receipt import verify_receipt

TREASURY = "rTREASURY0000000000000000000000000"
ISSUER = "rISSUER000000000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer=ISSUER)
AGENT_KEY = fixtures.ed25519_public_hex(fixtures.ed25519_key("trading-agent"))


def swap(**overrides: Any) -> Intent:
    fields: dict[str, Any] = {
        "type": INTENT_TYPE_SWAP,
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": TREASURY,
        "sell": SwapSell(currency=RLUSD, max_amount="500.00"),
        "buy": SwapBuy(currency="XRP", amount="1000"),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT_KEY,
        "nonce": "0123456789abcdef",
        "expires_at": "2026-01-02T03:04:05Z",
    }
    fields.update(overrides)
    return Intent(**fields)


def payment(**overrides: Any) -> Intent:
    fields: dict[str, Any] = {
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": "rSUPPLIER0000000000000000000000000",
        "amount": Amount(value="250.00", currency=RLUSD),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT_KEY,
        "nonce": "0123456789abcdef",
        "expires_at": "2026-01-02T03:04:05Z",
    }
    fields.update(overrides)
    return Intent(**fields)


class TestSwapIntentShape:
    def test_a_swap_carries_sell_and_buy_and_no_amount(self) -> None:
        content = swap().to_content()
        assert content["type"] == "swap"
        assert content["sell"] == {
            "currency": {"code": "RLUSD", "issuer": ISSUER},
            "max_amount": "500.00",
        }
        assert content["buy"] == {"currency": "XRP", "amount": "1000"}
        assert "amount" not in content

    def test_a_swap_with_an_amount_is_refused(self) -> None:
        with pytest.raises(IntentError, match="never amount"):
            swap(amount=Amount(value="1", currency=RLUSD))

    def test_a_swap_without_both_sides_is_refused(self) -> None:
        with pytest.raises(IntentError, match="requires sell and buy"):
            swap(buy=None)
        with pytest.raises(IntentError, match="requires sell and buy"):
            swap(sell=None)

    def test_a_payment_may_not_carry_sell_or_buy(self) -> None:
        with pytest.raises(IntentError, match="never sell or buy"):
            payment(sell=SwapSell(currency=RLUSD, max_amount="1"))

    def test_a_swap_sells_one_asset_and_buys_another(self) -> None:
        with pytest.raises(IntentError, match="on both sides"):
            swap(buy=SwapBuy(currency=RLUSD, amount="1000"))

    def test_a_swap_settles_to_the_treasury_itself(self) -> None:
        with pytest.raises(IntentError, match="settles to the treasury itself"):
            swap(destination="rSOMEONEELSE000000000000000000000")

    def test_the_outflow_is_the_sell_ceiling_and_the_delivery_is_the_buy(self) -> None:
        intent = swap()
        assert intent.outflow == Amount(value="500.00", currency=RLUSD)
        assert intent.deliver_amount == Amount(value="1000", currency="XRP")
        assert intent.is_swap

    def test_a_payment_reads_the_same_two_ways(self) -> None:
        intent = payment()
        assert intent.outflow == intent.deliver_amount == intent.amount
        assert not intent.is_swap

    def test_a_swap_survives_a_round_trip(self) -> None:
        intent = swap(reference=Reference(kind="mandate", id="M-1"))
        assert Intent.from_content(intent.to_content()) == intent

    def test_the_payment_shape_is_untouched(self) -> None:
        """The whole additive claim, at the byte level: no member moved."""
        assert set(payment().to_content()) == {
            "type",
            "rail",
            "treasury",
            "destination",
            "amount",
            "policy_version",
            "agent_public_key",
            "nonce",
            "expires_at",
        }

    @given(
        sell=st.decimals(min_value=1, max_value=10**6, places=2),
        buy=st.decimals(min_value=1, max_value=10**6, places=2),
    )
    def test_leaf_1_hashes_for_any_pair_of_amounts(self, sell: Any, buy: Any) -> None:
        intent = swap(
            sell=SwapSell(currency=RLUSD, max_amount=f"{sell}"),
            buy=SwapBuy(currency="XRP", amount=f"{buy}"),
        )
        assert receipt_leaf("intent", intent.to_content()) == receipt_leaf(
            "intent", Intent.from_content(intent.to_content()).to_content()
        )


class TestMaySwapGrant:
    """The grant is a new member that must not disturb a single existing hash."""

    def _document(self, **overrides: Any) -> PolicyDocument:
        section = AgentSection(
            agent_id="agent-ap",
            public_key=AGENT_KEY,
            allowlist_destinations=("rSUPPLIER0000000000000000000000000",),
            allowlist_assets=overrides.pop("assets", (RLUSD, "XRP")),
            per_tx_cap=(AssetLimit(asset=RLUSD, amount="1000.00"),),
            **overrides,
        )
        return PolicyDocument(
            version="2026.01.0",
            treasury=TREASURY,
            rail="xrpl",
            agents=(section,),
            admin_public_key="ab" * 32,
        )

    def test_may_swap_defaults_to_false_and_is_omitted_from_the_content(self) -> None:
        agent = self._document().to_content()["agents"][0]  # type: ignore[index]
        assert isinstance(agent, dict)
        assert "may_swap" not in agent

    def test_a_document_without_may_swap_keeps_its_policy_hash(self) -> None:
        """T3's proof: the hash of a document that never heard of may_swap.

        The literal is the hash this exact document had at commit e47e51b, the
        base of this branch — computed there, before ``may_swap`` existed in the
        dataclass at all. It is pinned so a future change to the field, the
        ordering or the canonicalization fails here rather than silently
        invalidating every admin signature made before this phase.
        """
        assert self._document().policy_hash() == (
            "ceaa030036378cd5bf2d7be259735724dd0d557b1d7108e3be812507d6d963b2"
        )

    def test_granting_may_swap_changes_the_hash(self) -> None:
        """The grant is signed. An authority nobody signed is not an authority."""
        assert self._document().policy_hash() != self._document(may_swap=True).policy_hash()
        content = self._document(may_swap=True).to_content()
        agent = content["agents"][0]  # type: ignore[index]
        assert isinstance(agent, dict)
        assert agent["may_swap"] is True

    def test_may_swap_survives_a_round_trip(self) -> None:
        document = self._document(may_swap=True)
        assert PolicyDocument.from_content(document.to_content()) == document

    def test_a_trader_with_one_asset_cannot_be_constructed(self) -> None:
        with pytest.raises(PolicyError, match="may_swap but names 1 allowlist_assets"):
            self._document(may_swap=True, assets=(RLUSD,))

    def test_the_finding_is_reported_from_content_too(self) -> None:
        """Both implementations judge the same bytes, so this reads content."""
        content = self._document(may_swap=True).to_content()
        agent = content["agents"][0]  # type: ignore[index]
        assert isinstance(agent, dict)
        agent["allowlist_assets"] = [agent["allowlist_assets"][0]]
        findings = unenforceable_rules(content)
        assert findings == [
            "agent 'agent-ap' may_swap but names 1 allowlist_assets; a swap sells one "
            "asset and buys another, so no trade by this agent could pass the "
            "asset_allowlist rule, and may_swap cannot be enforced"
        ]

    def test_may_swap_must_be_a_boolean(self) -> None:
        with pytest.raises(PolicyError, match="must be a boolean"):
            self._document(may_swap="yes")


def _receipt(result: Result, intent: Intent | None = None) -> Receipt:
    leaves = ReceiptLeaves(
        instruction=Instruction(source="system", content_hash="ab" * 32),
        intent=intent or swap(),
        policy_decision=PolicyDecision(
            policy_hash="cd" * 32,
            rules=(PolicyRule("may_swap", "pass", "agent may trade"),),
            outcome="allow",
            tier="instant",
        ),
        signer_attestation=None,
        settlement=Settlement(
            rail="xrpl",
            tx_hash="ef" * 32,
            ledger_index=94_211_402,
            close_time="2026-01-02T03:21:12Z",
        ),
        result=result,
    )
    return Receipt.build(
        receipt_id="01936b2e-2222-7000-8000-00000000000a",
        leaves=leaves,
        agent_id="agent-ap",
        signer_public_key="ab" * 32,
    )


def _settled(**overrides: Any) -> Result:
    fields: dict[str, Any] = {
        "outcome": "settled",
        "engine_result": "tesSUCCESS",
        "delivered": Amount(value="1000", currency="XRP"),
        "spent": Amount(value="492.50", currency=RLUSD),
    }
    fields.update(overrides)
    return Result(**fields)


def _check(receipt: Receipt) -> Any:
    verdict = verify_receipt(receipt.envelope, receipt.leaves)
    return verdict.result.get(CHECK_INTENT_MATCHES_SETTLED)


class TestSettledTradeIsHeldToItsIntent:
    def test_a_trade_inside_its_ceiling_passes(self) -> None:
        check = _check(_receipt(_settled()))
        assert check is not None and check.status is CheckStatus.PASS
        assert "within the 500.00 ceiling" in check.detail

    def test_delivering_something_other_than_the_buy_side_fails(self) -> None:
        check = _check(_receipt(_settled(delivered=Amount(value="900", currency="XRP"))))
        assert check is not None and check.status is CheckStatus.FAIL
        assert "bought exactly 1000" in check.detail

    def test_delivering_the_wrong_asset_fails(self) -> None:
        check = _check(_receipt(_settled(delivered=Amount(value="1000", currency="EUR"))))
        assert check is not None and check.status is CheckStatus.FAIL

    def test_spending_above_the_ceiling_fails(self) -> None:
        check = _check(_receipt(_settled(spent=Amount(value="500.01", currency=RLUSD))))
        assert check is not None and check.status is CheckStatus.FAIL
        assert "above the 500.00 ceiling" in check.detail

    def test_spending_the_wrong_asset_fails(self) -> None:
        check = _check(_receipt(_settled(spent=Amount(value="492.50", currency="XRP"))))
        assert check is not None and check.status is CheckStatus.FAIL

    @pytest.mark.parametrize("missing", ["delivered", "spent"])
    def test_a_missing_settled_amount_is_unchecked_by_name(self, missing: str) -> None:
        """Absence of data is never agreement. It is reported, with the name."""
        check = _check(_receipt(_settled(**{missing: None})))
        assert check is not None and check.status is CheckStatus.NOT_IMPLEMENTED
        assert missing in check.detail

    def test_a_payment_still_reads_its_balance_deltas(self) -> None:
        """The payment path is untouched: same check, same inputs, same verdict."""
        intent = payment()
        result = Result(
            outcome="settled",
            balance_deltas=(
                BalanceDelta(TREASURY, RLUSD, "-250.00"),
                BalanceDelta(intent.destination, RLUSD, "250.00"),
            ),
        )
        check = _check(_receipt(result, intent))
        assert check is not None and check.status is CheckStatus.PASS


class TestRateArithmetic:
    """Six significant digits, half to even, from strings. No float, ever."""

    @pytest.mark.parametrize(
        ("spent", "bought", "expected"),
        [
            ("492.50", "1000", "0.4925"),
            ("250.00", "100", "2.5"),
            ("1", "3", "0.333333"),
            ("2", "3", "0.666667"),
            ("0.000123456789", "1", "0.000123457"),
            ("123456789", "1", "123457000"),
            ("999999.5", "1", "1000000"),
            ("7", "1000000", "0.000007"),
        ],
    )
    def test_the_rate_reads_as_a_person_would_write_it(
        self, spent: str, bought: str, expected: str
    ) -> None:
        assert rate_string(spent, bought) == expected

    def test_a_rate_needs_two_sides(self) -> None:
        assert rate_string("0", "100") is None
        assert rate_string("100", "0") is None

    def test_it_is_never_in_scientific_notation(self) -> None:
        for spent in ("0.0000000001", "10000000000000"):
            rendered = rate_string(spent, "1")
            assert rendered is not None
            assert "e" not in rendered.lower()

    @given(
        spent=st.integers(min_value=1, max_value=10**12),
        bought=st.integers(min_value=1, max_value=10**12),
    )
    def test_it_always_produces_at_most_six_significant_digits(
        self, spent: int, bought: int
    ) -> None:
        rendered = rate_string(str(spent), str(bought))
        assert rendered is not None
        digits = rendered.replace(".", "").lstrip("0").rstrip("0")
        assert len(digits) <= 6


class TestTradeCard:
    def test_a_settled_trade_reads_bought_sold_and_rate(self) -> None:
        receipt = _receipt(_settled())
        verdict = verify_receipt(receipt.envelope, receipt.leaves)
        card = receipt_card(verdict, receipt.envelope, list(receipt.leaves.contents()))
        assert [line.label for line in card.body] == [
            "Bought",
            "Sold",
            "Rate",
            "From",
            "By",
            "On",
            "Ref",
        ]
        assert card.body[0].value == "1000 XRP"
        assert card.body[1].value == "492.50 RLUSD (limit 500.00 RLUSD)"
        assert card.body[2].value == "0.4925 RLUSD/XRP"

    def test_a_cost_the_rail_did_not_report_is_said_plainly(self) -> None:
        receipt = _receipt(_settled(spent=None))
        verdict = verify_receipt(receipt.envelope, receipt.leaves)
        card = receipt_card(verdict, receipt.envelope, list(receipt.leaves.contents()))
        labels = [line.label for line in card.body]
        assert "Rate" not in labels
        assert card.body[1].value == "not stated (limit 500.00 RLUSD)"


class TestResultLeafMembers:
    def test_delivered_and_spent_are_omitted_when_absent(self) -> None:
        content = Result(outcome="settled").to_content()
        assert "delivered" not in content
        assert "spent" not in content

    def test_they_survive_a_round_trip(self) -> None:
        result = _settled()
        assert Result.from_content(result.to_content()) == result

    def test_they_must_be_amounts(self) -> None:
        with pytest.raises(ContentError, match="must be an Amount"):
            Result(outcome="settled", spent="492.50")  # type: ignore[arg-type]

    def test_an_envelope_over_a_swap_still_binds_its_rail_and_treasury(self) -> None:
        receipt = _receipt(_settled())
        assert isinstance(receipt.envelope, Envelope)
        verdict = verify_receipt(receipt.envelope, receipt.leaves)
        for name in ("envelope.rail", "envelope.treasury", "commitment.root"):
            check = verdict.result.get(name)
            assert check is not None and check.status is CheckStatus.PASS


class TestTheFakeRailFillsATrade:
    """The in-memory book: a price, all-or-nothing, and a ceiling the rail enforces.

    The ceiling being enforced by the *rail* is what lets the policy bound only
    the size. If the rail filled partially, or above the limit, the policy would
    have to price trades — and a policy that prices trades is a policy with a
    model in its decision path.
    """

    def _rig(self, **overrides: Any) -> Any:
        import tempfile
        from decimal import Decimal
        from pathlib import Path

        from merkl.core.policy.document import asset_key
        from merkl.demo.rig import RLUSD as DEMO_RLUSD
        from merkl.demo.rig import XRP, build_policy, build_rig

        policy = build_policy(
            may_swap=True, other_asset=XRP, reference_required=False, reference_hashes=()
        )
        return build_rig(
            Path(tempfile.mkdtemp()) / "trading",
            policy=policy,
            rates={(asset_key(DEMO_RLUSD), asset_key(XRP)): Decimal(overrides.get("rate", "0.5"))},
        )

    @pytest.mark.asyncio
    async def test_a_trade_settles_with_what_it_bought_and_what_it_cost(self) -> None:
        rig = self._rig()
        outcome = await rig.builder.execute(
            instruction=rig.instruction("rotate into XRP"),
            intent=rig.swap_intent(sell="100.00", buy="150"),
        )
        assert outcome.settled
        result = outcome.receipt.leaves.result
        assert result is not None
        assert result.delivered == Amount(value="150", currency="XRP")
        assert result.spent is not None
        assert result.spent.value == "75.0"

    @pytest.mark.asyncio
    async def test_a_fill_above_the_ceiling_fails_rather_than_filling_partially(self) -> None:
        rig = self._rig(rate="2")
        outcome = await rig.builder.execute(
            instruction=rig.instruction("rotate into XRP"),
            intent=rig.swap_intent(sell="100.00", buy="150"),
        )
        # The policy allowed it; the rail refused the price. The receipt says so.
        assert outcome.decision.outcome == "allow"
        assert not outcome.settled
        assert "above the 100.00 ceiling" in outcome.reason

    @pytest.mark.asyncio
    async def test_an_asset_pair_with_no_book_cannot_be_traded(self) -> None:
        rig = self._rig()
        rig.ledger.rates.clear()
        outcome = await rig.builder.execute(
            instruction=rig.instruction("rotate into XRP"),
            intent=rig.swap_intent(sell="100.00", buy="150"),
        )
        assert not outcome.settled
        assert "no book between" in outcome.reason

    @pytest.mark.asyncio
    async def test_the_two_sides_both_land_on_the_treasury(self) -> None:
        rig = self._rig()
        outcome = await rig.builder.execute(
            instruction=rig.instruction("rotate into XRP"),
            intent=rig.swap_intent(sell="100.00", buy="150"),
        )
        result = outcome.receipt.leaves.result
        assert result is not None
        accounts = {d.account for d in result.balance_deltas}
        assert accounts == {rig.policy.treasury}
        assert {d.value for d in result.balance_deltas} == {"-75.0", "150"}
