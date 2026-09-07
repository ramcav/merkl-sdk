"""Intent v1 validation and the no-float rule on money."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.core.canonical import (
    ContentError,
    decimal_string,
    ensure_canonical_content,
    format_decimal,
    instant,
    token,
)
from merkl.core.intent import Amount, Intent, IntentError, IssuedCurrency, Reference
from merkl.core.leaf import receipt_leaf

RLUSD = IssuedCurrency(code="RLUSD", issuer="rISSUER000000000000000000000000000")


def make_intent(**overrides: Any) -> Intent:
    fields: dict[str, Any] = {
        "rail": "xrpl",
        "treasury": "rTREASURY0000000000000000000000000",
        "destination": "rDESTINATION00000000000000000000000",
        "amount": Amount(value="100.50", currency=RLUSD),
        "policy_version": "2026.01.0",
        "agent_public_key": "ed01" * 16,
        "nonce": "0123456789abcdef",
        "expires_at": "2026-01-02T03:04:05Z",
    }
    fields.update(overrides)
    return Intent(**fields)


class TestErrorHierarchy:
    def test_intent_errors_are_content_errors(self) -> None:
        assert issubclass(IntentError, ContentError)


class TestAmount:
    @pytest.mark.parametrize("value", ["1", "0.5", "100.50", "1234567.891011", "12"])
    def test_accepts_decimal_strings(self, value: str) -> None:
        assert Amount(value=value, currency="XRP").value == value

    @pytest.mark.parametrize(
        "value",
        ["0", "0.0", "0.000", "-1", "+1", "1e5", "1E5", ".5", "1.", "01", " 1", "1 ", "", "abc"],
    )
    def test_rejects_bad_or_non_positive_values(self, value: str) -> None:
        with pytest.raises(ContentError):
            Amount(value=value, currency="XRP")

    @pytest.mark.parametrize("value", [10.5, 10, True, None, Decimal("10.5")])
    def test_rejects_non_strings(self, value: Any) -> None:
        with pytest.raises(ContentError):
            Amount(value=value, currency="XRP")

    def test_decimal_is_exact(self) -> None:
        assert Amount(value="0.1", currency="XRP").decimal == Decimal("0.1")

    def test_addition_is_exact(self) -> None:
        total = Amount("0.1", "XRP").add(Amount("0.2", "XRP"))
        assert total.value == "0.3"
        assert total.decimal == Decimal("0.3")

    def test_addition_keeps_scale(self) -> None:
        assert Amount("1.50", "XRP").add(Amount("2.50", "XRP")).value == "4.00"

    def test_addition_across_currencies_rejected(self) -> None:
        with pytest.raises(IntentError, match="different currencies"):
            Amount("1", "XRP").add(Amount("1", RLUSD))

    def test_compare(self) -> None:
        assert Amount("1", "XRP").compare(Amount("2", "XRP")) == -1
        assert Amount("2", "XRP").compare(Amount("2.0", "XRP")) == 0
        assert Amount("3", "XRP").compare(Amount("2", "XRP")) == 1

    def test_from_decimal_never_uses_exponents(self) -> None:
        assert Amount.from_decimal(Decimal("1E+3"), "XRP").value == "1000"
        assert Amount.from_decimal(Decimal("0.000001"), "XRP").value == "0.000001"

    def test_native_currency_form(self) -> None:
        assert Amount("1", "XRP").to_content() == {"value": "1", "currency": "XRP"}

    def test_issued_currency_form(self) -> None:
        assert Amount("1", RLUSD).to_content()["currency"] == {
            "code": "RLUSD",
            "issuer": RLUSD.issuer,
        }

    @pytest.mark.parametrize("code", ["xrp", "RL USD", "", "TOOLONGCURRENCYCODEXX"])
    def test_bad_native_currency_rejected(self, code: str) -> None:
        with pytest.raises(ContentError):
            Amount("1", code).to_content()

    def test_round_trips(self) -> None:
        amount = Amount("100.50", RLUSD)
        assert Amount.from_content(amount.to_content()) == amount

    def test_unknown_member_rejected(self) -> None:
        with pytest.raises(IntentError, match="unknown"):
            Amount.from_content({"value": "1", "currency": "XRP", "drops": "1000000"})


class TestValidators:
    @pytest.mark.parametrize("value", ["", " ", "a b", "a\tb", "a\nb", "a\x00b", "\x7f"])
    def test_token_rejects_blanks_and_controls(self, value: str) -> None:
        with pytest.raises(ContentError):
            token(value, "field")

    def test_token_rejects_overlong(self) -> None:
        with pytest.raises(ContentError, match="longer than"):
            token("a" * 10, "field", max_length=9)

    @pytest.mark.parametrize(
        "value",
        ["2026-01-02T03:04:05Z", "2026-01-02T03:04:05.123Z", "2026-01-02T03:04:05.123456Z"],
    )
    def test_instant_accepts_utc_z(self, value: str) -> None:
        assert instant(value, "expires_at") == value

    @pytest.mark.parametrize(
        "value",
        [
            "2026-01-02T03:04:05+00:00",
            "2026-01-02T03:04:05",
            "2026-01-02 03:04:05Z",
            "2026-13-02T03:04:05Z",
            "2026-01-02T03:04:05z",
            1234567890,
        ],
    )
    def test_instant_rejects_other_forms(self, value: Any) -> None:
        with pytest.raises(ContentError):
            instant(value, "expires_at")

    def test_signed_decimals_for_balance_deltas(self) -> None:
        assert decimal_string("-1.5", "delta", signed=True, positive=False) == "-1.5"
        with pytest.raises(ContentError):
            decimal_string("-1.5", "delta")

    def test_format_decimal_rejects_nan(self) -> None:
        with pytest.raises(ContentError):
            format_decimal(Decimal("NaN"))


class TestIntent:
    def test_content_shape(self) -> None:
        content = make_intent().to_content()
        assert set(content) == {
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
        assert content["type"] == "payment"

    def test_absent_reference_is_omitted_not_null(self) -> None:
        assert "reference" not in make_intent().to_content()

    def test_reference_round_trips(self) -> None:
        intent = make_intent(reference=Reference(kind="invoice", id="INV-42", hash="ab" * 32))
        assert Intent.from_content(intent.to_content()) == intent

    def test_round_trips(self) -> None:
        intent = make_intent()
        assert Intent.from_content(intent.to_content()) == intent

    def test_content_is_canonical(self) -> None:
        ensure_canonical_content(make_intent().to_content())

    def test_leaf_changes_when_any_field_changes(self) -> None:
        base = receipt_leaf("intent", make_intent().to_content())
        for field, value in [
            ("rail", "fake"),
            ("treasury", "rOTHER"),
            ("destination", "rOTHER"),
            ("policy_version", "2026.02.0"),
            ("agent_public_key", "ff" * 32),
            ("nonce", "different"),
            ("expires_at", "2026-01-02T03:04:06Z"),
        ]:
            assert receipt_leaf("intent", make_intent(**{field: value}).to_content()) != base
        other_amount = make_intent(amount=Amount("100.51", RLUSD)).to_content()
        assert receipt_leaf("intent", other_amount) != base

    @pytest.mark.parametrize(
        "field", ["rail", "treasury", "destination", "policy_version", "agent_public_key", "nonce"]
    )
    def test_empty_fields_rejected(self, field: str) -> None:
        with pytest.raises(ContentError):
            make_intent(**{field: ""})

    def test_unknown_type_rejected(self) -> None:
        with pytest.raises(IntentError, match="intent type"):
            make_intent(type="trustline")

    def test_amount_must_be_an_amount(self) -> None:
        with pytest.raises(IntentError, match="Amount"):
            make_intent(amount={"value": "1", "currency": "XRP"})

    def test_unknown_members_rejected(self) -> None:
        content = make_intent().to_content()
        content["memo"] = "extra"
        with pytest.raises(IntentError, match="unknown members"):
            Intent.from_content(content)

    def test_missing_member_rejected(self) -> None:
        content = make_intent().to_content()
        del content["nonce"]
        with pytest.raises(IntentError, match="requires nonce"):
            Intent.from_content(content)

    def test_float_amount_in_content_rejected(self) -> None:
        content = make_intent().to_content()
        content["amount"] = {"value": 100.5, "currency": "XRP"}
        with pytest.raises(ContentError):
            Intent.from_content(content)


_positive_decimals = st.from_regex(r"\A(0\.[0-9]{1,6}[1-9]|[1-9][0-9]{0,9}(\.[0-9]{1,6})?)\Z")


class TestProperties:
    @given(value=_positive_decimals)
    def test_every_accepted_string_round_trips_through_decimal(self, value: str) -> None:
        amount = Amount(value=value, currency="XRP")
        assert Amount.from_decimal(amount.decimal, "XRP").decimal == amount.decimal

    @given(a=_positive_decimals, b=_positive_decimals)
    def test_addition_is_exact_and_commutative(self, a: str, b: str) -> None:
        x, y = Amount(a, "XRP"), Amount(b, "XRP")
        assert x.add(y).decimal == y.add(x).decimal == Decimal(a) + Decimal(b)

    @given(value=_positive_decimals)
    def test_content_round_trip_is_lossless(self, value: str) -> None:
        amount = Amount(value=value, currency=RLUSD)
        assert Amount.from_content(amount.to_content()) == amount

    @given(value=_positive_decimals)
    def test_no_float_ever_reaches_the_content(self, value: str) -> None:
        ensure_canonical_content(make_intent(amount=Amount(value, "XRP")).to_content())
