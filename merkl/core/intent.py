"""Intent v1 — what the agent asked the treasury to do.

The intent is leaf 1 of a receipt and the only thing the policy engine reads. It
is rail-agnostic in shape: ``rail`` names the settlement family, and everything
else is a string the adapter for that rail knows how to interpret.

Type ``payment`` is the only type in v1 (plan section 1). Other types (trustline,
escrow, card authorization) are additive: a new ``type`` value with its own
required members, the rest of the format unchanged.

Money never touches a float. An amount is a decimal string plus a currency, and
arithmetic goes through :class:`decimal.Decimal`. ``0.1 + 0.2`` is a bug in a
payments system, not a rounding curiosity.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Final, TypeAlias

from merkl.core.canonical import JSONObject, JSONValue, drop_none, ensure_canonical_content
from merkl.shared.errors import ValidationError

INTENT_TYPE_PAYMENT: Final = "payment"
INTENT_TYPES: Final = (INTENT_TYPE_PAYMENT,)

NATIVE_XRP: Final = "XRP"

_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$")
_SIGNED_DECIMAL_RE = re.compile(r"^-?(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$")
_NATIVE_CURRENCY_RE = re.compile(r"^[A-Z0-9]{1,20}$")
_INSTANT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
_TOKEN_MAX = 512


class IntentError(ValidationError):
    """Raised when an intent, or part of one, is not well formed."""

    error_code = "intent_error"


def token(value: Any, field: str, *, max_length: int = _TOKEN_MAX) -> str:
    """Validate an identifier-ish string: non-empty, printable, no whitespace."""
    if not isinstance(value, str):
        raise IntentError(f"{field} must be a string, got {type(value).__name__}")
    if not value:
        raise IntentError(f"{field} cannot be empty")
    if len(value) > max_length:
        raise IntentError(f"{field} is longer than {max_length} characters")
    for ch in value:
        if ch <= " " or ch == "\x7f":
            raise IntentError(f"{field} contains whitespace or a control character: {value!r}")
    return value


def instant(value: Any, field: str) -> str:
    """Validate an RFC 3339 UTC instant such as ``2026-01-02T03:04:05Z``.

    The ``Z`` form is required so a JavaScript verifier's ``toISOString()`` and a
    Python verifier agree on the exact bytes. Core has no clock: whether an
    instant has passed is the signer's business, not this module's.
    """
    if not isinstance(value, str) or not _INSTANT_RE.match(value):
        raise IntentError(f"{field} must be an RFC 3339 UTC instant ending in Z, got {value!r}")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntentError(f"{field} is not a valid instant: {value!r}") from exc
    return value


def decimal_string(value: Any, field: str, *, signed: bool = False, positive: bool = True) -> str:
    """Validate a decimal amount string and return it unchanged.

    Accepted: ``0``, ``12``, ``0.5``, ``1234.56789`` (and a leading ``-`` when
    ``signed``). Rejected: floats, exponents, leading ``+``, leading zeros,
    trailing dots, whitespace, and — when ``positive`` — anything not above zero.
    """
    if isinstance(value, bool) or not isinstance(value, str):
        raise IntentError(f"{field} must be a decimal string, got {type(value).__name__}")
    pattern = _SIGNED_DECIMAL_RE if signed else _DECIMAL_RE
    if not pattern.match(value):
        raise IntentError(f"{field} is not a canonical decimal string: {value!r}")
    if positive and parse_decimal(value, field) <= 0:
        raise IntentError(f"{field} must be greater than zero, got {value!r}")
    return value


def parse_decimal(value: str, field: str = "value") -> Decimal:
    """Parse a validated decimal string into a :class:`~decimal.Decimal`."""
    try:
        return Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - unreachable after the regex
        raise IntentError(f"{field} is not a decimal: {value!r}") from exc


def format_decimal(value: Decimal) -> str:
    """Render a Decimal as a canonical decimal string (never scientific notation)."""
    if value.is_nan() or value.is_infinite():
        raise IntentError(f"amount must be finite, got {value}")
    return format(value, "f")


@dataclasses.dataclass(frozen=True)
class IssuedCurrency:
    """A currency issued by an account on the rail (XRPL RLUSD, for example)."""

    code: str
    issuer: str

    def __post_init__(self) -> None:
        token(self.code, "currency.code", max_length=64)
        token(self.issuer, "currency.issuer", max_length=128)

    def to_content(self) -> JSONObject:
        return {"code": self.code, "issuer": self.issuer}

    @classmethod
    def from_content(cls, data: Any) -> IssuedCurrency:
        if not isinstance(data, dict):
            raise IntentError(f"issued currency must be an object, got {type(data).__name__}")
        _reject_unknown(data, {"code", "issuer"}, "currency")
        return cls(
            code=_member(data, "code", "currency"),
            issuer=_member(data, "issuer", "currency"),
        )


CurrencyRef: TypeAlias = str | IssuedCurrency
"""Either a native asset code (``"XRP"``) or an :class:`IssuedCurrency`."""


def currency_content(currency: CurrencyRef) -> JSONValue:
    """Canonical content form of a currency."""
    if isinstance(currency, IssuedCurrency):
        return currency.to_content()
    if not _NATIVE_CURRENCY_RE.match(currency):
        raise IntentError(f"native currency code must be A-Z0-9, got {currency!r}")
    return currency


def currency_from_content(data: Any) -> CurrencyRef:
    """Parse the canonical content form of a currency."""
    if isinstance(data, str):
        if not _NATIVE_CURRENCY_RE.match(data):
            raise IntentError(f"native currency code must be A-Z0-9, got {data!r}")
        return data
    return IssuedCurrency.from_content(data)


@dataclasses.dataclass(frozen=True)
class Amount:
    """A quantity of one currency, carried as a decimal string.

    ``value`` is the canonical string that goes into the receipt; :attr:`decimal`
    is the same number for arithmetic. The two never diverge because the string
    is the source of truth.
    """

    value: str
    currency: CurrencyRef

    def __post_init__(self) -> None:
        decimal_string(self.value, "amount.value")
        currency_content(self.currency)

    @property
    def decimal(self) -> Decimal:
        """The amount as a Decimal. Never a float."""
        return parse_decimal(self.value, "amount.value")

    @classmethod
    def from_decimal(cls, value: Decimal, currency: CurrencyRef) -> Amount:
        """Build an amount from a Decimal, rendering it canonically."""
        return cls(value=format_decimal(value), currency=currency)

    def _same_currency(self, other: Amount) -> None:
        if self.currency != other.currency:
            raise IntentError(
                f"cannot combine amounts in different currencies: "
                f"{currency_content(self.currency)!r} and {currency_content(other.currency)!r}"
            )

    def add(self, other: Amount) -> Amount:
        """Sum two amounts of the same currency, exactly."""
        self._same_currency(other)
        return Amount.from_decimal(self.decimal + other.decimal, self.currency)

    def compare(self, other: Amount) -> int:
        """-1, 0 or 1, comparing two amounts of the same currency by value."""
        self._same_currency(other)
        mine, theirs = self.decimal, other.decimal
        return -1 if mine < theirs else (0 if mine == theirs else 1)

    def to_content(self) -> JSONObject:
        return {"value": self.value, "currency": currency_content(self.currency)}

    @classmethod
    def from_content(cls, data: Any) -> Amount:
        if not isinstance(data, dict):
            raise IntentError(f"amount must be an object, got {type(data).__name__}")
        _reject_unknown(data, {"value", "currency"}, "amount")
        if "value" not in data or "currency" not in data:
            raise IntentError("amount requires value and currency")
        return cls(
            value=decimal_string(data["value"], "amount.value"),
            currency=currency_from_content(data["currency"]),
        )


@dataclasses.dataclass(frozen=True)
class Reference:
    """What the payment is *for*: an invoice, a mandate, a purchase order.

    ``hash`` is the content hash of the referenced document when the agent has it,
    which is what makes a reference-mismatch scenario detectable after the fact.
    """

    kind: str
    id: str
    hash: str | None = None

    def __post_init__(self) -> None:
        token(self.kind, "reference.kind", max_length=64)
        token(self.id, "reference.id", max_length=256)
        if self.hash is not None:
            token(self.hash, "reference.hash", max_length=128)

    def to_content(self) -> JSONObject:
        return drop_none({"kind": self.kind, "id": self.id, "hash": self.hash})

    @classmethod
    def from_content(cls, data: Any) -> Reference:
        if not isinstance(data, dict):
            raise IntentError(f"reference must be an object, got {type(data).__name__}")
        _reject_unknown(data, {"kind", "id", "hash"}, "reference")
        raw_hash = data.get("hash")
        return cls(
            kind=_member(data, "kind", "reference"),
            id=_member(data, "id", "reference"),
            hash=None if raw_hash is None else token(raw_hash, "reference.hash", max_length=128),
        )


@dataclasses.dataclass(frozen=True)
class Intent:
    """Intent v1, type ``payment``.

    Every member is a string or a nested object of strings: an intent survives a
    JSON round trip in any language with no numeric precision to lose.
    """

    rail: str
    treasury: str
    destination: str
    amount: Amount
    policy_version: str
    agent_public_key: str
    nonce: str
    expires_at: str
    reference: Reference | None = None
    type: str = INTENT_TYPE_PAYMENT

    def __post_init__(self) -> None:
        if self.type not in INTENT_TYPES:
            raise IntentError(
                f"intent type must be one of {list(INTENT_TYPES)}, got {self.type!r}"
            )
        token(self.rail, "rail", max_length=64)
        token(self.treasury, "treasury", max_length=128)
        token(self.destination, "destination", max_length=128)
        if not isinstance(self.amount, Amount):
            raise IntentError("amount must be an Amount")
        token(self.policy_version, "policy_version", max_length=64)
        token(self.agent_public_key, "agent_public_key")
        token(self.nonce, "nonce", max_length=128)
        instant(self.expires_at, "expires_at")

    def to_content(self) -> JSONObject:
        """The canonical content of receipt leaf 1."""
        content = drop_none(
            {
                "type": self.type,
                "rail": self.rail,
                "treasury": self.treasury,
                "destination": self.destination,
                "amount": self.amount.to_content(),
                "reference": self.reference.to_content() if self.reference else None,
                "policy_version": self.policy_version,
                "agent_public_key": self.agent_public_key,
                "nonce": self.nonce,
                "expires_at": self.expires_at,
            }
        )
        ensure_canonical_content(content)
        return content

    @classmethod
    def from_content(cls, data: Any) -> Intent:
        """Parse and re-validate leaf 1 content. Unknown members are rejected."""
        if not isinstance(data, dict):
            raise IntentError(f"intent must be an object, got {type(data).__name__}")
        _reject_unknown(
            data,
            {
                "type",
                "rail",
                "treasury",
                "destination",
                "amount",
                "reference",
                "policy_version",
                "agent_public_key",
                "nonce",
                "expires_at",
            },
            "intent",
        )
        reference = data.get("reference")
        return cls(
            type=data.get("type", INTENT_TYPE_PAYMENT),
            rail=_member(data, "rail", "intent"),
            treasury=_member(data, "treasury", "intent"),
            destination=_member(data, "destination", "intent"),
            amount=Amount.from_content(data.get("amount")),
            reference=None if reference is None else Reference.from_content(reference),
            policy_version=_member(data, "policy_version", "intent"),
            agent_public_key=_member(data, "agent_public_key", "intent"),
            nonce=_member(data, "nonce", "intent"),
            expires_at=_member(data, "expires_at", "intent"),
        )


def _member(data: dict[str, Any], key: str, owner: str) -> str:
    if key not in data:
        raise IntentError(f"{owner} requires {key}")
    value = data[key]
    if not isinstance(value, str):
        raise IntentError(f"{owner}.{key} must be a string, got {type(value).__name__}")
    return value


def _reject_unknown(data: dict[str, Any], allowed: set[str], owner: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise IntentError(f"{owner} has unknown members: {unknown}")
