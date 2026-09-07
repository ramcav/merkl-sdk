"""Canonical JSON content rules for Merkl receipts (v1).

Receipt leaf contents are hashed with :func:`merkl.shared.hashing.canonical_bytes`,
the one canonicalization shared by the SDK, the hook and the server. That function
accepts anything (non-JSON types fall through to ``str()``), which is fine for
opaque action payloads but not for a normative receipt format: a second
implementation in another language must be able to reproduce every byte.

So receipt content is restricted to a strict JSON subset:

* objects with string keys, arrays, strings, booleans, integers and ``null``;
* no floats anywhere (amounts are decimal strings — plan D6);
* integers within IEEE-754 safe range, so a JavaScript verifier reads them exactly;
* no other Python types (``Decimal``, ``datetime``, ``bytes``, enums): the caller
  converts them to strings explicitly, rather than relying on ``default=str``.

This module is pure: no I/O, no clock, no dependencies beyond ``merkl.shared``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, TypeAlias

from merkl.shared.errors import ValidationError

JSONValue: TypeAlias = None | bool | int | str | list["JSONValue"] | dict[str, "JSONValue"]
"""The value shapes a receipt leaf content may contain."""

JSONObject: TypeAlias = dict[str, JSONValue]

MAX_SAFE_INTEGER = 2**53 - 1
"""Largest integer a JSON number reproduces exactly in IEEE-754 double precision."""

MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER


class ContentError(ValidationError):
    """Raised when a value cannot appear in a Merkl receipt leaf.

    Every content and field error in ``merkl.core`` is one of these or a
    subclass, so a caller parsing untrusted JSON has exactly one thing to catch.
    """

    error_code = "content_error"


def ensure_canonical_content(value: Any, *, path: str = "$") -> None:
    """Raise :class:`ContentError` if ``value`` is not canonical receipt content.

    ``path`` is a JSONPath-ish breadcrumb used in the error message so a failure
    inside a nested object says which member is at fault.
    """
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, float):
        raise ContentError(
            f"{path}: receipts contain no fractional JSON numbers; "
            "encode the value as a decimal string"
        )
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ContentError(
                f"{path}: integer {value} is outside the IEEE-754 safe range "
                f"[{MIN_SAFE_INTEGER}, {MAX_SAFE_INTEGER}]; encode it as a string"
            )
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            ensure_canonical_content(item, path=f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContentError(
                    f"{path}: object keys must be strings, got {type(key).__name__}"
                )
            ensure_canonical_content(item, path=f"{path}.{key}")
        return
    raise ContentError(
        f"{path}: {type(value).__name__} is not canonical receipt content; "
        "convert it to a string, integer, bool, list, object or null"
    )


def drop_none(obj: dict[str, Any]) -> JSONObject:
    """Return ``obj`` without its ``None`` members.

    Optional members of a receipt content object are *omitted* when absent, never
    serialized as ``null`` — see ``docs/RECEIPT-SPEC.md`` section 4.
    """
    return {k: v for k, v in obj.items() if v is not None}


# --------------------------------------------------------------------------- #
# Field formats
# --------------------------------------------------------------------------- #

_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$")
_SIGNED_DECIMAL_RE = re.compile(r"^-?(0|[1-9][0-9]{0,30})(\.[0-9]{1,30})?$")
_INSTANT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")

TOKEN_MAX = 512


def token(value: Any, field: str, *, max_length: int = TOKEN_MAX) -> str:
    """Validate an identifier-ish string: non-empty, printable, no whitespace."""
    if not isinstance(value, str):
        raise ContentError(f"{field} must be a string, got {type(value).__name__}")
    if not value:
        raise ContentError(f"{field} cannot be empty")
    if len(value) > max_length:
        raise ContentError(f"{field} is longer than {max_length} characters")
    for ch in value:
        if ch <= " " or ch == "\x7f":
            raise ContentError(f"{field} contains whitespace or a control character: {value!r}")
    return value


def text(value: Any, field: str, *, max_length: int = 1024) -> str:
    """Validate free-form human text: printable, no control characters."""
    if not isinstance(value, str):
        raise ContentError(f"{field} must be a string, got {type(value).__name__}")
    if len(value) > max_length:
        raise ContentError(f"{field} is longer than {max_length} characters")
    for ch in value:
        if ch < " " or ch == "\x7f":
            raise ContentError(f"{field} contains a control character")
    return value


def hex_digest(value: Any, field: str) -> str:
    """Validate a lowercase 64-character SHA-256 hex digest and return it."""
    if not isinstance(value, str):
        raise ContentError(f"{field} must be a hex digest string, got {type(value).__name__}")
    if len(value) != 64:
        raise ContentError(f"{field} must be 64 hex characters, got {len(value)}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ContentError(f"{field} is not hex: {value!r}") from exc
    if value != value.lower():
        raise ContentError(f"{field} must be lowercase hex")
    return value


def instant(value: Any, field: str) -> str:
    """Validate an RFC 3339 UTC instant such as ``2026-01-02T03:04:05Z``.

    The ``Z`` form is required so a JavaScript verifier's ``toISOString()`` and a
    Python verifier agree on the exact bytes. Core has no clock: whether an
    instant has passed is the signer's business, not this module's.
    """
    if not isinstance(value, str) or not _INSTANT_RE.match(value):
        raise ContentError(f"{field} must be an RFC 3339 UTC instant ending in Z, got {value!r}")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContentError(f"{field} is not a valid instant: {value!r}") from exc
    return value


def parse_instant(value: Any, field: str) -> datetime:
    """Parse a validated instant into an aware :class:`~datetime.datetime` (UTC).

    Core never *reads* a clock; it does arithmetic on instants the caller supplies,
    which is what a sliding window and an expiry need.
    """
    return datetime.fromisoformat(instant(value, field).replace("Z", "+00:00"))


def format_instant(value: datetime) -> str:
    """Render a datetime as the canonical ``...Z`` instant, seconds precision.

    Sub-second precision is dropped on purpose: a receipt's instants are compared
    across implementations, and microseconds are the field where two runtimes
    disagree first.
    """
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def shift_instant(value: str, seconds: int, field: str = "instant") -> str:
    """The canonical instant ``seconds`` after ``value`` (negative shifts backwards)."""
    return format_instant(parse_instant(value, field) + timedelta(seconds=seconds))


def decimal_string(value: Any, field: str, *, signed: bool = False, positive: bool = True) -> str:
    """Validate a decimal amount string and return it unchanged.

    Accepted: ``0``, ``12``, ``0.5``, ``1234.56789`` (and a leading ``-`` when
    ``signed``). Rejected: floats, exponents, leading ``+``, leading zeros,
    trailing dots, whitespace, and — when ``positive`` — anything not above zero.
    """
    if isinstance(value, bool) or not isinstance(value, str):
        raise ContentError(f"{field} must be a decimal string, got {type(value).__name__}")
    pattern = _SIGNED_DECIMAL_RE if signed else _DECIMAL_RE
    if not pattern.match(value):
        raise ContentError(f"{field} is not a canonical decimal string: {value!r}")
    if positive and parse_decimal(value, field) <= 0:
        raise ContentError(f"{field} must be greater than zero, got {value!r}")
    return value


def parse_decimal(value: str, field: str = "value") -> Decimal:
    """Parse a validated decimal string into a :class:`~decimal.Decimal`."""
    try:
        return Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - unreachable after the regex
        raise ContentError(f"{field} is not a decimal: {value!r}") from exc


def format_decimal(value: Decimal) -> str:
    """Render a Decimal as a canonical decimal string (never scientific notation)."""
    if value.is_nan() or value.is_infinite():
        raise ContentError(f"amount must be finite, got {value}")
    return format(value, "f")
