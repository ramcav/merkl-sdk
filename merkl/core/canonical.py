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

from typing import Any, TypeAlias

from merkl.shared.errors import ValidationError

JSONValue: TypeAlias = None | bool | int | str | list["JSONValue"] | dict[str, "JSONValue"]
"""The value shapes a receipt leaf content may contain."""

JSONObject: TypeAlias = dict[str, JSONValue]

MAX_SAFE_INTEGER = 2**53 - 1
"""Largest integer a JSON number reproduces exactly in IEEE-754 double precision."""

MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER


class ContentError(ValidationError):
    """Raised when a value cannot appear in a Merkl receipt leaf."""

    error_code = "receipt_content_error"


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
