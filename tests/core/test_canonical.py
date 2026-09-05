"""The no-float rule and the rest of the canonical content subset."""

from __future__ import annotations

import decimal
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.core.canonical import (
    MAX_SAFE_INTEGER,
    ContentError,
    drop_none,
    ensure_canonical_content,
)
from merkl.shared.errors import ValidationError
from merkl.shared.hashing import canonical_bytes


class TestAccepts:
    @pytest.mark.parametrize(
        "value",
        [
            None,
            True,
            False,
            0,
            -7,
            MAX_SAFE_INTEGER,
            -MAX_SAFE_INTEGER,
            "",
            "café ☕",
            [],
            {},
            {"a": [1, "x", None, {"b": False}]},
        ],
    )
    def test_canonical_values(self, value: Any) -> None:
        ensure_canonical_content(value)


class TestRejects:
    @pytest.mark.parametrize(
        "value",
        [
            1.5,
            0.0,
            float("nan"),
            float("inf"),
            decimal.Decimal("1.5"),
            datetime(2026, 1, 1, tzinfo=UTC),
            b"bytes",
            {1: "int key"},
            {"nested": {"deep": [1, 2.0]}},
            [1, [2, [3.5]]],
            MAX_SAFE_INTEGER + 1,
            -MAX_SAFE_INTEGER - 1,
        ],
    )
    def test_non_canonical_values(self, value: Any) -> None:
        with pytest.raises(ContentError):
            ensure_canonical_content(value)

    def test_error_is_a_validation_error(self) -> None:
        assert issubclass(ContentError, ValidationError)

    def test_error_names_the_path(self) -> None:
        with pytest.raises(ContentError, match=r"\$\.a\[1\]\.b"):
            ensure_canonical_content({"a": [0, {"b": 1.25}]})

    def test_float_message_points_at_decimal_strings(self) -> None:
        with pytest.raises(ContentError, match="decimal string"):
            ensure_canonical_content({"value": 12.5})


class TestDropNone:
    def test_removes_absent_members_only(self) -> None:
        assert drop_none({"a": 1, "b": None, "c": "", "d": 0, "e": False}) == {
            "a": 1,
            "c": "",
            "d": 0,
            "e": False,
        }


class TestCanonicalBytes:
    def test_key_order_does_not_matter(self) -> None:
        assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})

    def test_non_ascii_is_escaped(self) -> None:
        assert canonical_bytes({"k": "café"}) == b'{"k":"caf\\u00e9"}'

    def test_null_is_the_literal_null(self) -> None:
        assert canonical_bytes(None) == b"null"

    def test_no_whitespace(self) -> None:
        assert canonical_bytes({"a": [1, 2]}) == b'{"a":[1,2]}'


_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.text()
)
_json = st.recursive(
    _scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=12,
)


class TestProperties:
    @given(value=_json)
    def test_accepted_values_serialize_without_the_str_fallback(self, value: Any) -> None:
        import json

        ensure_canonical_content(value)
        assert (
            canonical_bytes(value)
            == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )

    @given(value=_json)
    def test_canonicalization_is_stable(self, value: Any) -> None:
        assert canonical_bytes(value) == canonical_bytes(value)
