"""Leaf encodings: the frozen action leaf and the receipt leaf."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.core.canonical import ContentError
from merkl.core.leaf import ACTION_LEAF_TAG, RECEIPT_LEAF_TAG, action_leaf, receipt_leaf
from merkl.shared.enums import ActionStatus, ActionType, GuardrailResult
from merkl.shared.errors import ValidationError
from merkl.shared.hashing import SHA256Hash, canonical_bytes

_H = SHA256Hash.from_bytes(b"input").hex()
_O = SHA256Hash.from_bytes(b"output").hex()

_BASE: dict[str, Any] = {
    "action_id": "01936b2e-0000-7000-8000-000000000001",
    "session_id": "01936b2e-1111-7000-8000-000000000001",
    "action_type": "transaction",
    "tool_name": "submit_payment",
    "input_hash": _H,
    "output_hash": _O,
    "timestamp": "2026-01-02T03:04:05+00:00",
    "drift_score": "0.25",
    "guardrail_result": "passed",
    "display_name": "Submit payment",
    "depends_on": ["b", "a"],
    "status": "success",
    "category": "payments",
}


class TestActionLeaf:
    def test_matches_a_hand_written_encoding(self) -> None:
        expected = hashlib.sha256(
            b"merkl-leaf-v1\x00"
            + b"\x00".join(
                [
                    b"01936b2e-0000-7000-8000-000000000001",
                    b"01936b2e-1111-7000-8000-000000000001",
                    b"transaction",
                    b"submit_payment",
                    _H.encode(),
                    _O.encode(),
                    b"2026-01-02T03:04:05+00:00",
                    b"0.25",
                    b"passed",
                    b"Submit payment",
                    b"a,b",
                    b"success",
                    b"payments",
                ]
            )
        ).digest()
        assert action_leaf(**_BASE).digest == expected

    def test_tag_is_frozen(self) -> None:
        assert ACTION_LEAF_TAG == b"merkl-leaf-v1"

    def test_depends_on_is_sorted(self) -> None:
        a = action_leaf(**{**_BASE, "depends_on": ["b", "a"]})
        b = action_leaf(**{**_BASE, "depends_on": ["a", "b"]})
        assert a == b

    def test_depends_on_joined_with_commas(self) -> None:
        one = action_leaf(**{**_BASE, "depends_on": ["a,b"]})
        two = action_leaf(**{**_BASE, "depends_on": ["a", "b"]})
        assert one == two, "known v1 ambiguity: ids never contain commas"

    def test_datetime_and_isoformat_agree(self) -> None:
        when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        assert action_leaf(**{**_BASE, "timestamp": when}) == action_leaf(
            **{**_BASE, "timestamp": when.isoformat()}
        )

    def test_float_and_its_str_agree(self) -> None:
        assert action_leaf(**{**_BASE, "drift_score": 0.25}) == action_leaf(
            **{**_BASE, "drift_score": "0.25"}
        )

    def test_float_rendering_is_pythons_str(self) -> None:
        assert action_leaf(**{**_BASE, "drift_score": 1e-05}) == action_leaf(
            **{**_BASE, "drift_score": "1e-05"}
        )
        assert action_leaf(**{**_BASE, "drift_score": 1e-05}) != action_leaf(
            **{**_BASE, "drift_score": "0.00001"}
        )

    def test_str_enums_are_accepted(self) -> None:
        assert action_leaf(
            **{
                **_BASE,
                "action_type": ActionType.TRANSACTION,
                "guardrail_result": GuardrailResult.PASSED,
                "status": ActionStatus.SUCCESS,
            }
        ) == action_leaf(**_BASE)

    def test_hash_objects_and_hex_agree(self) -> None:
        as_object = {**_BASE, "input_hash": SHA256Hash.from_bytes(b"input")}
        assert action_leaf(**as_object) == action_leaf(**_BASE)

    @pytest.mark.parametrize("bad", ["", "zz", _H.upper(), "gg" * 32, _H[:63]])
    def test_bad_hash_hex_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            action_leaf(**{**_BASE, "input_hash": bad})

    @pytest.mark.parametrize(
        "field,value",
        [
            ("action_id", "other"),
            ("session_id", "other"),
            ("action_type", "tool_call"),
            ("tool_name", "other"),
            ("timestamp", "2026-01-02T03:04:06+00:00"),
            ("drift_score", "0.26"),
            ("guardrail_result", "blocked"),
            ("display_name", "other"),
            ("depends_on", ["c"]),
            ("status", "failed"),
            ("category", "other"),
        ],
    )
    def test_every_field_is_committed(self, field: str, value: Any) -> None:
        assert action_leaf(**{**_BASE, field: value}) != action_leaf(**_BASE)

    def test_field_boundaries_are_separated(self) -> None:
        moved = {**_BASE, "display_name": "Submit", "category": "paymentpayments"}
        assert action_leaf(**moved) != action_leaf(**_BASE)


class TestReceiptLeaf:
    def test_matches_a_hand_written_encoding(self) -> None:
        content = {"source": "system", "content_hash": _H}
        expected = hashlib.sha256(
            b"merkl-receipt-leaf-v1\x00instruction\x00" + canonical_bytes(content)
        ).digest()
        assert receipt_leaf("instruction", content).digest == expected

    def test_tag(self) -> None:
        assert RECEIPT_LEAF_TAG == b"merkl-receipt-leaf-v1"

    def test_null_content_is_the_literal_null(self) -> None:
        expected = hashlib.sha256(b"merkl-receipt-leaf-v1\x00signer_attestation\x00null").digest()
        assert receipt_leaf("signer_attestation", None).digest == expected

    def test_null_differs_per_name(self) -> None:
        assert receipt_leaf("settlement", None) != receipt_leaf("result", None)

    def test_name_is_committed(self) -> None:
        content = {"a": 1}
        assert receipt_leaf("intent", content) != receipt_leaf("result", content)

    def test_key_order_does_not_change_the_leaf(self) -> None:
        assert receipt_leaf("result", {"a": 1, "b": 2}) == receipt_leaf("result", {"b": 2, "a": 1})

    def test_unicode_content(self) -> None:
        leaf = receipt_leaf("reasoning", {"note": "café ☕ — 日本語"})
        assert leaf == receipt_leaf("reasoning", {"note": "café ☕ — 日本語"})

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            receipt_leaf("", {})

    def test_float_content_rejected(self) -> None:
        with pytest.raises(ContentError):
            receipt_leaf("intent", {"amount": {"value": 10.5}})

    def test_name_and_content_cannot_be_shifted(self) -> None:
        assert receipt_leaf("ab", "c") != receipt_leaf("a", "bc")

    @given(
        name=st.sampled_from(["instruction", "intent", "result"]),
        content=st.one_of(st.none(), st.text(), st.integers(-100, 100), st.booleans()),
    )
    def test_leaf_is_deterministic(self, name: str, content: Any) -> None:
        assert receipt_leaf(name, content) == receipt_leaf(name, content)
