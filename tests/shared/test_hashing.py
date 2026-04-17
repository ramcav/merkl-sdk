"""Tests for the SHA256Hash value object."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.shared.hashing import SHA256Hash, canonical_bytes, canonical_hash


class TestSHA256Hash:
    def test_from_bytes_deterministic(self) -> None:
        h1 = SHA256Hash.from_bytes(b"hello witness")
        h2 = SHA256Hash.from_bytes(b"hello witness")
        assert h1 == h2

    def test_different_inputs_different_hashes(self) -> None:
        h1 = SHA256Hash.from_bytes(b"action_1")
        h2 = SHA256Hash.from_bytes(b"action_2")
        assert h1 != h2

    def test_hex_returns_64_char_string(self) -> None:
        h = SHA256Hash.from_bytes(b"test data")
        hex_str = h.hex()
        assert len(hex_str) == 64
        assert all(c in "0123456789abcdef" for c in hex_str)

    def test_immutable(self) -> None:
        h = SHA256Hash.from_bytes(b"frozen")
        with pytest.raises(dataclasses.FrozenInstanceError):
            h.digest = b"tampered"  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        h1 = SHA256Hash.from_bytes(b"same")
        h2 = SHA256Hash.from_bytes(b"same")
        h3 = SHA256Hash.from_bytes(b"different")
        assert h1 == h2
        assert h1 != h3

    def test_bytes_property(self) -> None:
        h = SHA256Hash.from_bytes(b"data")
        assert isinstance(h.bytes, bytes)
        assert len(h.bytes) == 32

    def test_rejects_invalid_digest_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            SHA256Hash(digest=b"too short")


class TestSHA256HashProperties:
    @given(data=st.binary(min_size=0, max_size=1024))
    def test_hex_always_64_chars(self, data: bytes) -> None:
        h = SHA256Hash.from_bytes(data)
        assert len(h.hex()) == 64

    @given(
        a=st.binary(min_size=1, max_size=512),
        b=st.binary(min_size=1, max_size=512),
    )
    def test_different_inputs_produce_different_hashes(self, a: bytes, b: bytes) -> None:
        if a == b:
            return
        assert SHA256Hash.from_bytes(a) != SHA256Hash.from_bytes(b)


class TestCanonicalHash:
    def test_dict_key_order_independent(self) -> None:
        a = {"b": 2, "a": 1, "c": 3}
        b = {"c": 3, "a": 1, "b": 2}
        assert canonical_hash(a) == canonical_hash(b)

    def test_nested_dict_key_order_independent(self) -> None:
        a = {"outer": {"b": 2, "a": 1}, "z": [1, 2, 3]}
        b = {"z": [1, 2, 3], "outer": {"a": 1, "b": 2}}
        assert canonical_hash(a) == canonical_hash(b)

    def test_list_order_matters(self) -> None:
        assert canonical_hash([1, 2, 3]) != canonical_hash([3, 2, 1])

    def test_different_values_differ(self) -> None:
        assert canonical_hash({"x": 1}) != canonical_hash({"x": 2})

    def test_non_json_types_use_str(self) -> None:
        class Obj:
            def __str__(self) -> str:
                return "abc"

        expected = canonical_bytes("abc")
        assert canonical_bytes(Obj()) == expected

    def test_bytes_output_is_deterministic(self) -> None:
        payload = {"agent": "a", "goal": "g", "tools": ["t1", "t2"]}
        assert canonical_bytes(payload) == canonical_bytes(payload)

    def test_matches_session_context_hash(self) -> None:
        """Regression: SessionContext and hooks/claude_code.py must agree."""
        from merkl.hooks.claude_code import _sha256

        payload = {"b": 2, "a": 1, "nested": {"y": "z", "x": [1, 2]}}
        assert _sha256(payload) == canonical_hash(payload).hex()
