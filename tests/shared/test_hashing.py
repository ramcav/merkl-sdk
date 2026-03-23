"""Tests for the SHA256Hash value object."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.shared.hashing import SHA256Hash


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
