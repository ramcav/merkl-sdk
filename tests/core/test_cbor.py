"""The CBOR profile: round-trips, refusals, and the RFC's own examples."""

from __future__ import annotations

import base64
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkl.core.vectors.attestation import DOCUMENTS_FILE
from merkl.core.verify import cbor

# RFC 8949 appendix A, the definite-length subset this reader accepts.
RFC_VECTORS = [
    ("00", 0),
    ("01", 1),
    ("17", 23),
    ("1818", 24),
    ("1903e8", 1000),
    ("1a000f4240", 1000000),
    ("1b000000e8d4a51000", 1000000000000),
    ("20", -1),
    ("3863", -100),
    ("3903e7", -1000),
    ("f4", False),
    ("f5", True),
    ("f6", None),
    ("40", b""),
    ("4401020304", b"\x01\x02\x03\x04"),
    ("60", ""),
    ("6161", "a"),
    ("6449455446", "IETF"),
    ("80", []),
    ("83010203", [1, 2, 3]),
    ("a0", {}),
    ("a201020304", {1: 2, 3: 4}),
    ("a26161016162820203", {"a": 1, "b": [2, 3]}),
    ("826161a161626163", ["a", {"b": "c"}]),
]


@pytest.mark.parametrize("hexed,expected", RFC_VECTORS, ids=[h for h, _ in RFC_VECTORS])
def test_rfc_8949_examples_decode(hexed: str, expected: object) -> None:
    assert cbor.loads(bytes.fromhex(hexed)) == expected


@pytest.mark.parametrize("hexed,value", RFC_VECTORS, ids=[h for h, _ in RFC_VECTORS])
def test_rfc_8949_examples_re_encode_to_the_same_bytes(hexed: str, value: object) -> None:
    """Deterministic encoding: one value, one encoding, or a signature is checkable
    over bytes nobody can reproduce."""
    assert cbor.encode(value).hex() == hexed  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "hexed,why",
    [
        ("5f42010243030405ff", "indefinite-length byte string"),
        ("7f6161ff", "indefinite-length text string"),
        ("9fff", "indefinite-length array"),
        ("bfff", "indefinite-length map"),
        ("1817", "24 encoded in one extra byte instead of the shortest form"),
        ("190017", "23 encoded in two bytes"),
        ("fb3ff199999999999a", "a float"),
        ("f97e00", "a half float"),
        ("f0", "an unassigned simple value"),
        ("c11a514b67b0", "an epoch-time tag"),
        ("a2616101616101", "duplicate map keys"),
        ("a141610161620102", "a byte-string map key"),
        ("64494554", "a text string that runs past the end"),
        ("8301", "an array shorter than it declares"),
        ("0000", "trailing bytes"),
        ("", "no bytes at all"),
        ("1c", "a reserved additional-information value"),
        ("62ff41", "text that is not UTF-8"),
    ],
)
def test_the_reader_refuses_what_it_says_it_refuses(hexed: str, why: str) -> None:
    with pytest.raises(cbor.CborError):
        cbor.loads(bytes.fromhex(hexed))


def test_cose_sign1_tag_is_unwrapped() -> None:
    """RFC 9052 allows the tag; the NSM omits it. Both must decode the same."""
    untagged = cbor.encode([b"\x01", {}, b"\x02", b"\x03"])
    assert cbor.loads(b"\xd2" + untagged) == cbor.loads(untagged)


def test_nesting_is_bounded() -> None:
    deep = b"\x81" * (cbor.MAX_DEPTH + 2) + b"\x00"
    with pytest.raises(cbor.CborError, match="deeper"):
        cbor.loads(deep)


def test_a_huge_declared_length_is_refused_before_allocating() -> None:
    """``0x9b`` + 2^63 elements, in nine bytes. A reader that trusts the count dies."""
    with pytest.raises(cbor.CborError):
        cbor.loads(bytes.fromhex("9b7fffffffffffffff"))


def test_map_keys_are_ordered_by_their_encoding() -> None:
    """RFC 8949 4.2.1: sort by encoded key bytes, so 10 precedes -1 and "a"."""
    encoded = cbor.encode({"aa": 1, "b": 2, 10: 3, -1: 4})
    assert encoded.hex() == "a4" + "0a03" + "2004" + "616202" + "62616101"


@given(
    st.recursive(
        st.none()
        | st.booleans()
        | st.integers(min_value=-(2**64), max_value=2**64 - 1)
        | st.binary(max_size=32)
        | st.text(max_size=32),
        lambda children: st.lists(children, max_size=6)
        | st.dictionaries(st.integers(-100, 100) | st.text(max_size=8), children, max_size=6),
        max_leaves=20,
    )
)
def test_encode_then_decode_is_the_identity(value: cbor.CborValue) -> None:
    assert cbor.loads(cbor.encode(value)) == value


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers(-1000, 1000) | st.binary(max_size=16),
        lambda children: st.lists(children, max_size=4),
        max_leaves=12,
    )
)
def test_encoding_is_deterministic(value: cbor.CborValue) -> None:
    """Decoding then re-encoding gives the original bytes back, which is what makes
    it safe to rebuild a Sig_structure from a parsed document."""
    encoded = cbor.encode(value)
    assert cbor.encode(cbor.loads(encoded)) == encoded


def test_the_real_documents_are_in_this_profile() -> None:
    """The refusals above are only worth having if AWS's own bytes get through."""
    body = json.loads(DOCUMENTS_FILE.read_text(encoding="utf-8"))
    for entry in body["documents"]:
        message = cbor.loads(base64.b64decode(entry["document_b64"]))
        assert isinstance(message, list) and len(message) == 4
        payload = message[2]
        assert isinstance(payload, bytes)
        assert isinstance(cbor.loads(payload), dict)
