"""A deterministic CBOR reader and writer, in the standard library alone.

Why this exists rather than ``cbor2``. ``merkl.core`` is the half of the system a
stranger has to be able to run to check a receipt, and every dependency it grows
is a dependency the auditor, the JS verifier and the enclave image all inherit.
The attestation document needs exactly one profile of CBOR — RFC 8949 core
deterministic encoding, definite lengths, no floats, no tags except COSE's — and
that profile is about two hundred lines. A general decoder would be more code in
the trusted path, not less, and it would accept shapes an attestation document
may not contain.

The writer is not optional either. Verifying a COSE_Sign1 means re-encoding the
``Sig_structure`` array and checking the signature over *those* bytes, so a
verifier that cannot write CBOR cannot verify a signature over CBOR.

What this reader refuses, deliberately, and what each refusal buys:

* **indefinite lengths** — a streamed string has more than one encoding, and two
  encodings of the same value are the beginning of a signature-stripping bug;
* **non-shortest integer heads** — ``0x1817`` and ``0x17`` both say 23, so a
  document could be mutated without changing what it decodes to;
* **floats, and every simple value but ``false``/``true``/``null``** — a receipt
  never contains a fractional number (plan D6) and neither does an attestation
  document;
* **tags other than 18** — COSE_Sign1's own tag is the only one in scope, and it
  is unwrapped rather than represented;
* **duplicate map keys** — the second one silently winning is how a parser and a
  signature verifier come to disagree about what was signed;
* **unbounded nesting and length** — an attacker supplies the document, so depth
  and item counts are bounded before allocation, not after.

Map keys come back as ``int`` or ``str``, which is what the NSM emits (the PCR
map is keyed by integer, the document by name). Byte strings come back as
``bytes``.
"""

from __future__ import annotations

from typing import Final, Union

from merkl.core.canonical import ContentError

__all__ = [
    "COSE_SIGN1_TAG",
    "CborValue",
    "CborError",
    "encode",
    "loads",
    "decode",
]

CborValue = Union[  # noqa: UP007 - recursive alias needs the explicit form
    None,
    bool,
    int,
    bytes,
    str,
    list["CborValue"],
    dict[int | str, "CborValue"],
]

COSE_SIGN1_TAG: Final = 18
"""RFC 9052 §2: the CBOR tag a COSE_Sign1 message may be wrapped in."""

MAX_DEPTH: Final = 16
"""Deeper than any attestation document, shallower than a stack overflow."""

MAX_ITEMS: Final = 4096
"""Cap on the element count of any one array or map, checked before allocating."""

_MAJOR_UINT: Final = 0
_MAJOR_NEGINT: Final = 1
_MAJOR_BYTES: Final = 2
_MAJOR_TEXT: Final = 3
_MAJOR_ARRAY: Final = 4
_MAJOR_MAP: Final = 5
_MAJOR_TAG: Final = 6
_MAJOR_SIMPLE: Final = 7


class CborError(ContentError):
    """The bytes are not the CBOR profile this reader accepts."""

    error_code = "content_error"


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


def loads(data: bytes) -> CborValue:
    """Decode one CBOR item that is the *whole* of ``data``.

    Trailing bytes are an error rather than a shrug: a document with something
    appended is not the document that was signed.
    """
    value, offset = decode(data)
    if offset != len(data):
        raise CborError(f"{len(data) - offset} trailing bytes after the CBOR item")
    return value


def decode(data: bytes, offset: int = 0) -> tuple[CborValue, int]:
    """Decode one item at ``offset``; return it and the offset just past it."""
    return _item(data, offset, 0)


def _head(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return ``(major, argument, next_offset)`` for the head at ``offset``."""
    if offset >= len(data):
        raise CborError("CBOR ended in the middle of an item")
    initial = data[offset]
    major, minor = initial >> 5, initial & 0x1F
    offset += 1
    if minor < 24:
        return major, minor, offset
    if minor == 31:
        raise CborError("indefinite-length CBOR is not accepted")
    if minor > 27:
        raise CborError(f"reserved CBOR additional information {minor}")
    width = 1 << (minor - 24)
    if offset + width > len(data):
        raise CborError("CBOR ended in the middle of an argument")
    argument = int.from_bytes(data[offset : offset + width], "big")
    if major != _MAJOR_SIMPLE and argument < _MINIMUM_FOR_WIDTH[width]:
        raise CborError(
            f"non-canonical CBOR: {argument} is encoded in {width} bytes but fits in fewer"
        )
    return major, argument, offset + width


_MINIMUM_FOR_WIDTH: Final[dict[int, int]] = {1: 24, 2: 256, 4: 65536, 8: 4294967296}


def _item(data: bytes, offset: int, depth: int) -> tuple[CborValue, int]:
    if depth > MAX_DEPTH:
        raise CborError(f"CBOR nested deeper than {MAX_DEPTH}")
    major, argument, offset = _head(data, offset)

    if major == _MAJOR_UINT:
        return argument, offset
    if major == _MAJOR_NEGINT:
        return -1 - argument, offset
    if major in (_MAJOR_BYTES, _MAJOR_TEXT):
        end = offset + argument
        if end > len(data):
            raise CborError("CBOR string runs past the end of the buffer")
        raw = data[offset:end]
        if major == _MAJOR_BYTES:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise CborError("CBOR text string is not valid UTF-8") from exc
    if major == _MAJOR_ARRAY:
        _bound(argument, len(data) - offset, "array")
        items: list[CborValue] = []
        for _ in range(argument):
            value, offset = _item(data, offset, depth + 1)
            items.append(value)
        return items, offset
    if major == _MAJOR_MAP:
        _bound(argument, len(data) - offset, "map")
        mapping: dict[int | str, CborValue] = {}
        for _ in range(argument):
            key, offset = _item(data, offset, depth + 1)
            if not isinstance(key, (int, str)) or isinstance(key, bool):
                raise CborError("CBOR map keys must be integers or text strings")
            if key in mapping:
                raise CborError(f"duplicate CBOR map key {key!r}")
            value, offset = _item(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset
    if major == _MAJOR_TAG:
        if argument != COSE_SIGN1_TAG:
            raise CborError(f"CBOR tag {argument} is not accepted here")
        return _item(data, offset, depth + 1)
    if argument == 20:
        return False, offset
    if argument == 21:
        return True, offset
    if argument == 22:
        return None, offset
    raise CborError(f"CBOR simple value {argument} is not accepted")


def _bound(count: int, remaining: int, kind: str) -> None:
    """Refuse a declared element count before allocating for it."""
    if count > MAX_ITEMS:
        raise CborError(f"CBOR {kind} declares {count} elements, over the {MAX_ITEMS} cap")
    if count > remaining:
        raise CborError(f"CBOR {kind} declares {count} elements but only {remaining} bytes remain")


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def encode(value: CborValue) -> bytes:
    """Encode one value under RFC 8949 §4.2.1 core deterministic encoding.

    Shortest-form heads, definite lengths, map keys ordered by their encoded
    bytes. Round-tripping any value this module decoded gives the original bytes
    back, which is what makes it safe to rebuild a ``Sig_structure``.
    """
    return b"".join(_write(value, 0))


def _write(value: CborValue, depth: int) -> list[bytes]:
    if depth > MAX_DEPTH:
        raise CborError(f"CBOR nested deeper than {MAX_DEPTH}")
    if value is None:
        return [b"\xf6"]
    if value is True:
        return [b"\xf5"]
    if value is False:
        return [b"\xf4"]
    if isinstance(value, int):
        if value >= 0:
            return [_head_bytes(_MAJOR_UINT, value)]
        return [_head_bytes(_MAJOR_NEGINT, -1 - value)]
    if isinstance(value, bytes):
        return [_head_bytes(_MAJOR_BYTES, len(value)), value]
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return [_head_bytes(_MAJOR_TEXT, len(raw)), raw]
    if isinstance(value, list):
        out = [_head_bytes(_MAJOR_ARRAY, len(value))]
        for item in value:
            out.extend(_write(item, depth + 1))
        return out
    if isinstance(value, dict):
        entries = [(encode(key), item) for key, item in value.items()]
        entries.sort(key=lambda pair: pair[0])
        out = [_head_bytes(_MAJOR_MAP, len(entries))]
        for key_bytes, item in entries:
            out.append(key_bytes)
            out.extend(_write(item, depth + 1))
        return out
    raise CborError(f"cannot encode {type(value).__name__} as CBOR")


def _head_bytes(major: int, argument: int) -> bytes:
    if argument < 0:
        raise CborError("CBOR head arguments are never negative")
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    for minor, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * width):
            return bytes([prefix | minor]) + argument.to_bytes(width, "big")
    raise CborError("CBOR argument does not fit in 64 bits")
