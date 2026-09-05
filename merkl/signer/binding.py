"""Binding evidence: does the payload really describe the transaction it claims?

The signer checks the adapter's *fields* against the intent, which is the
authoritative comparison. But the bytes it signs come from the adapter too, and
an adapter that lied about which fields those bytes encode would get a signature
over a payment to somewhere else. Closing that gap completely needs a rail
serializer inside the signer, which this phase does not build (see
``docs/SIGNER-RPC.md``, "What the signer cannot check yet").

What it does instead is cheap and pure: decode the destination and treasury
addresses itself and require their raw account ids to appear in the payload. An
adapter can still append fields the signer cannot see, so this is evidence rather
than proof — but a payload that does not even mention the destination is refused
outright, and that is the case a bug produces.

XRPL base58 is its own alphabet with a double-SHA-256 checksum; decoding it is
thirty lines of arithmetic and no dependency, so the signer keeps depending on
``merkl.core`` and ``merkl.shared`` alone.
"""

from __future__ import annotations

import hashlib
from typing import Final

XRPL_ALPHABET: Final = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
ACCOUNT_ID_BYTES: Final = 20
CLASSIC_ADDRESS_PREFIX: Final = 0x00


class BindingError(ValueError):
    """Raised when an address cannot be decoded at all."""


def decode_classic_address(address: str) -> bytes:
    """The 20-byte account id inside an XRPL classic address (``r...``).

    Rejects a bad checksum rather than returning something plausible: a
    mistyped destination must fail loudly at the signer, not settle to an
    address nobody owns.
    """
    number = 0
    for character in address:
        index = XRPL_ALPHABET.find(character)
        if index < 0:
            raise BindingError(f"{character!r} is not in the XRPL base58 alphabet")
        number = number * 58 + index
    raw = number.to_bytes(25, "big")
    if raw[0] != CLASSIC_ADDRESS_PREFIX:
        raise BindingError(f"address {address!r} is not a classic account address")
    body, checksum = raw[:21], raw[21:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        raise BindingError(f"address {address!r} has a bad checksum")
    return body[1:]


def account_id(rail: str, address: str) -> bytes | None:
    """The raw account identifier a rail puts in its binary form, if we know how."""
    if rail == "xrpl":
        return decode_classic_address(address)
    return None


def missing_bindings(rail: str, payload: bytes, addresses: dict[str, str]) -> list[str]:
    """Which of these addresses do not appear in the payload at all.

    An empty list is the good case. A rail this function does not understand also
    returns an empty list — it has no evidence to offer, which the caller reports
    rather than mistaking for agreement.
    """
    missing: list[str] = []
    for label, address in addresses.items():
        try:
            identifier = account_id(rail, address)
        except BindingError as exc:
            missing.append(f"{label} ({exc})")
            continue
        if identifier is not None and identifier not in payload:
            missing.append(label)
    return missing
