"""The in-memory rail's codec — trivial, and present for a reason.

The fake rail's signing payload is a canonical JSON object between a domain tag
and a 32-byte anchor, so "decoding" it is one ``json.loads``. It exists so the
scenario suite exercises the *same* code path on both rails: the signer resolves
a codec, decodes the bytes it is about to sign, and denies on a mismatch. A test
rail that skipped the codec would let a regression in that path reach XRPL first.

Held to the same standard as the real one: an allowlist of fields, and the
anchor compared to the commitment.
"""

from __future__ import annotations

import json
from typing import Any, Final

from merkl.core.canonical import parse_decimal
from merkl.core.intent import Amount, Intent
from merkl.core.rail import ANCHOR_BYTES, ANCHOR_PLACEHOLDER_HEX, MEMO_TYPE, RAIL_FAKE

FAKE_TX_TAG: Final = b"merkl-fake-tx-v1"

ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {"account", "destination", "amount", "memo_type", "sequence", "fee"}
)

SWAP_FIELDS: Final[frozenset[str]] = ALLOWED_FIELDS | {"send_max"}
"""A trade adds exactly one field, the sell ceiling — the fake rail's ``SendMax``."""


class FakePayloadCodec:
    """Reads the in-memory rail's payload and holds it against the intent."""

    rail = RAIL_FAKE

    def decode_payload(self, payload: bytes) -> dict[str, Any]:
        prefix = FAKE_TX_TAG + b"\x00"
        if not payload.startswith(prefix):
            raise ValueError("payload does not begin with the fake-rail tag")
        body = payload[len(prefix) : -(ANCHOR_BYTES + 1)]
        decoded: dict[str, Any] = json.loads(body.decode())
        return decoded

    def anchor(self, payload: bytes) -> str:
        return payload[-ANCHOR_BYTES:].hex()

    def problems(
        self, payload: bytes, intent: Intent, commitment: str | None, **_: object
    ) -> list[str]:
        try:
            fields = self.decode_payload(payload)
        except Exception as exc:
            return [f"the payload does not decode as a fake-rail transaction: {exc}"]

        found: list[str] = []
        unknown = sorted(set(fields) - (SWAP_FIELDS if intent.is_swap else ALLOWED_FIELDS))
        if unknown:
            found.append(f"the transaction carries unexpected fields: {unknown}")
        if fields.get("account") != intent.treasury:
            found.append(
                f"account is {fields.get('account')!r}, the intent pays from {intent.treasury!r}"
            )
        if fields.get("destination") != intent.destination:
            found.append(
                f"destination is {fields.get('destination')!r}, the intent pays "
                f"{intent.destination!r}"
            )
        found.extend(_amount_problems(fields.get("amount"), intent.deliver_amount, "amount"))
        if intent.is_swap:
            found.extend(_amount_problems(fields.get("send_max"), intent.outflow, "send_max"))
        elif fields.get("send_max") is not None:
            found.append("a payment carries no send_max; this transaction names one")
        if fields.get("memo_type") != MEMO_TYPE:
            found.append(f"anchor field is tagged {fields.get('memo_type')!r}, not {MEMO_TYPE!r}")

        expected = (commitment or ANCHOR_PLACEHOLDER_HEX).lower()
        if self.anchor(payload) != expected:
            found.append(
                f"the anchor holds {self.anchor(payload)}, the authorization commitment "
                f"is {expected}"
            )
        return found


def _amount_problems(observed: Any, expected: Amount, field: str) -> list[str]:
    """One amount object against one amount the intent names."""
    if not isinstance(observed, dict):
        return [f"the transaction carries no {field} object"]
    wanted = expected.to_content()
    if observed.get("currency") != wanted["currency"]:
        return [
            f"{field} currency is {observed.get('currency')!r}, the intent is "
            f"{wanted['currency']!r}"
        ]
    try:
        value = parse_decimal(str(observed.get("value", "")), f"{field}.value")
    except Exception:
        return [f"{field} value {observed.get('value')!r} is not a decimal"]
    if value != expected.decimal:
        return [f"{field} is {value}, the intent is {expected.decimal}"]
    return []
