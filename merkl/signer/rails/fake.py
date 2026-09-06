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
from merkl.core.intent import Intent
from merkl.core.rail import ANCHOR_BYTES, ANCHOR_PLACEHOLDER_HEX, MEMO_TYPE, RAIL_FAKE

FAKE_TX_TAG: Final = b"merkl-fake-tx-v1"

ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {"account", "destination", "amount", "memo_type", "sequence", "fee"}
)


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

    def problems(self, payload: bytes, intent: Intent, commitment: str | None) -> list[str]:
        try:
            fields = self.decode_payload(payload)
        except Exception as exc:
            return [f"the payload does not decode as a fake-rail transaction: {exc}"]

        found: list[str] = []
        unknown = sorted(set(fields) - ALLOWED_FIELDS)
        if unknown:
            found.append(f"the transaction carries unexpected fields: {unknown}")
        if fields.get("account") != intent.treasury:
            found.append(
                f"account is {fields.get('account')!r}, the intent pays from "
                f"{intent.treasury!r}"
            )
        if fields.get("destination") != intent.destination:
            found.append(
                f"destination is {fields.get('destination')!r}, the intent pays "
                f"{intent.destination!r}"
            )
        amount = fields.get("amount")
        if not isinstance(amount, dict):
            found.append("the transaction carries no amount object")
        else:
            wanted = intent.amount.to_content()
            if amount.get("currency") != wanted["currency"]:
                found.append(
                    f"amount currency is {amount.get('currency')!r}, the intent is "
                    f"{wanted['currency']!r}"
                )
            else:
                try:
                    delivered = parse_decimal(str(amount.get("value", "")), "amount.value")
                except Exception:
                    found.append(f"amount value {amount.get('value')!r} is not a decimal")
                else:
                    if delivered != intent.amount.decimal:
                        found.append(
                            f"amount is {delivered}, the intent is {intent.amount.decimal}"
                        )
        if fields.get("memo_type") != MEMO_TYPE:
            found.append(f"anchor field is tagged {fields.get('memo_type')!r}, not {MEMO_TYPE!r}")

        expected = (commitment or ANCHOR_PLACEHOLDER_HEX).lower()
        if self.anchor(payload) != expected:
            found.append(
                f"the anchor holds {self.anchor(payload)}, the authorization commitment "
                f"is {expected}"
            )
        return found
