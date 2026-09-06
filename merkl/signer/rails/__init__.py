"""Rail payload codecs — the signer reads the bytes it is about to sign.

The settlement adapter runs in the **agent's** process. That is the party the
whole product assumes may be compromised, and until now the signer took its word
for what the payload encoded: it compared the adapter's reported *fields* to the
intent, and signed the adapter's *bytes*. A hostile adapter could report an
honest destination over bytes that pay someone else, and the policy signature
would bless it.

A codec closes that. It decodes the exact bytes the signer is about to sign —
after the anchor write — and compares the decoded transaction to the intent field
by field. Only then does the key move.

Two rules shape what a codec may be:

* **Verify-only.** A codec never builds a transaction and never reaches a
  network. Decoding is a pure function of bytes, so it can live inside an enclave
  and be reasoned about in isolation.
* **Allowlist, not blocklist.** A codec names the fields it understands and
  refuses everything else. A blocklist is a promise to have thought of every
  dangerous field; XRPL alone has `SendMax`, `DeliverMin`, `Paths`,
  `DestinationTag` and a partial-payment flag, and the next rail will have
  others.

The signer resolves its codec at boot from the treasury's rail and refuses to
start without one. Codecs live behind their own extras (`signer-xrpl`) so a
signer for one rail does not carry another rail's library: ``merkl.signer``'s
base stays dependent on ``merkl.core`` and ``merkl.shared`` alone, and only the
codec module for the configured rail imports anything else.
"""

from __future__ import annotations

from typing import Protocol

from merkl.core.intent import Intent
from merkl.core.rail import RAIL_FAKE, RAIL_XRPL
from merkl.shared.errors import MerklError

RULE_PAYLOAD_ENCODES_INTENT = "rail.payload_encodes_intent"
"""The rule name a mismatch is reported under, in the decision and the receipt."""


class CodecUnavailable(MerklError):
    """Raised at boot when no codec exists for the rail the signer must serve."""

    error_code = "signer_codec_unavailable"


class RailCodec(Protocol):
    """What the signer needs in order to read a rail's signing payload."""

    rail: str

    def problems(self, payload: bytes, intent: Intent, commitment: str | None) -> list[str]:
        """Everything about ``payload`` that disagrees with ``intent``.

        An empty list means the bytes encode exactly this payment and nothing
        else. ``commitment`` is the anchor the payload must carry, or ``None``
        when the anchor should still hold the placeholder.

        Never raises for a hostile payload: undecodable bytes are a finding like
        any other, because the caller turns findings into a denial with a receipt.
        """
        ...


_EXTRAS = {RAIL_XRPL: "signer-xrpl"}


def codec_for(rail: str) -> RailCodec:
    """The codec for one rail, or a refusal naming the extra that provides it.

    Imported lazily so a signer only ever loads the rail library it was
    configured for.
    """
    if rail == RAIL_XRPL:
        try:
            from merkl.signer.rails.xrpl import XrplPayloadCodec
        except ImportError as exc:  # pragma: no cover - depends on how it was installed
            raise CodecUnavailable(
                f"the {rail} payload codec needs xrpl-py: "
                f"pip install 'merkl-sdk[{_EXTRAS[rail]}]'"
            ) from exc
        return XrplPayloadCodec()
    if rail == RAIL_FAKE:
        from merkl.signer.rails.fake import FakePayloadCodec

        return FakePayloadCodec()
    raise CodecUnavailable(
        f"no payload codec for rail {rail!r}. The signer will not sign bytes it "
        "cannot read, so it refuses to serve this treasury."
    )


def available_rails() -> tuple[str, ...]:
    """Rails this build can decode, in the order a caller should prefer them."""
    return (RAIL_XRPL, RAIL_FAKE)


__all__ = [
    "RULE_PAYLOAD_ENCODES_INTENT",
    "CodecUnavailable",
    "RailCodec",
    "available_rails",
    "codec_for",
]
