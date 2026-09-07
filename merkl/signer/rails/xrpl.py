"""Verify-only XRPL codec: what do these bytes actually say?

Decodes an XRPL multisigning payload with ``xrpl.core.binarycodec.decode`` — pure,
offline, no client — and compares the result to the intent. This is the module
that makes the policy signature mean something: without it the signer signs an
adapter's bytes on an adapter's description of them.

The payload is `encode_for_multisigning` output, which wraps the signing-only
serialization:

```
534D5400 ‖ <transaction, signing fields only> ‖ <signer AccountID, 20 bytes>
```

so the prefix and suffix come off before decoding.

Every field is on an allowlist. XRPL has several ways to make a Payment deliver
something other than `Amount` to `Destination` — `SendMax`, `DeliverMin`, `Paths`
and `tfPartialPayment` between them — and Intent v1 expresses none of them, so
their *presence* is the finding. `DestinationTag` is on the same footing: an
exchange treats it as part of the address, and an intent that does not name one
must not settle with one.

Issued amounts need one piece of care. XRPL normalises an issued amount's
mantissa, so `"250.00"` comes back as `"250"`. The comparison is therefore
numeric, over `decimal.Decimal` parsed from canonical decimal strings — never
string equality, and never a float.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Final

from xrpl.core.binarycodec import decode
from xrpl.utils import xrp_to_drops

from merkl.core.canonical import parse_decimal
from merkl.core.intent import Intent, IssuedCurrency
from merkl.core.rail import (
    ANCHOR_PLACEHOLDER_HEX,
    MEMO_TYPE,
    NETWORK_XRPL_MAINNET,
    NETWORK_XRPL_TESTNET,
    RAIL_XRPL,
)

MULTISIGN_PREFIX: Final = bytes.fromhex("534D5400")
ACCOUNT_ID_BYTES: Final = 20

PAYMENT: Final = "Payment"

NETWORK_IDS: Final[dict[str, int]] = {
    NETWORK_XRPL_MAINNET: 0,
    NETWORK_XRPL_TESTNET: 1,
}
"""rippled's chain ids for the two networks a policy may name."""

NETWORK_ID_FLOOR: Final = 1024
"""Below this, rippled *rejects* a transaction that carries ``NetworkID`` at all.

That is the honest limit of what a payload can prove about its chain. Mainnet is
network 0 and testnet is network 1, so neither carries the field, and the same
signed bytes are valid on both — the two chains differ in their validator sets,
not in anything inside a Payment. So the codec's rule is only "a NetworkID, if
present, must not contradict the policy", and the real agreement between a
treasury and a chain is made at boot, where the signer holds its configured rail
endpoint against ``policy.network`` (``merkl.signer.rails.network_of_endpoint``)
and refuses to serve a testnet policy from a mainnet node. Documented rather than
papered over: a verifier reading a receipt cannot tell the chains apart either,
which is exactly why the policy has to name one."""

ALLOWED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "TransactionType",
        "Account",
        "Destination",
        "Amount",
        "Fee",
        "Sequence",
        "LastLedgerSequence",
        "SigningPubKey",
        "Memos",
        "Flags",
        "NetworkID",
    }
)
"""Everything Intent v1 can account for. Anything else is a finding, not a detail."""

TF_FULLY_CANONICAL_SIG: Final = 0x80000000
"""The one flag with no effect on where the money goes."""

STANDARD_CODE_LENGTH: Final = 3
HEX_CODE_LENGTH: Final = 40


def _currency_code(code: str) -> str:
    """The on-ledger form of a currency code, so `RLUSD` compares to `524C…`."""
    if len(code) == STANDARD_CODE_LENGTH:
        return code
    if len(code) == HEX_CODE_LENGTH:
        return code.upper()
    return code.encode().hex().upper().ljust(HEX_CODE_LENGTH, "0")


class XrplPayloadCodec:
    """Reads an XRPL multisigning payload and holds it against the intent."""

    rail = RAIL_XRPL

    def __init__(self, network: str | None = None) -> None:
        if network is not None and network not in NETWORK_IDS:
            raise ValueError(f"unknown xrpl network {network!r}")
        self._network = network

    def decode_payload(self, payload: bytes) -> dict[str, Any]:
        """The transaction inside a multisigning payload, as plain JSON."""
        if not payload.startswith(MULTISIGN_PREFIX):
            raise ValueError("payload does not begin with the multisigning prefix 534D5400")
        inner = payload[len(MULTISIGN_PREFIX) : -ACCOUNT_ID_BYTES]
        if not inner:
            raise ValueError("payload has no transaction between its prefix and suffix")
        decoded: dict[str, Any] = decode(inner.hex().upper())
        return decoded

    def problems(self, payload: bytes, intent: Intent, commitment: str | None) -> list[str]:
        """Every disagreement between these bytes and this intent."""
        try:
            tx = self.decode_payload(payload)
        except Exception as exc:
            return [f"the payload does not decode as an XRPL transaction: {exc}"]

        found: list[str] = []
        unknown = sorted(set(tx) - ALLOWED_FIELDS)
        if unknown:
            found.append(f"the transaction carries fields Intent v1 cannot account for: {unknown}")

        if tx.get("TransactionType") != PAYMENT:
            found.append(f"TransactionType is {tx.get('TransactionType')!r}, not {PAYMENT!r}")
        if tx.get("Account") != intent.treasury:
            found.append(
                f"Account is {tx.get('Account')!r}, the intent pays from {intent.treasury!r}"
            )
        if tx.get("Destination") != intent.destination:
            found.append(
                f"Destination is {tx.get('Destination')!r}, the intent pays {intent.destination!r}"
            )

        found.extend(self._amount_problems(tx.get("Amount"), intent))
        found.extend(self._flag_problems(tx.get("Flags")))
        found.extend(self._network_problems(tx.get("NetworkID")))
        found.extend(self._memo_problems(tx.get("Memos"), commitment))
        return found

    # -- pieces ------------------------------------------------------------ #

    def _network_problems(self, network_id: Any) -> list[str]:
        """Whether ``NetworkID`` contradicts the chain the policy governs.

        See :data:`NETWORK_ID_FLOOR`: on mainnet and testnet the field must be
        absent, so its *presence* is the finding, and its absence proves nothing.
        """
        if self._network is None:
            return []
        expected = NETWORK_IDS[self._network]
        if network_id is None:
            return []
        if isinstance(network_id, bool) or not isinstance(network_id, int):
            return [f"NetworkID is {network_id!r}, which is not an integer"]
        if network_id != expected:
            return [
                f"NetworkID is {network_id}, but this policy governs {self._network}, "
                f"which is network {expected}"
            ]
        if expected < NETWORK_ID_FLOOR:
            return [
                f"the transaction carries NetworkID {network_id}; {self._network} is "
                f"network {expected}, below the {NETWORK_ID_FLOOR} at which rippled "
                "expects the field, so these bytes would be rejected by the chain the "
                "policy names"
            ]
        return []

    def _amount_problems(self, amount: Any, intent: Intent) -> list[str]:
        currency = intent.amount.currency
        wanted = parse_decimal(intent.amount.value, "intent.amount.value")

        if isinstance(currency, IssuedCurrency):
            if not isinstance(amount, dict):
                return [f"Amount is drops, the intent is {currency.code}"]
            code = str(amount.get("currency", ""))
            if code.upper() != _currency_code(currency.code):
                return [
                    f"Amount currency is {code!r}, the intent is {currency.code!r} "
                    f"({_currency_code(currency.code)})"
                ]
            if amount.get("issuer") != currency.issuer:
                return [
                    f"Amount issuer is {amount.get('issuer')!r}, the intent names "
                    f"{currency.issuer!r}"
                ]
            try:
                # XRPL normalises an issued mantissa: "250.00" comes back as "250".
                delivered = Decimal(str(amount.get("value", "")))
            except Exception:
                return [f"Amount value {amount.get('value')!r} is not a number"]
            if delivered != wanted:
                return [f"Amount is {delivered} {currency.code}, the intent is {wanted}"]
            return []

        if isinstance(amount, dict):
            return [f"Amount is an issued currency, the intent is {currency}"]
        expected = str(xrp_to_drops(wanted))
        if str(amount) != expected:
            return [f"Amount is {amount} drops, the intent is {expected} drops"]
        return []

    def _flag_problems(self, flags: Any) -> list[str]:
        if flags in (None, 0):
            return []
        if not isinstance(flags, int):
            return [f"Flags is {flags!r}, which is not an integer"]
        meaningful = flags & ~TF_FULLY_CANONICAL_SIG
        if meaningful:
            return [
                f"Flags {hex(flags)} changes how the payment delivers "
                "(tfPartialPayment, tfLimitQuality or tfNoRippleDirect); "
                "Intent v1 expresses none of them"
            ]
        return []

    def _memo_problems(self, memos: Any, commitment: str | None) -> list[str]:
        expected_type = MEMO_TYPE.encode().hex().upper()
        expected_data = (commitment or ANCHOR_PLACEHOLDER_HEX).upper()
        if not isinstance(memos, list) or not memos:
            return ["the transaction carries no memo, so it anchors no authorization"]
        if len(memos) != 1:
            return [
                f"the transaction carries {len(memos)} memos; exactly one is the "
                "authorization anchor and a second is somewhere to hide something"
            ]
        entry = memos[0]
        memo = entry.get("Memo", entry) if isinstance(entry, dict) else {}
        if not isinstance(memo, dict):
            return ["the memo is not an object"]
        unknown = sorted(set(memo) - {"MemoType", "MemoData", "MemoFormat"})
        if unknown:
            return [f"the memo carries unexpected members: {unknown}"]
        if str(memo.get("MemoType", "")).upper() != expected_type:
            return [f"MemoType is {memo.get('MemoType')!r}, not the Merkl anchor ({MEMO_TYPE})"]
        if str(memo.get("MemoData", "")).upper() != expected_data:
            return [
                f"MemoData is {memo.get('MemoData')!r}, the authorization commitment "
                f"is {expected_data}"
            ]
        return []
