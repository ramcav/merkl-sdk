"""XRPL settlement: a multisigned Payment whose memo is the authorization commitment.

The rail Merkl launches on, and the reason the receipt format looks the way it
does. Three XRPL facts shape the design:

* **Memos are inside the signed transaction.** The anchor cannot be edited after
  the fact, cannot be added by anyone else, and is republished by every validator
  — so ``anchor_capability()`` is ``immutable`` and the memo is a real commitment
  rather than a note.
* **Multisigning is per-signer.** Each signer signs
  ``encode_for_multisigning(tx, their_own_address)``, so the agent and the policy
  key sign *different* bytes over the same transaction. The signer's payload is
  the one this adapter puts in ``UnsignedTx``; the agent's is derived here.
* **A transaction id is a hash of the blob.** ``SHA-512Half("TXN" ‖ blob)``, which
  means a verifier with the receipt alone can re-derive the id offline and check
  the receipt names the transaction it carries.

Issued currencies need one piece of local knowledge: XRPL currency codes are
three characters or forty hex digits, so ``RLUSD`` travels on the ledger as
``524C555344…`` padded to twenty bytes. :func:`currency_code` does that
conversion in one place.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

from xrpl.asyncio.clients import AsyncJsonRpcClient, AsyncWebsocketClient
from xrpl.asyncio.transaction import autofill, sign, submit_and_wait
from xrpl.core import keypairs
from xrpl.core.binarycodec import encode, encode_for_multisigning
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.models.requests import AccountTx, Ledger, Subscribe, Tx
from xrpl.models.requests.subscribe import StreamParameter
from xrpl.models.response import Response
from xrpl.models.transactions import Memo, Payment, Signer
from xrpl.utils import xrp_to_drops
from xrpl.wallet import Wallet

from merkl.core.canonical import JSONObject, JSONValue, format_instant, parse_decimal
from merkl.core.intent import Amount, Intent, IssuedCurrency
from merkl.core.policy.document import asset_key
from merkl.core.policy.state import Outflow
from merkl.core.rail import (
    ANCHOR_BYTES,
    ANCHOR_PLACEHOLDER,
    ANCHOR_PLACEHOLDER_HEX,
    MEMO_TYPE,
    RAIL_XRPL,
    AnchorCapability,
    PartialTx,
    RailError,
    SettlementProof,
    SettlementRef,
    Signature,
    SignedTx,
    UnsignedTx,
)

TESTNET_JSON_RPC: Final = "https://s.altnet.rippletest.net:51234"
TESTNET_WEBSOCKET: Final = "wss://s.altnet.rippletest.net:51233"
MAINNET_JSON_RPC: Final = "https://xrplcluster.com"
MAINNET_WEBSOCKET: Final = "wss://xrplcluster.com"

RIPPLE_EPOCH_OFFSET: Final = 946_684_800
"""Seconds between the Unix epoch and 2000-01-01, which is when XRPL time starts."""

NATIVE: Final = "XRP"
STANDARD_CODE_LENGTH: Final = 3
HEX_CODE_LENGTH: Final = 40


class XrplAdapterError(RailError):
    """Raised when the adapter cannot build, sign or read an XRPL transaction."""

    error_code = "xrpl_adapter_error"


def currency_code(code: str) -> str:
    """XRPL's on-ledger form of a currency code.

    Three characters travel as themselves; anything longer becomes the ASCII
    bytes padded to twenty, in hex. ``RLUSD`` is five characters, so this is not
    an edge case — it is the first currency the product cares about.
    """
    if len(code) == STANDARD_CODE_LENGTH:
        return code
    if len(code) == HEX_CODE_LENGTH:
        return code.upper()
    encoded = code.encode()
    if len(encoded) > 20:
        raise XrplAdapterError(f"currency code {code!r} is longer than 20 bytes")
    return encoded.hex().upper().ljust(HEX_CODE_LENGTH, "0")


def to_xrpl_amount(amount: Amount) -> str | IssuedCurrencyAmount:
    """Drops for XRP, an issued amount otherwise. Never a float, at any point."""
    currency = amount.currency
    if isinstance(currency, IssuedCurrency):
        return IssuedCurrencyAmount(
            currency=currency_code(currency.code), issuer=currency.issuer, value=amount.value
        )
    if currency != NATIVE:
        raise XrplAdapterError(f"XRPL's native asset is XRP, not {currency!r}")
    return str(xrp_to_drops(Decimal(amount.value)))


def ripple_time(value: int) -> str:
    """A Ripple-epoch timestamp as a canonical instant."""
    return format_instant(datetime.fromtimestamp(value + RIPPLE_EPOCH_OFFSET, tz=UTC))


def signer_address(policy_public_key: str) -> str:
    """The XRPL account for an Ed25519 policy key.

    XRPL prefixes Ed25519 public keys with ``ED``, which is how it tells them from
    secp256k1. The signer never needs to know this: it holds a raw key and the
    rail's naming convention lives at the rail's edge.
    """
    return str(keypairs.derive_classic_address("ED" + policy_public_key.upper()))


class XrplSettlementAdapter:
    """XRPL as a :class:`~merkl.core.ports.SettlementPort`."""

    def __init__(
        self,
        *,
        treasury: str,
        agent_wallet: Wallet,
        policy_public_key: str,
        json_rpc_url: str = TESTNET_JSON_RPC,
        websocket_url: str | None = TESTNET_WEBSOCKET,
        signers_count: int = 2,
        capture_validations: bool = True,
    ) -> None:
        self._treasury = treasury
        self._agent = agent_wallet
        self._policy_public_key = policy_public_key
        self._policy_address = signer_address(policy_public_key)
        self._client = AsyncJsonRpcClient(json_rpc_url)
        self._websocket_url = websocket_url
        self._signers_count = signers_count
        self._capture = capture_validations
        self._prepared: dict[str, Payment] = {}
        self._proofs: dict[str, SettlementProof] = {}
        self._validations: list[JSONValue] = []
        self._validation_task: asyncio.Task[None] | None = None

    @property
    def policy_address(self) -> str:
        return self._policy_address

    @property
    def agent_address(self) -> str:
        return str(self._agent.classic_address)

    def anchor_capability(self) -> AnchorCapability:
        """The memo is inside the signed, validated transaction. Nobody can edit it."""
        return AnchorCapability.IMMUTABLE

    # -- prepare ----------------------------------------------------------- #

    async def prepare(self, intent: Intent, commitment: str) -> UnsignedTx:
        """Build the Payment, autofilled once, with ``commitment`` in the memo.

        Autofill is memoized against the intent's nonce so that preparing with the
        placeholder and preparing with the real commitment differ in exactly the
        32 anchor bytes — the fee, sequence and last-ledger fields must not move
        between the call the signer inspected and the call that gets submitted.
        """
        if intent.rail != RAIL_XRPL:
            raise XrplAdapterError(f"this adapter settles xrpl, not {intent.rail!r}")
        base = self._prepared.get(intent.nonce)
        if base is None:
            base = await autofill(
                self._payment(intent, ANCHOR_PLACEHOLDER_HEX),
                self._client,
                signers_count=self._signers_count,
            )
            self._prepared[intent.nonce] = base

        offset = _anchor_offset(
            bytes.fromhex(encode_for_multisigning(base.to_xrpl(), self._policy_address))
        )
        payment = _with_memo(base, commitment)
        payload = encode_for_multisigning(payment.to_xrpl(), self._policy_address)
        return UnsignedTx(
            rail=RAIL_XRPL,
            treasury=intent.treasury,
            signing_payload=payload.lower(),
            anchor_offset=offset,
            fields=self._fields(intent, payment),
            commitment=commitment,
            handle=payment,
        )

    def _payment(self, intent: Intent, commitment: str) -> Payment:
        return Payment(
            account=intent.treasury,
            destination=intent.destination,
            amount=to_xrpl_amount(intent.amount),
            memos=[
                Memo(
                    memo_type=MEMO_TYPE.encode().hex().upper(),
                    memo_data=commitment.upper(),
                )
            ],
            signing_pub_key="",
        )

    def _fields(self, intent: Intent, payment: Payment) -> JSONObject:
        raw = payment.to_xrpl()
        return {
            "account": intent.treasury,
            "destination": intent.destination,
            "amount": intent.amount.to_content(),
            "memo_type": MEMO_TYPE,
            "fee": str(raw.get("Fee", "")),
            "sequence": int(raw.get("Sequence", 0)),
            "last_ledger_sequence": int(raw.get("LastLedgerSequence", 0)),
            "network_id": int(raw["NetworkID"]) if "NetworkID" in raw else 0,
        }

    # -- sign and submit --------------------------------------------------- #

    async def agent_sign(self, unsigned: UnsignedTx) -> PartialTx:
        """The agent's half of the quorum, over *its own* multisigning payload."""
        payment = _handle(unsigned)
        signed = sign(payment, self._agent, multisign=True)
        signers = signed.signers or []
        if not signers:  # pragma: no cover - xrpl-py always returns one
            raise XrplAdapterError("xrpl-py returned no signer entry for the agent")
        entry = signers[0]
        return PartialTx(
            unsigned=unsigned,
            signatures=(
                Signature(
                    public_key=str(entry.signing_pub_key).lower(),
                    signature=str(entry.txn_signature).lower(),
                    algorithm="ed25519",
                ),
            ),
        )

    async def attach_policy_signature(self, partial: PartialTx, sig: Signature) -> SignedTx:
        """Add the policy key's signature and produce the submittable blob.

        Signers are sorted by numeric account id, which is what the ledger
        requires and what makes a multisigned blob canonical.
        """
        payment = _handle(partial.unsigned)
        entries = [
            Signer(
                account=self.agent_address,
                txn_signature=partial.signatures[0].signature.upper(),
                signing_pub_key=partial.signatures[0].public_key.upper(),
            ),
            Signer(
                account=self._policy_address,
                txn_signature=sig.signature.upper(),
                signing_pub_key="ED" + sig.public_key.upper(),
            ),
        ]
        entries.sort(key=lambda s: _account_number(str(s.account)))
        combined = Payment.from_xrpl(
            {
                **payment.to_xrpl(),
                "Signers": [
                    {
                        "Signer": {
                            "Account": str(e.account),
                            "TxnSignature": str(e.txn_signature),
                            "SigningPubKey": str(e.signing_pub_key),
                        }
                    }
                    for e in entries
                ],
            }
        )
        return SignedTx(
            rail=RAIL_XRPL,
            blob=encode(combined.to_xrpl()).lower(),
            commitment=partial.unsigned.commitment,
            signatures=(*partial.signatures, sig),
            handle=combined,
        )

    async def submit(self, signed: SignedTx) -> SettlementRef:
        """Submit and wait for validation, capturing the proof around it (D20)."""
        transaction = signed.handle
        if not isinstance(transaction, Payment):  # pragma: no cover - built above
            raise XrplAdapterError("submitted transaction has no xrpl payload")

        await self._start_validation_capture()
        try:
            response = await submit_and_wait(transaction, self._client, autofill=False)
        finally:
            await self._stop_validation_capture()

        result = response.result
        meta = result.get("meta") or {}
        engine_result = meta.get("TransactionResult", "unknown")
        tx_hash = str(result.get("hash") or result.get("tx_json", {}).get("hash", ""))
        ledger_index = int(result.get("ledger_index", 0))
        date = result.get("date") or result.get("close_time_iso")
        close_time = (
            ripple_time(int(date))
            if isinstance(date, int)
            else await self._close_time(ledger_index)
        )
        ref = SettlementRef(
            rail=RAIL_XRPL,
            tx_hash=tx_hash,
            ledger_index=ledger_index,
            close_time=close_time,
            observed_anchor=_observed_anchor(result),
            signed_tx_blob=signed.blob,
            engine_result=str(engine_result),
            validated=bool(result.get("validated", False)),
        )
        if engine_result != "tesSUCCESS":
            raise XrplAdapterError(f"the ledger refused the transaction: {engine_result}")
        self._proofs[tx_hash] = await self._capture_proof(ref, signed)
        return ref

    # -- reads ------------------------------------------------------------- #

    async def settlement_proof(self, ref: SettlementRef) -> SettlementProof | None:
        return self._proofs.get(ref.tx_hash)

    async def history(self, treasury: str, since: str) -> Sequence[Outflow]:
        """Validated outflows from ``account_tx`` (plan D2 and D17)."""
        response = await _account_tx(self._client, treasury)
        return _outflows_since(_outflows_from_response(response, treasury), since)

    async def close(self) -> None:
        await self._stop_validation_capture()

    # -- proof capture ----------------------------------------------------- #

    async def _start_validation_capture(self) -> None:
        """Subscribe to the validations stream *before* submitting (plan D20).

        Validations for a ledger are broadcast once, as it closes. Subscribing
        after the transaction is already validated means the evidence is gone, so
        the subscription has to be open across the submit.
        """
        if not self._capture or self._websocket_url is None:
            return
        self._validations = []
        self._validation_task = asyncio.create_task(self._collect_validations())
        await asyncio.sleep(0)

    async def _collect_validations(self) -> None:
        try:
            async with AsyncWebsocketClient(self._websocket_url or "") as socket:
                await socket.send(Subscribe(streams=[StreamParameter.VALIDATIONS]))
                async for message in socket:
                    if message.get("type") == "validationReceived":
                        self._validations.append(dict(message))
        except asyncio.CancelledError:  # pragma: no cover - normal shutdown
            raise
        except Exception:  # pragma: no cover - a missing stream is reported, not fatal
            return

    async def _stop_validation_capture(self) -> None:
        task = self._validation_task
        self._validation_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    async def _capture_proof(self, ref: SettlementRef, signed: SignedTx) -> SettlementProof:
        """What is obtainable at settlement time, and what is honestly missing.

        rippled exposes no API that returns a SHAMap path for a transaction, so
        the proof carries the validated transaction with its metadata, the ledger
        header (whose ``transaction_hash`` is the root of the transaction SHAMap),
        and every validation message seen for that ledger index. That is enough to
        check a quorum of validators signed *a* ledger with that transaction root;
        it is not enough to prove offline that this transaction is in that root.
        Rebuilding the SHAMap from the ledger's full binary transaction set would
        close the gap, and ``missing`` says so rather than implying otherwise.
        """
        header: JSONValue = None
        transaction: JSONValue = None
        ledger_hash: str | None = None
        with contextlib.suppress(Exception):
            response = await self._client.request(
                Ledger(ledger_index=ref.ledger_index, transactions=False, expand=False)
            )
            ledger = response.result.get("ledger", {})
            header = dict(ledger)
            ledger_hash = str(
                ledger.get("ledger_hash") or response.result.get("ledger_hash") or ""
            )
        with contextlib.suppress(Exception):
            response = await self._client.request(Tx(transaction=ref.tx_hash))
            transaction = dict(response.result)

        validations = tuple(
            v
            for v in self._validations
            if isinstance(v, dict) and _ledger_index_of(v) == ref.ledger_index
        )
        captured = ["signed_blob"]
        missing = ["shamap_path"]
        if header is not None:
            captured.append("ledger_header")
        else:
            missing.append("ledger_header")
        if transaction is not None:
            captured.append("validated_transaction_with_metadata")
        else:
            missing.append("validated_transaction_with_metadata")
        if validations:
            captured.append("validator_validations")
        else:
            missing.append("validator_validations")
        return SettlementProof(
            rail=RAIL_XRPL,
            tx_hash=ref.tx_hash,
            ledger_index=ref.ledger_index,
            ledger_hash=ledger_hash or None,
            ledger_header=header,
            transaction=transaction,
            validations=validations,
            captured=tuple(captured),
            missing=tuple(missing),
        )

    async def _close_time(self, ledger_index: int) -> str:
        with contextlib.suppress(Exception):
            response = await self._client.request(Ledger(ledger_index=ledger_index))
            ledger = response.result.get("ledger", {})
            if "close_time" in ledger:
                return ripple_time(int(ledger["close_time"]))
        return format_instant(datetime.now(tz=UTC))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _handle(unsigned: UnsignedTx) -> Payment:
    payment = unsigned.handle
    if not isinstance(payment, Payment):
        raise XrplAdapterError(
            "this unsigned transaction has no xrpl payload; it must be prepared by this adapter"
        )
    return payment


def _with_memo(payment: Payment, commitment: str) -> Payment:
    raw = payment.to_xrpl()
    raw["Memos"] = [
        {"Memo": {"MemoType": MEMO_TYPE.encode().hex().upper(), "MemoData": commitment.upper()}}
    ]
    return Payment.from_xrpl(raw)


def _anchor_offset(payload: bytes) -> int:
    """Where the placeholder sits, and a refusal if it is ambiguous."""
    count = payload.count(ANCHOR_PLACEHOLDER)
    if count != 1:
        raise XrplAdapterError(
            f"the multisigning payload has {count} placeholder-shaped runs; the anchor "
            "offset would be ambiguous"
        )
    return payload.index(ANCHOR_PLACEHOLDER)


def _account_number(address: str) -> int:
    from merkl.signer.binding import decode_classic_address

    return int.from_bytes(decode_classic_address(address), "big")


def _observed_anchor(result: dict[str, Any]) -> str | None:
    tx = result.get("tx_json") or result
    return _memo_anchor(tx.get("Memos") or [])


def _memo_anchor(memos: Sequence[Any]) -> str | None:
    """The MemoData of the merkl memo, lowercased, or None."""
    wanted = MEMO_TYPE.encode().hex().upper()
    for entry in memos:
        memo = entry.get("Memo", entry) if isinstance(entry, dict) else {}
        if str(memo.get("MemoType", "")).upper() != wanted:
            continue
        data = str(memo.get("MemoData", ""))
        if len(data) == ANCHOR_BYTES * 2:
            return data.lower()
    return None


def _read_amount(amount: Any) -> tuple[str, str]:
    """An XRPL amount as (decimal string, asset key)."""
    if isinstance(amount, str):
        drops = parse_decimal(amount, "amount")
        return str(drops / Decimal(1_000_000)), NATIVE
    if isinstance(amount, dict):
        code = str(amount.get("currency", ""))
        issuer = str(amount.get("issuer", ""))
        readable = _decode_currency(code)
        key = asset_key(IssuedCurrency(code=readable, issuer=issuer))
        return str(amount.get("value", "0")), key
    return "0", NATIVE


def _ledger_index_of(validation: dict[str, Any]) -> int:
    raw = validation.get("ledger_index", 0)
    return int(raw) if isinstance(raw, (int, str)) and str(raw).isdigit() else 0


def _decode_currency(code: str) -> str:
    """Turn XRPL's forty-hex form back into the readable code."""
    if len(code) != HEX_CODE_LENGTH:
        return code
    return bytes.fromhex(code).rstrip(b"\x00").decode(errors="replace") or code


async def _account_tx(client: AsyncJsonRpcClient, treasury: str) -> Response:
    return await client.request(
        AccountTx(account=treasury, ledger_index_min=-1, ledger_index_max=-1, limit=200)
    )


def _outflows_from_response(response: Response, treasury: str) -> list[Outflow]:
    """Every validated `Payment` *from* ``treasury`` in an ``account_tx`` response.

    The one parsing of ``account_tx`` in this module — :meth:`XrplSettlementAdapter.history`
    and the module-level :func:`history` both call this, so a read-only caller
    and a wallet-holding one can never drift into reading the ledger two
    different ways.
    """
    outflows: list[Outflow] = []
    for entry in response.result.get("transactions", []):
        tx = entry.get("tx_json") or entry.get("tx") or {}
        meta = entry.get("meta") or {}
        if tx.get("TransactionType") != "Payment" or tx.get("Account") != treasury:
            continue
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue
        amount = meta.get("delivered_amount") or tx.get("DeliverMax") or tx.get("Amount")
        value, asset = _read_amount(amount)
        close = entry.get("close_time_iso")
        date = tx.get("date") or entry.get("date")
        close_time = (
            format_instant(datetime.fromisoformat(close.replace("Z", "+00:00")))
            if isinstance(close, str)
            else ripple_time(int(date or 0))
        )
        outflows.append(
            Outflow(
                tx_hash=str(entry.get("hash") or tx.get("hash", "")),
                treasury=treasury,
                destination=str(tx.get("Destination", "")),
                value=value,
                asset=asset,
                ledger_index=int(entry.get("ledger_index", 0)),
                close_time=close_time,
                anchor=_memo_anchor(tx.get("Memos") or []),
            )
        )
    return outflows


def _outflows_since(outflows: Sequence[Outflow], since: str) -> list[Outflow]:
    return [o for o in outflows if o.close_time >= since]


async def history(
    treasury: str, since: str = "", *, json_rpc_url: str
) -> Sequence[Outflow]:
    """Read-only rail history for reconciliation (plan D17) — no wallet, no signing.

    For a caller that must never hold a signing key — the notary, in
    particular (`docs/INTERFACES-P4.md`, "Reconciliation: reading rail
    history"). Builds its own throwaway :class:`AsyncJsonRpcClient` for
    ``json_rpc_url`` and reads ``account_tx`` exactly the way
    :meth:`XrplSettlementAdapter.history` does — :func:`_outflows_from_response`
    is the one parser, not a second copy of it. Returns
    :class:`~merkl.core.policy.state.Outflow` value objects: evidence for
    ``SignerEngine.reconcile`` to compare against state it wrote itself, never
    a decision this function or its caller gets to make.
    """
    client = AsyncJsonRpcClient(json_rpc_url)
    response = await _account_tx(client, treasury)
    return _outflows_since(_outflows_from_response(response, treasury), since)
