"""A deterministic in-memory rail, for scenarios that must not need a network.

It is not a mock. It enforces the thing the real rail enforces — **2-of-2 quorum**
— and it refuses a single-signature submission with an error named the way the
ledger names it (``BAD_QUORUM``, after XRPL's ``tefBAD_QUORUM``). A scenario suite
that ran against a rail which accepted anything would prove that the SDK is
consistent with itself and nothing more.

Everything it produces is derived from its inputs: the transaction id is
``SHA-256("merkl-fake-tx-v1" ‖ NUL ‖ blob)``, which
:func:`merkl.core.rail.fake_tx_id` re-derives offline, so ``settlement.signed_blob``
is a real check here too. Ledger indexes count up from a fixed start and close
times come from the injected clock, so a whole scenario replays byte-identically.

The signing payload has the same shape as a real one: a canonical prefix, then a
32-byte anchor field at a known offset. That is the part the signer interacts
with, so it is the part that must not be simplified.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
from collections.abc import Sequence
from decimal import Decimal
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from merkl.core.canonical import JSONObject, format_decimal, parse_decimal, parse_instant
from merkl.core.crypto import ed25519_verify, tagged
from merkl.core.intent import CurrencyRef, Intent, currency_from_content
from merkl.core.merkle import MerkleTree
from merkl.core.policy.document import asset_key
from merkl.core.policy.state import Outflow
from merkl.core.rail import (
    ANCHOR_BYTES,
    MEMO_TYPE,
    RAIL_FAKE,
    AnchorCapability,
    PartialTx,
    SettlementProof,
    SettlementRef,
    Signature,
    SignedTx,
    UnsignedTx,
    fake_tx_id,
)
from merkl.core.verify.settlement import fake_ledger_hash, fake_validation_message
from merkl.shared.errors import MerklError
from merkl.shared.hashing import SHA256Hash, canonical_bytes

FAKE_TX_TAG: Final = b"merkl-fake-tx-v1"
FIRST_LEDGER: Final = 1_000_000
DEFAULT_QUORUM: Final = 2


def merkle_root(digests: Sequence[bytes]) -> str:
    """Merkl's Merkle root over raw digests, lowercase hex — the fold used everywhere."""
    return MerkleTree.build([SHA256Hash(d) for d in digests]).root.hex()


class FakeRailError(MerklError):
    """A rail-level refusal. ``engine_result`` names it the way a ledger would."""

    error_code = "fake_rail_error"

    def __init__(self, message: str, engine_result: str) -> None:
        super().__init__(message)
        self.engine_result = engine_result


@dataclasses.dataclass(frozen=True)
class FakeValidator:
    """One validator of the fake network: a name and the key it signs ledgers with."""

    name: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> str:
        return self.private_key.public_key().public_bytes_raw().hex()

    def sign(self, ledger_hash: str, ledger_index: int) -> JSONObject:
        """The validation message this validator broadcasts for a closed ledger."""
        message = fake_validation_message(ledger_hash, ledger_index)
        return {
            "validator": self.name,
            "ledger_index": ledger_index,
            "ledger_hash": ledger_hash,
            "signature": self.private_key.sign(message).hex(),
        }


def validator_set(count: int = 3, *, prefix: str = "validator") -> tuple[FakeValidator, ...]:
    """A deterministic validator set, so a scenario replays byte-identically.

    The seeds are derived from the name and are not secret in any sense that
    matters: this network exists only inside a test process.
    """
    return tuple(
        FakeValidator(
            name=f"{prefix}-{i}",
            private_key=Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(f"merkl-fake-validator:{prefix}-{i}".encode()).digest()
            ),
        )
        for i in range(count)
    )


@dataclasses.dataclass
class FakeLedger:
    """Balances, a signer list, and a clock. The whole ledger."""

    balances: dict[tuple[str, str], Decimal] = dataclasses.field(default_factory=dict)
    signers: frozenset[str] = frozenset()
    quorum: int = DEFAULT_QUORUM
    ledger_index: int = FIRST_LEDGER
    outflows: list[Outflow] = dataclasses.field(default_factory=list)
    validators: tuple[FakeValidator, ...] = dataclasses.field(default_factory=validator_set)
    """Who signs closed ledgers. A verifier pins these; the proof never names them."""

    def credit(self, account: str, asset: str, value: str) -> None:
        key = (account, asset)
        self.balances[key] = self.balances.get(key, Decimal(0)) + parse_decimal(value, "value")

    def balance(self, account: str, asset: str) -> str:
        return format_decimal(self.balances.get((account, asset), Decimal(0)))


class FakeSettlementAdapter:
    """An in-memory :class:`~merkl.core.ports.SettlementPort`.

    ``agent_key`` signs as the agent. The policy key never appears here — it is in
    the signer, and this adapter only ever receives its signature.
    """

    def __init__(
        self,
        ledger: FakeLedger,
        *,
        agent_key: object,
        agent_public_key: str,
        clock: object,
    ) -> None:
        self._ledger = ledger
        self._agent_key = agent_key
        self._agent_public_key = agent_public_key
        self._clock = clock
        self._sequences: dict[str, int] = {}
        self._counter = itertools.count(1)
        self._proofs: dict[str, SettlementProof] = {}

    # -- SettlementPort ---------------------------------------------------- #

    def anchor_capability(self) -> AnchorCapability:
        """The anchor is inside the signed payload, so nobody can edit it after."""
        return AnchorCapability.IMMUTABLE

    async def prepare(self, intent: Intent, commitment: str, **_: object) -> UnsignedTx:
        """Build the unsigned transaction. Called twice; both must agree.

        The sequence number is memoized against the intent's nonce so that
        preparing with the placeholder and preparing with the real commitment
        differ in exactly 32 bytes — which is what lets the caller check that the
        transaction it submits is the one the policy key signed.
        """
        sequence = self._sequences.setdefault(intent.nonce, next(self._counter))
        fields: JSONObject = {
            "account": intent.treasury,
            "destination": intent.destination,
            "amount": intent.amount.to_content(),
            "memo_type": MEMO_TYPE,
            "sequence": sequence,
            "fee": "10",
        }
        prefix = tagged(FAKE_TX_TAG, canonical_bytes(fields)) + b"\x00"
        payload = prefix + bytes.fromhex(commitment)
        return UnsignedTx(
            rail=RAIL_FAKE,
            treasury=intent.treasury,
            signing_payload=payload.hex(),
            anchor_offset=len(prefix),
            fields=fields,
            commitment=commitment,
        )

    async def agent_sign(self, unsigned: UnsignedTx) -> PartialTx:
        signature = self._agent_key.sign(unsigned.payload_bytes).hex()  # type: ignore[attr-defined]
        return PartialTx(
            unsigned=unsigned,
            signatures=(Signature(public_key=self._agent_public_key, signature=signature),),
        )

    async def attach_policy_signature(self, partial: PartialTx, sig: Signature) -> SignedTx:
        signatures = (*partial.signatures, sig)
        blob = canonical_bytes(
            {
                "payload": partial.unsigned.signing_payload,
                "signatures": [s.to_content() for s in _sorted(signatures)],
            }
        )
        return SignedTx(
            rail=RAIL_FAKE,
            blob=blob.hex(),
            commitment=partial.unsigned.commitment,
            signatures=tuple(_sorted(signatures)),
            handle=partial.unsigned,
        )

    async def submit(self, signed: SignedTx) -> SettlementRef:
        """Validate, enforce quorum, move the money.

        Quorum is checked the way a ledger checks it: distinct authorized signers
        whose signatures verify over the exact payload. One good signature is not
        a partial success, it is ``BAD_QUORUM``.
        """
        unsigned = signed.handle
        if not isinstance(unsigned, UnsignedTx):  # pragma: no cover - built by this adapter
            raise FakeRailError("submitted transaction has no payload", "temMALFORMED")
        payload = unsigned.with_anchor(signed.commitment).payload_bytes

        valid: set[str] = set()
        for signature in signed.signatures:
            if signature.public_key not in self._ledger.signers:
                continue
            if ed25519_verify(signature.public_key, signature.signature, payload):
                valid.add(signature.public_key)
        if len(valid) < self._ledger.quorum:
            raise FakeRailError(
                f"{len(valid)} of {self._ledger.quorum} required signatures; the ledger "
                "will not move funds on an incomplete quorum",
                "BAD_QUORUM",
            )

        fields = unsigned.fields
        account = str(fields["account"])
        destination = str(fields["destination"])
        amount = fields["amount"]
        assert isinstance(amount, dict)
        value = str(amount["value"])
        asset = asset_key(_currency(amount))
        if parse_decimal(self._ledger.balance(account, asset), "balance") < parse_decimal(
            value, "value"
        ):
            raise FakeRailError(f"{account} does not hold {value} {asset}", "tecUNFUNDED_PAYMENT")

        self._ledger.ledger_index += 1
        close_time = self._clock.now()  # type: ignore[attr-defined]
        self._ledger.credit(account, asset, f"-{value}")
        self._ledger.credit(destination, asset, value)

        tx_hash = fake_tx_id(bytes.fromhex(signed.blob))
        outflow = Outflow(
            tx_hash=tx_hash,
            treasury=account,
            destination=destination,
            value=value,
            asset=asset,
            ledger_index=self._ledger.ledger_index,
            close_time=close_time,
            anchor=signed.commitment,
        )
        self._ledger.outflows.append(outflow)
        ref = SettlementRef(
            rail=RAIL_FAKE,
            tx_hash=tx_hash,
            ledger_index=self._ledger.ledger_index,
            close_time=close_time,
            observed_anchor=payload[
                unsigned.anchor_offset : unsigned.anchor_offset + ANCHOR_BYTES
            ].hex(),
            signed_tx_blob=signed.blob,
            engine_result="tesSUCCESS",
        )
        self._proofs[tx_hash] = self._build_proof(ref, signed)
        return ref

    async def settlement_proof(self, ref: SettlementRef) -> SettlementProof | None:
        return self._proofs.get(ref.tx_hash)

    async def history(self, treasury: str, since: str) -> Sequence[Outflow]:
        moment = parse_instant(since, "since")
        return [
            outflow
            for outflow in self._ledger.outflows
            if outflow.treasury == treasury
            and parse_instant(outflow.close_time, "close_time") >= moment
        ]

    # -- helpers ----------------------------------------------------------- #

    def _build_proof(self, ref: SettlementRef, signed: SignedTx) -> SettlementProof:
        """A proof shaped like the real one, and complete the way a real one is not.

        This rail closes one transaction per ledger, so the transaction set has a
        single member and the path to its root is empty — which the verifier folds
        exactly as it folds a longer one. The point of building it here rather
        than faking a verdict is that ``proven-offline`` (plan D10) is then a
        state both implementations actually reach and both test suites actually
        assert, instead of a branch nobody has run.
        """
        transaction_hash = merkle_root([bytes.fromhex(ref.tx_hash)])
        header: JSONObject = {
            "ledger_index": ref.ledger_index,
            "close_time": ref.close_time,
            "transaction_hash": transaction_hash,
            "transaction_count": 1,
        }
        ledger_hash = fake_ledger_hash(header)
        return SettlementProof(
            rail=RAIL_FAKE,
            tx_hash=ref.tx_hash,
            ledger_index=ref.ledger_index,
            ledger_hash=ledger_hash,
            ledger_header=header,
            transaction={"blob": signed.blob, "engine_result": ref.engine_result},
            tx_path={"leaf_index": 0, "siblings": [], "directions": []},
            validations=tuple(
                v.sign(ledger_hash, ref.ledger_index) for v in self._ledger.validators
            ),
            captured=(
                "ledger_header",
                "transaction",
                "shamap_path",
                "validator_signatures",
                "signed_blob",
            ),
            missing=(),
        )


def _currency(amount: JSONObject) -> CurrencyRef:
    return currency_from_content(amount["currency"])


def _sorted(signatures: Sequence[Signature]) -> list[Signature]:
    """Canonical signature order, as multisig rails require."""
    return sorted(signatures, key=lambda s: s.public_key)
