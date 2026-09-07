"""One rig the scenarios share, wired the way a real deployment is.

Nothing here is a mock of a Merkl component. The signer is the real
:class:`~merkl.signer.engine.SignerEngine` with a real encrypted keystore and a
real sealed state file on disk; the policy is a real signed document; the
approvals are real signatures over the real challenge. Only the *rail* is
swappable, which is the point: the same scenario must reach the same verdict
against the in-memory ledger and against XRPL testnet.

The clock is frozen and advanced explicitly. A sliding window whose tests depend
on wall time is a test suite that fails at midnight.

**None of these keys is a secret.** Every one is derived from a public label so a
run replays byte-identically, and they exist to make a demo reproducible. A key
in a library is a key everyone has; never point one of these at money.
"""

from __future__ import annotations

import dataclasses
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from merkl.adapters.fake import FakeLedger, FakeSettlementAdapter
from merkl.adapters.signer_dev import LocalSignerClient
from merkl.core.canonical import shift_instant
from merkl.core.intent import Amount, CurrencyRef, Intent, IssuedCurrency, Reference
from merkl.core.policy.approvals import ApprovalAssertion
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    CREDENTIAL_WEBAUTHN,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    HumanTier,
    PolicyDocument,
    ReferenceBinding,
    RiskRule,
    SignedPolicy,
    Tiers,
    WindowRule,
)
from merkl.core.policy.engine import RiskScore
from merkl.core.receipt import Instruction, Reasoning
from merkl.core.vectors import fixtures
from merkl.sdk.receipts import ReceiptBuilder
from merkl.shared.hashing import SHA256Hash
from merkl.signer.engine import Clock, SignerEngine
from merkl.signer.keystore import DevKeystore
from merkl.signer.risk import StaticRiskScorer
from merkl.signer.state import SealedStateStore

POLICY_VERSION: Final = "2026.01.0"
START: Final = "2026-01-02T03:00:00Z"

TREASURY: Final = "rTREASURY0000000000000000000000000"
SUPPLIER: Final = "rSUPPLIER0000000000000000000000000"
ATTACKER: Final = "rATTACKER0000000000000000000000000"
ISSUER: Final = "rISSUER000000000000000000000000000"
RLUSD: Final = IssuedCurrency(code="RLUSD", issuer=ISSUER)

INVOICE_HASH: Final = SHA256Hash.from_bytes(b"invoice INV-2026-0042.pdf").hex()
ORIGIN: Final = "https://app.merkl.ai"
RP_ID: Final = "app.merkl.ai"

AGENT_ID: Final = "agent-accounts-payable"


def digest(label: str) -> str:
    return SHA256Hash.from_bytes(label.encode()).hex()


class FrozenClock(Clock):
    """A clock that only moves when a caller says so."""

    def __init__(self, now: str = START) -> None:
        self._now = now

    def now(self) -> str:
        return self._now

    def advance(self, seconds: int) -> str:
        self._now = shift_instant(self._now, seconds, "now")
        return self._now


class Ed25519Party:
    """Someone with an Ed25519 key: the agent, the admin, an approver."""

    def __init__(self, label: str) -> None:
        self._key = fixtures.ed25519_key(label)

    @property
    def public_key(self) -> str:
        return fixtures.ed25519_public_hex(self._key)

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def sign_bytes(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def raw(self) -> ed25519.Ed25519PrivateKey:
        return self._key


class PasskeyParty:
    """An approver with a WebAuthn passkey (ECDSA P-256)."""

    def __init__(self, scalar: int) -> None:
        self._key = fixtures.p256_key(scalar)

    @property
    def public_key(self) -> str:
        return fixtures.p256_public_hex(self._key)

    def assert_over(
        self, challenge: bytes, *, approver_id: str, signed_at: str, origin: str = ORIGIN
    ) -> ApprovalAssertion:
        client_data = fixtures.client_data_json(challenge, origin)
        auth_data = fixtures.authenticator_data(RP_ID)
        signature = self._key.sign(
            fixtures.webauthn_message(auth_data, client_data), ec.ECDSA(hashes.SHA256())
        )
        return ApprovalAssertion(
            approver_id=approver_id,
            credential_type=CREDENTIAL_WEBAUTHN,
            signature=signature.hex(),
            client_data_json=client_data.hex(),
            authenticator_data=auth_data.hex(),
            signed_at=signed_at,
        )


ADMIN: Final = Ed25519Party("scenario-admin")
AGENT: Final = Ed25519Party("scenario-agent")
ALICE: Final = Ed25519Party("scenario-alice")
CAROL: Final = Ed25519Party("scenario-carol")
BOB: Final = PasskeyParty(fixtures.WEBAUTHN_SCALAR)


def build_policy(
    *,
    treasury: str = TREASURY,
    destinations: tuple[str, ...] = (SUPPLIER,),
    per_tx_cap: str = "1000.00",
    window: tuple[str, int] | None = ("2500.00", 86400),
    human_threshold: str | None = "500.00",
    quorum: int = 2,
    reference_required: bool = True,
    reference_hashes: tuple[str, ...] = (INVOICE_HASH,),
    risk_threshold: str = "0.75",
    asset: CurrencyRef = RLUSD,
    rail: str = "fake",
) -> PolicyDocument:
    """The scenario policy. Every knob a scenario needs to turn is a parameter."""
    windows = (WindowRule(asset=asset, amount=window[0], seconds=window[1]),) if window else ()
    return PolicyDocument(
        version=POLICY_VERSION,
        treasury=treasury,
        rail=rail,
        agents=(
            AgentSection(
                agent_id=AGENT_ID,
                public_key=AGENT.public_key,
                allowlist_destinations=destinations,
                allowlist_assets=(asset,),
                per_tx_cap=(AssetLimit(asset=asset, amount=per_tx_cap),),
                windows=windows,
                reference_binding=ReferenceBinding(
                    required=reference_required,
                    allowed_kinds=("invoice",),
                    hashes=reference_hashes,
                ),
            ),
        ),
        admin_public_key=ADMIN.public_key,
        tiers=Tiers(
            human=HumanTier(
                thresholds=(
                    (AssetLimit(asset=asset, amount=human_threshold),) if human_threshold else ()
                ),
                quorum=quorum,
                expires_seconds=3600,
            )
        ),
        approvers=(
            ApproverCredential(
                id="alice@example.com",
                credential_type=CREDENTIAL_ED25519,
                public_key=ALICE.public_key,
            ),
            ApproverCredential(
                id="bob@example.com",
                credential_type=CREDENTIAL_WEBAUTHN,
                public_key=BOB.public_key,
                origins=(ORIGIN,),
                rp_id=RP_ID,
                user_verification=True,
            ),
            ApproverCredential(
                id="carol@example.com",
                credential_type=CREDENTIAL_ED25519,
                public_key=CAROL.public_key,
            ),
        ),
        risk=RiskRule(threshold=risk_threshold),
    )


def sign_policy(document: PolicyDocument) -> SignedPolicy:
    """The admin signs the document. The signer verifies this at boot (plan D16)."""
    return SignedPolicy(
        document=document,
        signature=ADMIN.sign(document.pre_image()),
        signer_public_key=ADMIN.public_key,
    )


@dataclasses.dataclass
class Rig:
    """Everything a scenario needs, already wired together."""

    clock: FrozenClock
    engine: SignerEngine
    signer: LocalSignerClient
    builder: ReceiptBuilder
    rail: Any
    policy: PolicyDocument
    signed_policy: SignedPolicy
    ledger: FakeLedger | None = None

    def intent(
        self,
        *,
        value: str = "250.00",
        destination: str = SUPPLIER,
        reference: Reference | None = None,
        nonce: str | None = None,
        asset: CurrencyRef = RLUSD,
        treasury: str | None = None,
        policy_version: str = POLICY_VERSION,
    ) -> Intent:
        return Intent(
            rail=self.rail_name,
            treasury=treasury or self.policy.treasury,
            destination=destination,
            amount=Amount(value=value, currency=asset),
            policy_version=policy_version,
            agent_public_key=AGENT.public_key,
            nonce=nonce or digest(f"nonce-{value}-{destination}-{self.clock.now()}")[:32],
            expires_at=shift_instant(self.clock.now(), 600, "now"),
            reference=reference
            or Reference(kind="invoice", id="INV-2026-0042", hash=INVOICE_HASH),
        )

    @property
    def rail_name(self) -> str:
        return self.policy.rail

    def instruction(self, text: str = "pay invoice INV-2026-0042") -> Instruction:
        return Instruction(source="human_input", content_hash=digest(text), ref="action-0001")

    def reasoning(self, text: str = "the invoice matched the supplier on file") -> Reasoning:
        return Reasoning(content_hash=digest(text), source="claude-code", note=text[:200])


def build_rig(
    home: Path,
    *,
    policy: PolicyDocument | None = None,
    blocklist: tuple[str, ...] = (),
    starting_balance: str = "100000.00",
    clock: FrozenClock | None = None,
) -> Rig:
    """A signer, a keystore, sealed state and the in-memory rail, all real."""
    document = policy or build_policy()
    signed = sign_policy(document)
    clock = clock or FrozenClock()
    keystore = DevKeystore(home / "keystore", passphrase="scenario-passphrase")
    state = SealedStateStore(home / "state", document.treasury, keystore.seal_key())
    engine = SignerEngine(
        policy=signed,
        keystore=keystore,
        state=state,
        clock=clock,
        risk=StaticRiskScorer.of(blocklist),
    )
    ledger = FakeLedger(signers=frozenset({AGENT.public_key, keystore.public_key()}))
    ledger.balances[(document.treasury, "RLUSD." + ISSUER)] = Decimal(starting_balance)
    rail = FakeSettlementAdapter(
        ledger, agent_key=AGENT.raw(), agent_public_key=AGENT.public_key, clock=clock
    )
    signer = LocalSignerClient(engine)
    builder = ReceiptBuilder(
        signer=signer,
        settlement=rail,
        agent_id=AGENT_ID,
        agent_public_key=AGENT.public_key,
        agent_sign=AGENT.sign,
        clock=clock,
    )
    return Rig(
        clock=clock,
        engine=engine,
        signer=signer,
        builder=builder,
        rail=rail,
        policy=document,
        signed_policy=signed,
        ledger=ledger,
    )


def approvals_for(challenge: str, *, at: str) -> list[ApprovalAssertion]:
    """Two of three approvers sign: one Ed25519, one passkey."""
    raw = bytes.fromhex(challenge)
    return [
        fixtures.ed25519_assertion(
            approver_id="alice@example.com", key=ALICE.raw(), challenge=raw, signed_at=at
        ),
        BOB.assert_over(raw, approver_id="bob@example.com", signed_at=at),
    ]


def risk_zero(_destination: str) -> RiskScore:
    return RiskScore()


__all__ = [
    "ADMIN",
    "AGENT",
    "AGENT_ID",
    "ALICE",
    "ATTACKER",
    "BOB",
    "CAROL",
    "INVOICE_HASH",
    "ISSUER",
    "ORIGIN",
    "POLICY_VERSION",
    "RLUSD",
    "RP_ID",
    "START",
    "SUPPLIER",
    "TREASURY",
    "Ed25519Party",
    "FrozenClock",
    "PasskeyParty",
    "Rig",
    "approvals_for",
    "build_policy",
    "build_rig",
    "digest",
    "risk_zero",
    "sign_policy",
]
