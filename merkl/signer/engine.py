"""The signer engine — the authoritative flow (plan section 6).

One rule shapes every method here: **the signer never accepts a decision from the
caller** (plan D1). ``propose`` takes an instruction, an intent and a prepared
transaction. There is no argument through which a caller could suggest an
outcome, a tier, a policy hash or a reservation, and that is deliberate — the
moment such an argument exists, the policy authority has moved to whoever calls.

The flow, in order:

1. authenticate the request against the agent key **in the policy** (D15);
2. evaluate the pinned policy on the canonical intent, with the signer's own
   state and its own clock;
3. deny → return the decision, reserve nothing, sign nothing;
4. escalate → reserve, register the pending escalation under ``LEFT_pre``, return
   the challenge;
5. allow → check the prepared transaction against the intent, reserve, compute
   LEFT, write LEFT into the transaction's anchor field, sign those exact bytes.

Step 5 is the important one. The signer does not trust the adapter to have put
the right commitment in the memo: it writes the commitment itself, over a
placeholder it first checks is untouched, and signs the result. What it still
takes on trust is that the adapter's *fields* describe the payload — see
``docs/SIGNER-RPC.md``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import secrets
from collections.abc import Callable, Sequence
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue, parse_instant, shift_instant
from merkl.core.intent import Intent
from merkl.core.policy.approvals import (
    ApprovalAssertion,
    QuorumResult,
    verify_policy_signature,
    verify_quorum,
)
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    AdminCredential,
    PolicyChange,
    PolicyDocument,
    SignedPolicy,
    asset_key,
)
from merkl.core.policy.engine import (
    Decision,
    EscalationRequest,
    ReservationRequest,
    RiskScore,
    RuleOutcome,
    evaluate,
)
from merkl.core.policy.state import (
    EscalationEntry,
    NonceEntry,
    Outflow,
    Reconciliation,
    SpendEntry,
    SpendStatus,
    StateError,
)
from merkl.core.rail import (
    ANCHOR_BYTES,
    ANCHOR_PLACEHOLDER,
    MEMO_TYPE,
    MERKL_SOURCE_TAG,
    UnsignedTx,
)
from merkl.core.receipt import (
    Escalation,
    Instruction,
    PolicyDecision,
    PolicyOutcome,
    PolicyRule,
    ReceiptLeaves,
    authorization_commitment,
    escalation_challenge,
)
from merkl.shared.errors import MerklError
from merkl.signer.auth import AuthError, SignedRequest, verify_request
from merkl.signer.binding import missing_bindings
from merkl.signer.keystore import KeystorePort
from merkl.signer.rails import RULE_PAYLOAD_ENCODES_INTENT, RailCodec, codec_for
from merkl.signer.state import SealedStateStore

NONCE_TTL_SECONDS: Final = 3600
DEFAULT_PRUNE_SECONDS: Final = 30 * 24 * 3600


class SignerError(MerklError):
    """Raised when a request cannot be answered at all.

    Not the same thing as a denial. A denied payment is a *decision* and has a
    receipt; a request the signer cannot make sense of has neither.
    """

    error_code = "signer_error"


MAX_REMEMBERED_EXPIRED = 1000
"""How many swept escalations are kept so a late approval is told "expired"."""


class Clock:
    """The signer's clock, injected so any decision can be replayed."""

    def now(self) -> str:  # pragma: no cover - trivial, and the tests inject their own
        from datetime import datetime

        from merkl.core.canonical import format_instant

        return format_instant(datetime.now().astimezone())


@dataclasses.dataclass(frozen=True)
class PendingEscalation:
    """An escalation waiting for people, keyed by its challenge."""

    challenge: str
    instruction: Instruction
    intent: Intent
    decision: Decision
    unsigned: UnsignedTx | None
    reservation_id: str
    expires_at: str
    quorum: int
    agent_id: str

    def to_content(self) -> JSONObject:
        """Everything needed to resume this escalation after a restart."""
        escalation = self.decision.escalation
        reservation = self.decision.reservation
        return {
            "agent_id": self.agent_id,
            "instruction": self.instruction.to_content(),
            "intent": self.intent.to_content(),
            "prepared_tx": self.unsigned.to_content() if self.unsigned is not None else None,
            "quorum": self.quorum,
            "decision": self.decision.to_content(),
            "escalation_request": (
                {"quorum": escalation.quorum, "expires_at": escalation.expires_at}
                if escalation is not None
                else None
            ),
            "reservation_request": (
                {"asset": reservation.asset, "value": reservation.value, "at": reservation.at}
                if reservation is not None
                else None
            ),
            "risk_score": {
                "value": self.decision.risk_score.value,
                "source": self.decision.risk_score.source,
            },
        }

    @classmethod
    def from_entry(cls, entry: EscalationEntry) -> PendingEscalation:
        content = entry.content
        leaf = PolicyDecision.from_content(content["decision"])
        request = content.get("escalation_request")
        reserved = content.get("reservation_request")
        risk = content["risk_score"]
        prepared = content.get("prepared_tx")
        if not isinstance(risk, dict):
            raise SignerError("a persisted escalation has no risk score")
        decision = Decision(
            policy_hash=leaf.policy_hash,
            rules=leaf.rules,
            outcome=leaf.outcome,
            tier=leaf.tier,
            escalation=(
                EscalationRequest(
                    quorum=int(str(request["quorum"])), expires_at=str(request["expires_at"])
                )
                if isinstance(request, dict)
                else None
            ),
            reservation=(
                ReservationRequest(
                    asset=str(reserved["asset"]),
                    value=str(reserved["value"]),
                    at=str(reserved["at"]),
                )
                if isinstance(reserved, dict)
                else None
            ),
            risk_score=RiskScore(value=str(risk["value"]), source=str(risk["source"])),
        )
        return cls(
            challenge=entry.challenge,
            instruction=Instruction.from_content(content["instruction"]),
            intent=Intent.from_content(content["intent"]),
            decision=decision,
            unsigned=None if prepared is None else UnsignedTx.from_content(prepared),
            reservation_id=entry.reservation_id,
            expires_at=entry.expires_at,
            quorum=int(str(content["quorum"])),
            agent_id=str(content["agent_id"]),
        )


class SignerEngine:
    """One signer, one treasury, one pinned policy, one key.

    Synchronous on purpose: it is a decision function with a durable log beside
    it, and the concurrency belongs to whatever serves it. ``merkl.signer.server``
    holds a lock so two proposals can never read the same window.
    """

    def __init__(
        self,
        *,
        policy: SignedPolicy,
        keystore: KeystorePort,
        state: SealedStateStore,
        clock: Clock | None = None,
        risk: Callable[[str], RiskScore] | None = None,
        admin_public_key: str | None = None,
        admin: AdminCredential | None = None,
        codec: RailCodec | None = None,
    ) -> None:
        pinned = admin or (
            AdminCredential(credential_type=CREDENTIAL_ED25519, public_key=admin_public_key)
            if admin_public_key is not None
            else policy.document.effective_admin
        )
        if not verify_policy_signature(policy, admin=pinned):
            raise SignerError("the policy document's admin signature does not verify")
        # Resolved at boot, not per request: a signer that cannot read its rail's
        # bytes must refuse to start rather than discover it mid-payment.
        self._codec = codec or codec_for(policy.document.rail, policy.document.network)
        self._policy = policy
        self._admin = pinned
        self._keystore = keystore
        self._state = state
        self._clock = clock or Clock()
        self._risk = risk or (lambda _destination: RiskScore())
        self._pending: dict[str, PendingEscalation] = {}
        self._expired: dict[str, PendingEscalation] = {}
        self._changes: list[PolicyChange] = []
        # The pending map is a cache of what the sealed state holds: a signer
        # recreated with escalations in flight resumes them, and the sweep
        # below gives back whatever lapsed while it was down, before serving.
        for entry in state.snapshot().escalations:
            self._pending[entry.challenge] = PendingEscalation.from_entry(entry)
        self.sweep_expired()

    # -- read-only methods ------------------------------------------------- #

    @property
    def document(self) -> PolicyDocument:
        return self._policy.document

    @property
    def policy_hash(self) -> str:
        return self._policy.policy_hash

    @property
    def admin(self) -> AdminCredential:
        """The admin credential currently pinned, not necessarily the document's own."""
        return self._admin

    def public_key(self) -> JSONObject:
        return {"public_key": self._keystore.public_key(), "key_type": "ed25519"}

    def attestation(self) -> JSONValue:
        """``None`` for a dev signer, and every caller is told so (plan D3)."""
        return self._keystore.attestation()

    def health(self) -> JSONObject:
        self.sweep_expired()
        attested = self._keystore.attestation() is not None
        return {
            "status": "ok",
            "treasury": self.document.treasury,
            "policy_version": self.document.version,
            "policy_hash": self.policy_hash,
            "signer_public_key": self._keystore.public_key(),
            "state_sequence": self._state.sequence,
            "pending_escalations": len(self._pending),
            "attested": attested,
            "warning": None if attested else "UNATTESTED SIGNER — no enclave vouches for this key",
        }

    def policy_changes(self) -> list[JSONObject]:
        return [change.to_content() for change in self._changes]

    # -- propose ----------------------------------------------------------- #

    def propose(self, raw_request: Any) -> JSONObject:
        """Evaluate an intent and, on ALLOW, sign the transaction that carries it."""
        request = SignedRequest.from_content(raw_request)
        now = self._clock.now()
        self.sweep_expired(now)
        section = verify_request(
            request,
            self.document,
            now=now,
            seen_nonces=self._state.nonces_seen(request.agent_id),
            expected_method="propose",
        )
        self._state.record_nonce(
            NonceEntry(
                agent_id=request.agent_id,
                nonce=request.nonce,
                expires_at=request.expires_at,
            )
        )

        params = request.params
        instruction = Instruction.from_content(_required(params, "instruction"))
        intent = Intent.from_content(_required(params, "intent"))
        if intent.agent_public_key != section.public_key:
            raise AuthError(
                "the intent names a different agent key from the one that signed the request"
            )

        decision = evaluate(
            intent, self.document, self._state.view(), self._risk(intent.destination), now
        )

        if decision.denied:
            return self._envelope(decision, outcome=PolicyOutcome.DENY.value)

        unsigned = self._prepared(params, intent)
        reservation_id = self._reserve(
            decision, request.agent_id, now, self._reservation_expiry(decision, intent)
        )

        if decision.escalated:
            return self._register_escalation(
                decision, instruction, intent, unsigned, reservation_id, request.agent_id
            )
        return self._authorize(decision, instruction, intent, unsigned, reservation_id)

    # -- approve ----------------------------------------------------------- #

    def approve(
        self,
        challenge: str,
        assertions: Sequence[Any],
        prepared_tx: Any | None = None,
    ) -> JSONObject:
        """Resolve an escalation with the approvals people gave (plan D11).

        Re-evaluates rather than trusting the earlier verdict: minutes have passed
        and the window may have filled in the meantime. Approval is permission to
        proceed, not a decision that stands on its own.
        """
        now = self._clock.now()
        self.sweep_expired(now)
        parsed = tuple(ApprovalAssertion.from_content(a) for a in assertions)
        gone = self._expired.get(challenge)
        if gone is not None:
            return self._expired_denial(gone, parsed)
        pending = self._pending.get(challenge)
        if pending is None:
            raise SignerError(f"no escalation is pending for challenge {challenge[:16]}…")

        if parse_instant(now, "now") > parse_instant(pending.expires_at, "escalation.expires_at"):
            return self._reject_escalation(
                pending,
                parsed,
                None,
                f"the escalation expired at {pending.expires_at}",
            )

        quorum = verify_quorum(
            parsed,
            bytes.fromhex(challenge),
            self.document.approvers,
            pending.quorum,
        )
        if not quorum.reached:
            return self._reject_escalation(pending, parsed, quorum, quorum.detail())

        fresh = evaluate(
            pending.intent,
            self.document,
            self._state.view().excluding_reservation(pending.reservation_id),
            self._risk(pending.intent.destination),
            now,
        )
        if fresh.denied:
            return self._reject_escalation(
                pending, parsed, quorum, f"re-evaluation denied it: {fresh.reason()}"
            )

        unsigned = pending.unsigned
        if prepared_tx is not None:
            unsigned = self._verify_prepared(UnsignedTx.from_content(prepared_tx), pending.intent)
        if unsigned is None:
            raise SignerError("this escalation has no prepared transaction to sign")

        decision = dataclasses.replace(
            pending.decision,
            outcome=PolicyOutcome.ALLOW.value,
            escalation=pending.decision.escalation,
        )
        del self._pending[challenge]
        self._state.resolve_escalation(challenge)
        return self._authorize(
            decision,
            pending.instruction,
            pending.intent,
            unsigned,
            pending.reservation_id,
            escalation=self._escalation_leaf(pending, parsed),
        )

    def reject(
        self,
        challenge: str,
        assertions: Sequence[Any],
    ) -> JSONObject:
        """Refuse an escalation, with the refusal signed (plan D11).

        A rejection is evidence. Somebody with standing to approve chose not to,
        and that fact belongs in the record the same way an approval does — so
        the same assertions are verified against the same challenge, and the
        resulting DENY decision carries them in leaf 2. An escalation that simply
        stops being mentioned proves nothing about whether anyone looked at it.

        The reservation is released here rather than left to expire, because the
        money is not going to move and a window that stays full is a denial of
        service the approver did not intend.
        """
        self.sweep_expired()
        pending = self._pending.get(challenge)
        if pending is None:
            gone = self._expired.get(challenge)
            if gone is None:
                raise SignerError(f"no escalation is pending for challenge {challenge[:16]}…")
            return self._expired_denial(
                gone, tuple(ApprovalAssertion.from_content(a) for a in assertions)
            )
        parsed = tuple(ApprovalAssertion.from_content(a) for a in assertions)
        if not parsed:
            raise SignerError("a rejection is signed: send at least one assertion")

        quorum = verify_quorum(
            parsed,
            bytes.fromhex(challenge),
            self.document.approvers,
            pending.quorum,
        )
        signers = [c.approver_id for c in quorum.checks if c.valid]
        if not signers:
            return self._reject_escalation(
                pending,
                parsed,
                quorum,
                f"rejected, but no assertion verifies: {quorum.detail()}",
            )
        return self._reject_escalation(
            pending,
            parsed,
            quorum,
            f"rejected by {', '.join(sorted(set(signers)))}",
        )

    # -- expiry ------------------------------------------------------------ #

    def sweep_expired(self, now: str | None = None) -> int:
        """Drop escalations nobody answered in time, and release what they reserved.

        An escalation reserves its amount against the window the moment it is
        raised. Only ``approve`` and ``reject`` used to give that back, so one
        that simply expired kept counting forever and every later proposal
        failed its window cap. Called at the start of every ``propose``,
        ``approve``, ``reject`` and ``health``, and by the notary follower on
        each poll, so a quiet signer clears them too. Returns how many it dropped.

        The swept ones are remembered (bounded), so an ``approve`` that arrives
        afterwards is still refused as *expired* rather than as unknown.
        """
        moment = parse_instant(now if now is not None else self._clock.now(), "now")
        swept = 0
        stale = [
            p
            for p in self._pending.values()
            if moment > parse_instant(p.expires_at, "escalation.expires_at")
        ]
        for pending in stale:
            self._forget(pending)
            swept += 1
        # The backstop: a reservation past its own expiry that nothing will ever
        # settle or release, with no escalation left to match it.
        by_reservation = {p.reservation_id: p for p in self._pending.values()}
        for entry in self._state.snapshot().entries:
            if entry.status != SpendStatus.RESERVED.value:
                continue
            if moment <= parse_instant(self._lapses_at(entry), "reservation.expires_at"):
                continue
            orphan = by_reservation.get(entry.reservation_id)
            if orphan is not None:
                self._forget(orphan)
            else:
                with contextlib.suppress(StateError):
                    self._state.release(entry.reservation_id)
            swept += 1
        while len(self._expired) > MAX_REMEMBERED_EXPIRED:
            del self._expired[next(iter(self._expired))]
        return swept

    def _forget(self, pending: PendingEscalation) -> None:
        """Move an escalation to the expired memory and give its reservation back."""
        del self._pending[pending.challenge]
        self._expired[pending.challenge] = pending
        with contextlib.suppress(StateError):  # already settled or released elsewhere
            self._state.release(pending.reservation_id)

    def _lapses_at(self, entry: SpendEntry) -> str:
        """When an unsettled reservation stops counting.

        Entries written before 0.3.3 carry no expiry; the longest an unsettled
        reservation could legitimately wait is an escalation's lifetime, so that
        is what they get.
        """
        if entry.expires_at is not None:
            return entry.expires_at
        return shift_instant(entry.at, self.document.tiers.human.expires_seconds)

    def _expired_denial(
        self, pending: PendingEscalation, assertions: Sequence[ApprovalAssertion]
    ) -> JSONObject:
        return self._reject_escalation(
            pending,
            assertions,
            None,
            f"the escalation expired at {pending.expires_at}",
            release=False,
        )

    # -- settlement bookkeeping -------------------------------------------- #

    def settle(self, reservation_id: str, settlement_ref: str) -> JSONObject:
        """Record that a reservation reached the ledger.

        The amount stays counted against the window either way — settling only
        attaches the transaction that carried it, so reconciliation has something
        to match. Nothing is ever counted twice.
        """
        sequence = self._state.settle(reservation_id, settlement_ref)
        return {"reservation_id": reservation_id, "state_sequence": sequence}

    def release(self, reservation_id: str) -> JSONObject:
        """Drop a reservation whose attempt provably failed."""
        sequence = self._state.release(reservation_id)
        return {"reservation_id": reservation_id, "state_sequence": sequence}

    def reconcile(self, outflows: Sequence[Outflow]) -> Reconciliation:
        """Compare rail history to signer state, both directions (plan D17)."""
        return self._state.reconcile(outflows)

    # -- policy updates ---------------------------------------------------- #

    def policy_update(self, raw_policy: Any) -> JSONObject:
        """Adopt a new policy, signed by the *current* admin key (plan D16).

        Checked against the pinned key rather than the key the new document
        nominates: a document that got to name its own admin would be a document
        that could replace the admin.
        """
        incoming = SignedPolicy.from_content(raw_policy)
        if not verify_policy_signature(incoming, admin=self._admin):
            raise SignerError(
                "the new policy is not signed by the admin credential this signer has pinned"
            )
        if incoming.document.treasury != self.document.treasury:
            raise SignerError("a policy update cannot change which treasury the signer serves")
        change = PolicyChange(
            old_hash=self.policy_hash,
            new_hash=incoming.policy_hash,
            signed_by=incoming.signer_public_key,
            at=self._clock.now(),
            credential_type=self._admin.credential_type,
        )
        self._policy = incoming
        self._admin = incoming.document.effective_admin
        self._changes.append(change)
        return {
            "change": change.to_content(),
            "policy_hash": incoming.policy_hash,
            "policy_version": incoming.document.version,
        }

    # -- internals --------------------------------------------------------- #

    def _agent_section(self, intent: Intent) -> Any:
        for agent in self.document.agents:
            if agent.public_key == intent.agent_public_key:
                return agent
        return None

    def _source_tag_for(self, intent: Intent) -> int:
        section = self._agent_section(intent)
        return section.effective_source_tag() if section is not None else MERKL_SOURCE_TAG

    def _agent_id_for(self, intent: Intent) -> str | None:
        section = self._agent_section(intent)
        return section.agent_id if section is not None else None

    def _prepared(self, params: JSONObject, intent: Intent) -> UnsignedTx:
        raw = params.get("prepared_tx")
        if raw is None:
            raise SignerError("propose requires a prepared_tx to sign")
        return self._verify_prepared(UnsignedTx.from_content(raw), intent)

    def _verify_prepared(self, unsigned: UnsignedTx, intent: Intent) -> UnsignedTx:
        """Check the transaction against the intent before signing anything.

        Field by field, and then the bytes: the anchor slot must still hold the
        placeholder, and it must be the only place in the payload that does, so
        the signer knows exactly where its commitment is going.
        """
        fields = unsigned.fields
        problems: list[str] = []
        if unsigned.rail != intent.rail:
            problems.append(f"rail {unsigned.rail!r} is not the intent's {intent.rail!r}")
        if unsigned.rail != self.document.rail:
            problems.append(
                f"rail {unsigned.rail!r} is not the one this policy governs "
                f"({self.document.rail!r})"
            )
        if fields.get("account") != intent.treasury:
            problems.append(f"account {fields.get('account')!r} is not the intent's treasury")
        if fields.get("destination") != intent.destination:
            problems.append(
                f"destination {fields.get('destination')!r} is not the intent's destination"
            )
        if fields.get("amount") != intent.deliver_amount.to_content():
            problems.append(f"amount {fields.get('amount')!r} is not the intent's amount")
        # A trade names a ceiling as well as a delivery. The ceiling is the only
        # number the policy bounded, so a prepared transaction that quietly
        # widened it must not reach the key.
        send_max = fields.get("send_max")
        if intent.is_swap:
            if send_max != intent.outflow.to_content():
                problems.append(f"send_max {send_max!r} is not the intent's sell ceiling")
        elif send_max is not None:
            problems.append("a payment carries no send_max; this transaction names one")
        if fields.get("memo_type") != MEMO_TYPE:
            problems.append(
                f"anchor field is tagged {fields.get('memo_type')!r}, not {MEMO_TYPE!r}"
            )

        payload = unsigned.payload_bytes
        if unsigned.anchor != ANCHOR_PLACEHOLDER:
            problems.append("the anchor field does not hold the placeholder")
        if payload.count(ANCHOR_PLACEHOLDER) != 1:
            problems.append(
                f"the payload has {payload.count(ANCHOR_PLACEHOLDER)} placeholder-shaped runs; "
                "the signer must know which one is the anchor"
            )
        missing = missing_bindings(
            unsigned.rail,
            payload,
            {"treasury": intent.treasury, "destination": intent.destination},
        )
        if missing:
            problems.append(f"the payload does not mention {missing}")

        if problems:
            raise SignerError(
                "the prepared transaction does not match the intent: " + "; ".join(problems)
            )
        return unsigned

    def _reserve(self, decision: Decision, agent_id: str, now: str, expires_at: str) -> str:
        reservation = decision.reservation
        if reservation is None:  # pragma: no cover - allow and escalate always reserve
            raise SignerError("an authorized decision must carry a reservation")
        reservation_id = secrets.token_hex(16)
        self._state.reserve(
            SpendEntry(
                reservation_id=reservation_id,
                agent_id=agent_id,
                asset=reservation.asset,
                value=reservation.value,
                at=now,
                expires_at=expires_at,
            )
        )
        return reservation_id

    @staticmethod
    def _reservation_expiry(decision: Decision, intent: Intent) -> str:
        """The intent's own expiry, or the escalation's if people are given longer."""
        request = decision.escalation
        if request is not None and parse_instant(request.expires_at, "escalation.expires_at") > (
            parse_instant(intent.expires_at, "intent.expires_at")
        ):
            return request.expires_at
        return intent.expires_at

    def _register_escalation(
        self,
        decision: Decision,
        instruction: Instruction,
        intent: Intent,
        unsigned: UnsignedTx,
        reservation_id: str,
        agent_id: str,
    ) -> JSONObject:
        leaves = ReceiptLeaves(
            instruction=instruction,
            intent=intent,
            policy_decision=decision.to_leaf(),
            signer_attestation=None,
        )
        challenge = escalation_challenge(leaves).hex()
        request = decision.escalation
        if request is None:  # pragma: no cover - escalate always carries one
            raise SignerError("an escalated decision must carry escalation parameters")
        pending = PendingEscalation(
            challenge=challenge,
            instruction=instruction,
            intent=intent,
            decision=decision,
            unsigned=unsigned,
            reservation_id=reservation_id,
            expires_at=request.expires_at,
            quorum=request.quorum,
            agent_id=agent_id,
        )
        self._state.escalate(
            EscalationEntry(
                challenge=challenge,
                reservation_id=reservation_id,
                expires_at=request.expires_at,
                content=pending.to_content(),
            )
        )
        self._pending[challenge] = pending
        return self._envelope(
            decision,
            outcome=PolicyOutcome.ESCALATE.value,
            challenge=challenge,
            expires_at=request.expires_at,
            quorum=request.quorum,
            reservation_id=reservation_id,
        )

    def _escalation_leaf(
        self, pending: PendingEscalation, assertions: Sequence[ApprovalAssertion]
    ) -> Escalation:
        return Escalation(
            challenge=pending.challenge,
            expires_at=pending.expires_at,
            quorum=pending.quorum,
            approvals=tuple(a.to_content() for a in assertions),
        )

    def _reject_escalation(
        self,
        pending: PendingEscalation,
        assertions: Sequence[ApprovalAssertion],
        quorum: QuorumResult | None,
        reason: str,
        *,
        release: bool = True,
    ) -> JSONObject:
        """An escalation that did not resolve is a denial with a receipt, not silence."""
        self._pending.pop(pending.challenge, None)
        if release:
            self._state.release(pending.reservation_id)
        else:
            with contextlib.suppress(StateError):
                self._state.resolve_escalation(pending.challenge)
        decision = dataclasses.replace(pending.decision, outcome=PolicyOutcome.DENY.value)
        return self._envelope(
            decision,
            outcome=PolicyOutcome.DENY.value,
            escalation=self._escalation_leaf(pending, assertions).to_content(),
            detail=reason,
            approvals_accepted=list(quorum.accepted) if quorum else [],
        )

    def _authorize(
        self,
        decision: Decision,
        instruction: Instruction,
        intent: Intent,
        unsigned: UnsignedTx,
        reservation_id: str,
        escalation: Escalation | None = None,
    ) -> JSONObject:
        """Compute LEFT, write it into the anchor field, and sign those bytes."""
        leaf = decision.to_leaf(escalation)
        leaves = ReceiptLeaves(
            instruction=instruction,
            intent=intent,
            policy_decision=leaf,
            signer_attestation=None,
        )
        left = authorization_commitment(leaves)
        anchored = unsigned.with_anchor(left.hex())
        payload = anchored.payload_bytes
        if payload[anchored.anchor_offset : anchored.anchor_offset + ANCHOR_BYTES] != left.bytes:
            raise SignerError("the anchor splice did not land where the adapter said it would")

        # The last thing before the key moves: read the bytes. The adapter that
        # produced them runs in the agent's process, so its account of what they
        # encode is exactly the thing that cannot be taken on trust.
        problems = self._codec.problems(
            payload,
            intent,
            left.hex(),
            source_tag=self._source_tag_for(intent),
            agent_id=self._agent_id_for(intent),
        )
        if problems:
            return self._refuse_payload(decision, reservation_id, problems)

        signature = self._keystore.sign(payload)
        return self._envelope(
            decision,
            outcome=PolicyOutcome.ALLOW.value,
            decision_leaf=leaf.to_content(),
            left=left.hex(),
            signature=signature,
            signed_payload=payload.hex(),
            anchored_tx=anchored.to_content(),
            reservation_id=reservation_id,
        )

    def _refuse_payload(
        self, decision: Decision, reservation_id: str, problems: list[str]
    ) -> JSONObject:
        """The payload does not encode the intent. Deny it, and say exactly why.

        A denial rather than an error, because this is a policy outcome with a
        receipt: the agent asked for one payment and its adapter produced the
        bytes for another, and that is worth being able to prove afterwards.
        """
        detail = "; ".join(problems)
        refused = dataclasses.replace(
            decision,
            outcome=PolicyOutcome.DENY.value,
            rules=(
                *decision.rules,
                PolicyRule(
                    name=RULE_PAYLOAD_ENCODES_INTENT,
                    outcome=RuleOutcome.FAIL.value,
                    detail=detail[:1024],
                ),
            ),
        )
        self._state.release(reservation_id)
        return self._envelope(refused, outcome=PolicyOutcome.DENY.value)

    def _envelope(
        self,
        decision: Decision,
        *,
        outcome: str,
        decision_leaf: JSONObject | None = None,
        escalation: JSONValue = None,
        **extra: Any,
    ) -> JSONObject:
        content = decision_leaf if decision_leaf is not None else decision.to_content()
        if escalation is not None:
            content = {**content, "escalation": escalation}
        result: JSONObject = {
            "outcome": outcome,
            "decision": content,
            "attestation": self.attestation(),
            "signer_public_key": self._keystore.public_key(),
            "policy_hash": self.policy_hash,
            "state_sequence": self._state.sequence,
            "risk_score": decision.risk_score.value,
            "reason": decision.reason(),
        }
        result.update({k: v for k, v in extra.items() if v is not None})
        return result


def _required(params: JSONObject, key: str) -> Any:
    if key not in params:
        raise SignerError(f"propose requires {key}")
    return params[key]


def asset_of(intent: Intent) -> str:
    """The asset key an intent's outflow belongs to (re-exported for callers).

    A payment's amount, a trade's ``sell.max_amount``: what the reservation and
    the window are counted in is always the asset that can leave.
    """
    return asset_key(intent.outflow.currency)
