"""``ReceiptBuilder`` — propose, route, co-sign, settle, attest.

This is the only place the whole flow is written down, and it is deliberately
thin: every decision it makes is the signer's, every byte it hashes is core's,
and every network call is an adapter's. What it owns is *order*, and the order is
load-bearing.

```
prepare(placeholder) → propose → ┬ deny     → receipt, nothing submitted
                                 ├ escalate → collect approvals → approve ┐
                                 └ allow ───────────────────────────────┬─┘
                                                                        ↓
        prepare(LEFT) → check it equals what the signer signed → agent_sign
                      → attach policy signature → submit → capture proof
                      → append leaves 4-6 → envelope → record in the session
                      → file receipt + proof (local store, then notary)
```

Two checks in that chain are the reason it is not simply glue:

* the caller re-prepares the transaction with the real commitment and requires it
  to equal, byte for byte, the payload the signer signed. If an adapter changed
  anything else between the two calls, this is where it stops;
* a submission that fails releases the reservation, so a rail that refused does
  not permanently consume the agent's window.

A denial produces a receipt (plan D14). A receipt exists whether or not money
moved, because "we refused" is a fact worth being able to prove — and an agent
that can silently produce nothing is an agent whose refusals cannot be audited.

merkl-api is never on this *decision* path (plan D12): nothing is asked of it
before money moves, and a notary that is down cannot stop a payment or delay one.
Filing is the last step rather than a step, and it carries the whole record —
the seven leaves *and* the settlement capture, which lives only here. Leaf 4
commits a short ``settlement_proof_ref``; the ledger header, the transaction and
the validators' signatures a reader needs to establish inclusion offline are what
the rail adapter captured at submit time, and a flow that held them in memory and
dropped them would leave every reader of that receipt with
``ledger inclusion: unchecked``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import secrets
from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Final

from merkl.core.canonical import JSONObject, format_instant, parse_decimal, shift_instant
from merkl.core.checks import VerificationResult
from merkl.core.intent import Intent
from merkl.core.policy.approvals import ApprovalAssertion
from merkl.core.rail import (
    ANCHOR_PLACEHOLDER_HEX,
    SettlementProof,
    SettlementRef,
    Signature,
)
from merkl.core.receipt import (
    BalanceDelta,
    Envelope,
    Instruction,
    PolicyDecision,
    PolicyOutcome,
    PolicySignature,
    Reasoning,
    Receipt,
    ReceiptLeaves,
    Result,
    ResultOutcome,
    SessionLocator,
    Settlement,
    authorization_commitment,
)
from merkl.sdk.decorators import get_current_session
from merkl.shared.errors import MerklError
from merkl.shared.ids import ActionId
from merkl.signer.auth import sign_request

REQUEST_TTL_SECONDS: Final = 300
ACTION_TYPE: Final = "transaction"


class ReceiptBuildError(MerklError):
    """Raised when the flow cannot continue — never when a payment is refused."""

    error_code = "receipt_build_error"


class SystemClock:
    """The default :class:`~merkl.core.ports.ClockPort`."""

    def now(self) -> str:
        return format_instant(datetime.now().astimezone())


@dataclasses.dataclass(frozen=True)
class ReceiptOutcome:
    """What one attempt produced: a receipt, always, and settlement if it settled."""

    receipt: Receipt
    decision: PolicyDecision
    settlement: SettlementRef | None = None
    proof: SettlementProof | None = None
    action_id: str | None = None
    reason: str = ""
    notary_error: str | None = None
    """Why the receipt did not reach the notary, when it did not.

    A payment that has already settled cannot be undone by a witness being down,
    so a filing failure never raises here (plan D12) — but it is never silent
    either. The local store still has the receipt and its proof; this says the
    notary does not yet, so a caller can retry rather than discover the gap at
    audit time."""

    pending_escalation: JSONObject | None = None
    """``{challenge, expires_at, quorum}`` when this decision is still
    ``escalate``. The signer's ``propose`` response carries these at the top
    level — RECEIPT-SPEC.md has nowhere in a receipt leaf for them until the
    escalation resolves — so a caller filing this receipt with a notary that
    wants to open a human queue entry from it (rather than only from an
    already-resolved one) has to hand them over separately. This is exactly
    the shape merkl-api's ``POST /v1/receipts`` accepts as
    ``pending_escalation`` (``docs/INTERFACES-P4.md`` sec 2)."""

    @property
    def envelope(self) -> Envelope:
        return self.receipt.envelope

    @property
    def settled(self) -> bool:
        return self.settlement is not None

    @property
    def outcome(self) -> str:
        return self.decision.outcome

    def verify(self) -> VerificationResult:
        """Re-verify the receipt as an outside reader would."""
        return self.receipt.verify_structure()


class ReceiptBuilder:
    """Orchestrates one payment from instruction to receipt."""

    def __init__(
        self,
        *,
        signer: Any,
        settlement: Any,
        agent_id: str,
        agent_public_key: str,
        agent_sign: Any,
        clock: Any | None = None,
        approvals: Any | None = None,
        receipt_store: Any | None = None,
        notary: Any | None = None,
        rail: str | None = None,
    ) -> None:
        self._signer = signer
        self._rail = settlement
        self._agent_id = agent_id
        self._agent_public_key = agent_public_key
        self._agent_sign = agent_sign
        self._clock = clock or SystemClock()
        self.approvals = approvals
        """The queue humans answer. Swappable after construction: the approval
        route is a deployment choice, not a property of the flow."""
        self._store = receipt_store
        self._notary = notary
        """Where the finished receipt is filed, afterwards and never before."""
        self._rail_name = rail

    # -- the flow ---------------------------------------------------------- #

    async def execute(
        self,
        *,
        instruction: Instruction,
        intent: Intent,
        reasoning: Reasoning | None = None,
        receipt_id: str | None = None,
        depends_on: str | None = None,
        assertions: Sequence[ApprovalAssertion] | None = None,
    ) -> ReceiptOutcome:
        """Run the whole flow and return a receipt, whatever the verdict."""
        receipt_id = receipt_id or str(ActionId.generate())
        session = get_current_session()
        session_id = str(getattr(session, "session_id", "") or "")
        unsigned = await self._rail.prepare(
            intent,
            ANCHOR_PLACEHOLDER_HEX,
            agent_id=self._agent_id,
            session_id=session_id,
            task_id=receipt_id,
        )
        response = await self._signer.propose(
            self._request(intent, instruction, unsigned).to_content()
        )

        if response["outcome"] == PolicyOutcome.ESCALATE.value:
            response = await self._resolve(response, unsigned, assertions)

        if response["outcome"] != PolicyOutcome.ALLOW.value:
            return await self._refused(
                receipt_id, instruction, intent, response, reasoning, depends_on
            )
        return await self._settle(receipt_id, instruction, intent, response, reasoning, depends_on)

    async def resume(
        self,
        *,
        instruction: Instruction,
        intent: Intent,
        decision: JSONObject,
        receipt_id: str | None = None,
        reasoning: Reasoning | None = None,
        depends_on: str | None = None,
    ) -> ReceiptOutcome:
        """Finish a payment whose decision was already reached out of band.

        ``approve``/``reject`` decide once (``docs/SIGNER-RPC.md`` §4): the
        signer drops its pending escalation the instant one caller's assertion
        completes the quorum, so whichever caller made that call is the only
        one who ever sees the resulting ``allow``/``deny``. When that caller is
        a notary relaying a human's approval rather than this process, this is
        how the agent picks the flow back up: ``decision`` is the signer's raw
        result — the same shape ``propose``/``approve`` return to
        :meth:`execute` itself — and this runs exactly the tail ``execute``
        would have run against it, co-signing and submitting on ``allow``,
        filing a receipt either way.
        """
        receipt_id = receipt_id or str(ActionId.generate())
        if decision["outcome"] != PolicyOutcome.ALLOW.value:
            return await self._refused(
                receipt_id, instruction, intent, decision, reasoning, depends_on
            )
        return await self._settle(receipt_id, instruction, intent, decision, reasoning, depends_on)

    # -- steps ------------------------------------------------------------- #

    def _request(self, intent: Intent, instruction: Instruction, unsigned: Any) -> Any:
        now = self._clock.now()
        return sign_request(
            method="propose",
            agent_id=self._agent_id,
            nonce=secrets.token_hex(16),
            expires_at=shift_instant(now, REQUEST_TTL_SECONDS, "now"),
            params={
                "instruction": instruction.to_content(),
                "intent": intent.to_content(),
                "prepared_tx": unsigned.to_content(),
            },
            agent_public_key=self._agent_public_key,
            sign=self._agent_sign,
        )

    async def _resolve(
        self,
        response: JSONObject,
        unsigned: Any,
        assertions: Sequence[ApprovalAssertion] | None,
    ) -> JSONObject:
        """Take the escalation to people and bring the answer back.

        The approvals are *relayed*, never judged here: quorum, expiry and every
        signature are the signer's to check (plan D11), and a client that decided
        for itself whether two approvals were enough would be a client that could
        decide one was.
        """
        challenge = str(response["challenge"])
        collected = list(assertions or ())
        if not collected and self.approvals is not None:
            await self.approvals.enqueue(response)
            collected = list(await self.approvals.collect(challenge))
        if not collected:
            return response
        resolved: JSONObject = await self._signer.approve(
            challenge, collected, unsigned.to_content()
        )
        return resolved

    async def _refused(
        self,
        receipt_id: str,
        instruction: Instruction,
        intent: Intent,
        response: JSONObject,
        reasoning: Reasoning | None,
        depends_on: str | None,
    ) -> ReceiptOutcome:
        """A denial or an unresolved escalation. Both leave a receipt behind."""
        decision = PolicyDecision.from_content(response["decision"])
        escalating = response["outcome"] == PolicyOutcome.ESCALATE.value
        reason = str(response.get("reason", ""))
        leaves = ReceiptLeaves(
            instruction=instruction,
            intent=intent,
            policy_decision=decision,
            signer_attestation=None,
            settlement=None,
            result=Result(
                outcome=(
                    ResultOutcome.EXPIRED.value if escalating else ResultOutcome.DENIED.value
                ),
                detail=(
                    "Awaiting human approval; nothing was submitted."
                    if escalating
                    else f"Denied by policy; nothing was submitted. {reason}"[:1024]
                ),
            ),
            reasoning=reasoning,
        )
        receipt = self._build(receipt_id, leaves, response)
        receipt, action_id = await self._join_session(receipt, response, depends_on)
        await self._store_receipt(receipt)
        notary_error = await self._file_with_notary(receipt, None)
        pending_escalation: JSONObject | None = (
            {
                "challenge": str(response["challenge"]),
                "expires_at": str(response["expires_at"]),
                "quorum": int(str(response["quorum"])),
            }
            if escalating
            else None
        )
        return ReceiptOutcome(
            receipt=receipt,
            decision=decision,
            action_id=action_id,
            reason=reason,
            notary_error=notary_error,
            pending_escalation=pending_escalation,
        )

    async def _settle(
        self,
        receipt_id: str,
        instruction: Instruction,
        intent: Intent,
        response: JSONObject,
        reasoning: Reasoning | None,
        depends_on: str | None,
    ) -> ReceiptOutcome:
        decision = PolicyDecision.from_content(response["decision"])
        left = str(response["left"])
        reservation_id = str(response["reservation_id"])

        authorization = ReceiptLeaves(
            instruction=instruction,
            intent=intent,
            policy_decision=decision,
            signer_attestation=None,
        )
        if authorization_commitment(authorization).hex() != left:
            raise ReceiptBuildError(
                "the signer's LEFT does not match the leaves it was given; refusing to submit"
            )

        anchored = await self._rail.prepare(
            intent,
            left,
            agent_id=self._agent_id,
            session_id=str(getattr(get_current_session(), "session_id", "") or ""),
            task_id=receipt_id,
        )
        if anchored.signing_payload != response["signed_payload"]:
            await self._release(reservation_id)
            raise ReceiptBuildError(
                "the anchored transaction differs from the bytes the policy key signed; "
                "refusing to submit"
            )

        signature = Signature(
            public_key=str(response["signer_public_key"]),
            signature=str(response["signature"]),
        )
        partial = await self._rail.agent_sign(anchored)
        signed = await self._rail.attach_policy_signature(partial, signature)

        try:
            ref = await self._rail.submit(signed)
        except Exception as exc:
            await self._release(reservation_id)
            return await self._failed(
                receipt_id, authorization, decision, response, reasoning, depends_on, exc
            )

        proof = await self._rail.settlement_proof(ref)
        leaves = dataclasses.replace(
            authorization,
            settlement=Settlement(
                rail=ref.rail,
                tx_hash=ref.tx_hash,
                ledger_index=ref.ledger_index,
                close_time=ref.close_time,
                signed_tx_blob=ref.signed_tx_blob,
                observed_anchor=ref.observed_anchor,
                settlement_proof_ref=proof.proof_ref() if proof else None,
                observed_memos=getattr(ref, "observed_memos", None),
                policy_signature=PolicySignature(
                    algorithm="ed25519",
                    public_key=signature.public_key,
                    signature=signature.signature,
                    payload=str(response["signed_payload"]),
                ),
            ),
            result=Result(
                outcome=ResultOutcome.SETTLED.value,
                engine_result=ref.engine_result,
                balance_deltas=_deltas(intent),
            ),
            reasoning=reasoning,
        )
        receipt = self._build(receipt_id, leaves, response)
        await self._signer.settle(reservation_id, ref.tx_hash)
        receipt, action_id = await self._join_session(receipt, response, depends_on)
        # The capture goes with the receipt, to both places. Leaf 4 commits only
        # a `settlement_proof_ref`; the header, the transaction and the
        # validators' signatures that establish ledger inclusion offline exist
        # nowhere but here, and a flow that dropped them would leave every
        # reader of this receipt unable to check the one thing it is about.
        await self._store_receipt(receipt, proof)
        notary_error = await self._file_with_notary(receipt, proof)
        return ReceiptOutcome(
            receipt=receipt,
            decision=decision,
            settlement=ref,
            proof=proof,
            action_id=action_id,
            reason=str(response.get("reason", "")),
            notary_error=notary_error,
        )

    async def _failed(
        self,
        receipt_id: str,
        authorization: ReceiptLeaves,
        decision: PolicyDecision,
        response: JSONObject,
        reasoning: Reasoning | None,
        depends_on: str | None,
        error: Exception,
    ) -> ReceiptOutcome:
        """The rail refused. The authorization still happened, and still commits."""
        leaves = dataclasses.replace(
            authorization,
            settlement=None,
            result=Result(
                outcome=ResultOutcome.FAILED.value,
                engine_result=getattr(error, "engine_result", None),
                detail=str(error)[:1024],
            ),
            reasoning=reasoning,
        )
        receipt = self._build(receipt_id, leaves, response)
        receipt, action_id = await self._join_session(receipt, response, depends_on)
        await self._store_receipt(receipt)
        notary_error = await self._file_with_notary(receipt, None)
        return ReceiptOutcome(
            receipt=receipt,
            decision=decision,
            action_id=action_id,
            reason=str(error),
            notary_error=notary_error,
        )

    # -- plumbing ---------------------------------------------------------- #

    def _build(self, receipt_id: str, leaves: ReceiptLeaves, response: JSONObject) -> Receipt:
        return Receipt.build(
            receipt_id=receipt_id,
            leaves=leaves,
            agent_id=self._agent_id,
            signer_public_key=str(response["signer_public_key"]),
        )

    async def _release(self, reservation_id: str) -> None:
        with contextlib.suppress(Exception):  # the signer may already have released it
            await self._signer.release(reservation_id)

    async def _store_receipt(self, receipt: Receipt, proof: SettlementProof | None = None) -> None:
        """Write the receipt — and the capture taken with it — to the local store.

        The proof goes through its own port method rather than a fourth argument
        to ``put`` (``merkl.core.ports.SettlementProofStorePort``), so a store
        written before this existed keeps working: it records the receipt and
        simply does not record the proof. Probed for, never assumed.
        """
        if self._store is None:
            return
        await self._store.put(receipt.envelope, receipt.leaves)
        put_proof = getattr(self._store, "put_settlement_proof", None)
        if proof is not None and put_proof is not None:
            await put_proof(receipt.envelope.receipt_id, proof)

    async def _file_with_notary(
        self, receipt: Receipt, proof: SettlementProof | None
    ) -> str | None:
        """File the receipt with the notary, proof included. Returns any error.

        Never raises. The payment has settled, the local store has the record,
        and a witness that is unreachable is not permitted to turn a completed
        payment into a failed call (plan D12). The failure is returned so it can
        be reported rather than lost.
        """
        if self._notary is None:
            return None
        try:
            await self._notary.file_receipt(
                receipt.envelope, receipt.leaves, settlement_proof=proof
            )
        except Exception as exc:  # noqa: BLE001 - a witness may be down; a payer may not care
            return str(exc)
        return None

    async def attach_settlement_proof(self, receipt_id: str, proof: SettlementProof) -> str | None:
        """File a capture that completed after its receipt was already filed.

        The late path (``POST /v1/receipts/{id}/settlement-proof``): validations
        collected after the fact, a header fetched on a retry. The evidence is
        the same evidence and belongs on the same receipt, so it goes to the
        local store as well as the notary. Returns the notary's error, if any,
        on the same terms as filing a receipt does.
        """
        if self._store is not None:
            put_proof = getattr(self._store, "put_settlement_proof", None)
            if put_proof is not None:
                await put_proof(receipt_id, proof)
        if self._notary is None:
            return None
        try:
            await self._notary.file_settlement_proof(receipt_id, proof)
        except Exception as exc:  # noqa: BLE001 - see _file_with_notary
            return str(exc)
        return None

    async def _join_session(
        self, receipt: Receipt, response: JSONObject, depends_on: str | None
    ) -> tuple[Receipt, str | None]:
        """Commit the envelope hash as one action in the enclosing session (D4).

        The receipt inherits log inclusion, the checkpoint signature and Bitcoin
        anchoring from the session it lands in, with no second chain. The join is
        optional and one-way (D9): a receipt that never reaches a session is still
        a complete receipt, so a notary that is down cannot stop a payment.

        A joined receipt's envelope carries a ``session_locator`` naming exactly
        where its hash was committed — the notary uses it to link the stored
        receipt back to the session and action (``docs/INTERFACES-P4.md`` sec 2).
        The locator has to be in the envelope *before* it is hashed, so the leaf
        index is the one piece of information predicted rather than read back:
        the session assigns leaf indices in append order, so the next one is
        exactly this session's current ``action_count``, true for the single
        sequential writer this flow assumes.
        """
        session = get_current_session()
        if session is None:
            return receipt, None
        locator = SessionLocator(
            session_id=str(session.session_id), leaf_index=session.action_count
        )
        receipt = dataclasses.replace(
            receipt, envelope=dataclasses.replace(receipt.envelope, session_locator=locator)
        )
        outcome = receipt.leaves.result
        recorded = await session.record_action(
            tool_name=f"{receipt.envelope.rail}.payment",
            input_data=receipt.envelope.to_content(),
            output_data=outcome.to_content() if outcome else None,
            action_type=ACTION_TYPE,
            guardrail_result=_guardrail(receipt.leaves.policy_decision),
            status=_status(outcome),
            category="payments",
            display_name=_display_name(receipt),
            depends_on=[depends_on] if depends_on else [],
        )
        action_id = str(recorded.get("action_id")) if isinstance(recorded, dict) else None
        return receipt, action_id


def _guardrail(decision: PolicyDecision | None) -> str:
    """The session's guardrail column mirrors the signer's verdict."""
    if decision is None:  # pragma: no cover - every receipt has leaf 2
        return "passed"
    return {
        PolicyOutcome.ALLOW.value: "passed",
        PolicyOutcome.DENY.value: "blocked",
        PolicyOutcome.ESCALATE.value: "flagged",
    }.get(decision.outcome, "passed")


def _status(result: Result | None) -> str:
    if result is None or result.outcome == ResultOutcome.SETTLED.value:
        return "success"
    return "blocked" if result.outcome == ResultOutcome.DENIED.value else "failure"


def _display_name(receipt: Receipt) -> str:
    intent = receipt.leaves.intent
    if intent is None:  # pragma: no cover - every receipt has leaf 1
        return "Payment"
    return f"Pay {intent.amount.value} to {intent.destination[:12]}…"


def _deltas(intent: Intent) -> tuple[BalanceDelta, ...]:
    """The money that moved, as signed decimal strings. Never a float."""
    amount: Decimal = parse_decimal(intent.amount.value, "amount")
    return (
        BalanceDelta(account=intent.treasury, currency=intent.amount.currency, value=f"-{amount}"),
        BalanceDelta(
            account=intent.destination, currency=intent.amount.currency, value=str(amount)
        ),
    )


__all__ = [
    "ReceiptBuildError",
    "ReceiptBuilder",
    "ReceiptOutcome",
    "SystemClock",
]
