"""The whole receipt verdict: every check, both settlement lines, and the level.

:func:`merkl.core.receipt.verify_receipt_structure` answers everything a receipt
can be asked about *itself*. This module answers the rest — the questions that
need material the verifier brought with it — and then says what the answers add
up to, in the shape plan D9 and D10 require:

* **Level 1** is the receipt alone: the signer's public key, the rail, and the
  local trace. **Level 2** joins the session and the transparency log, which adds
  completeness, the notary's signature and a Bitcoin anchor. The join is optional
  and one-way, so a level-1 verdict is not a lesser verdict — it is a different
  question, answered fully.
* The settlement verdict is **two lines, never one**: transaction authorization
  (did the policy key sign the bytes that settled) and ledger inclusion (is that
  transaction in a ledger anyone can check). A single PASS over both would hide
  which half was actually established, and hiding that is the failure mode the
  whole format exists to prevent.

Above those sits a plain-language summary — what the agent was told, which rule
allowed it, who approved, what settled, when — because a receipt whose meaning
only survives as hex has not been verified by anybody who matters.

Nothing here reaches a network or a clock. Trust anchors (the PCR allowlist, the
validator key set, the policy document, the notary's checkpoint key) are all
arguments. No receipt gets to nominate what it should be judged against.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Mapping, Sequence
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.checks import Check, CheckStatus, VerificationResult, no_data, outcome
from merkl.core.crypto import CryptoError, ed25519_verify
from merkl.core.policy.approvals import ApprovalError, assertions_from_content, verify_quorum
from merkl.core.policy.document import PolicyDocument, PolicyError, SignedPolicy
from merkl.core.receipt import (
    CHECK_LEDGER_INCLUSION,
    CHECK_LOG_JOIN,
    CHECK_POLICY_SIGNATURE,
    CHECK_SIGNED_BLOB,
    LEAF_NAMES,
    Envelope,
    Escalation,
    PolicyDecision,
    ReceiptLeaves,
    Settlement,
    escalation_challenge_from_contents,
    verify_receipt_structure,
)
from merkl.core.verify.attestation import AttestationTrust
from merkl.core.verify.log import LogVerdict, verify_log_bundle
from merkl.core.verify.settlement import (
    CHECK_LEDGER_HEADER,
    CHECK_PROOF_MATCHES,
    CHECK_VALIDATOR_QUORUM,
    LEDGER_UNCHECKED,
    ValidatorTrust,
    read_settlement_proof,
)
from merkl.shared.errors import ValidationError
from merkl.shared.hashing import canonical_hash

__all__ = [
    "AUTHORIZATION_ABSENT",
    "AUTHORIZATION_CONTRADICTED",
    "AUTHORIZATION_VERIFIED",
    "CHECK_APPROVAL_QUORUM",
    "CHECK_ESCALATION_CHALLENGE",
    "CHECK_POLICY_DOCUMENT",
    "LEVEL_RECEIPT",
    "LEVEL_SESSION",
    "PlainSummary",
    "ReceiptVerdict",
    "SessionJoin",
    "receipt_from_content",
    "verify_receipt",
]


CHECK_ESCALATION_CHALLENGE: Final = "policy.escalation_challenge"
CHECK_APPROVAL_QUORUM: Final = "policy.approval_quorum"
CHECK_POLICY_DOCUMENT: Final = "policy.document"

AUTHORIZATION_VERIFIED: Final = "verified"
"""The policy key signed the exact bytes that settled."""

AUTHORIZATION_ABSENT: Final = "absent"
"""Nothing settled, or the receipt carries no signature to check."""

AUTHORIZATION_CONTRADICTED: Final = "contradicted"
"""A signature is present and it does not authorize this transaction."""

LEVEL_RECEIPT: Final = 1
"""Verified against the signer key, the rail and the local trace (plan D9)."""

LEVEL_SESSION: Final = 2
"""Additionally joined to the session log: completeness, notary signature, anchor."""


# --------------------------------------------------------------------------- #
# Plain language
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PlainSummary:
    """The five sentences a non-technical reader needs, before any hash.

    Every member is either a sentence or ``None``. ``None`` means the receipt
    does not say, and the page prints that rather than an empty string, because a
    blank line reads as "nothing to report" and absence is a finding.
    """

    instructed: str | None = None
    rule: str | None = None
    approved: str | None = None
    settled: str | None = None
    when: str | None = None
    signer: str | None = None
    testimony: str | None = None

    def to_content(self) -> JSONObject:
        return {
            "instructed": self.instructed,
            "rule": self.rule,
            "approved": self.approved,
            "settled": self.settled,
            "when": self.when,
            "signer": self.signer,
            "testimony": self.testimony,
        }


_SOURCE_WORDS: Final[dict[str, str]] = {
    "human_input": "a person typed it",
    "mandate": "a standing mandate authorized it",
    "system": "a system triggered it",
}


def _content(contents: Sequence[JSONValue], index: int) -> JSONValue:
    return contents[index] if index < len(contents) else None


def _member(content: JSONValue, key: str) -> Any:
    return content.get(key) if isinstance(content, Mapping) else None


def _amount_words(intent: JSONValue) -> str:
    amount = _member(intent, "amount")
    value = _member(amount, "value") or "?"
    currency = _member(amount, "currency")
    if isinstance(currency, str):
        code = currency
    elif isinstance(currency, Mapping):
        code = str(currency.get("code", "?"))
    else:
        code = "?"
    return f"{value} {code}"


def _summarize(
    contents: Sequence[JSONValue], envelope: Envelope, approved_ids: Sequence[str]
) -> PlainSummary:
    instruction = _content(contents, 0)
    intent = _content(contents, 1)
    decision = _content(contents, 2)
    attestation = _content(contents, 3)
    settlement = _content(contents, 4)
    result = _content(contents, 5)
    reasoning = _content(contents, 6)

    source = str(_member(instruction, "source") or "")
    ref = _member(instruction, "ref")
    instructed = None
    if source:
        words = _SOURCE_WORDS.get(source, f"the instruction came from {source}")
        instructed = f"The agent was told to make this payment — {words}."
        if ref:
            instructed += f" It traces back to {ref}."

    rule = None
    if isinstance(decision, Mapping):
        outcome_word = str(decision.get("outcome", "?"))
        tier = str(decision.get("tier", "?"))
        rules = decision.get("rules")
        names = (
            [str(r.get("name")) for r in rules if isinstance(r, Mapping)]
            if isinstance(rules, list)
            else []
        )
        blocked = (
            [
                str(r.get("name"))
                for r in rules
                if isinstance(r, Mapping) and r.get("outcome") not in ("pass", None)
            ]
            if isinstance(rules, list)
            else []
        )
        if outcome_word == "allow":
            rule = (
                f"The policy allowed it at the {tier} tier; "
                f"{len(names)} rules ran and all of them passed."
            )
        elif outcome_word == "deny":
            rule = (
                f"The policy refused it at the {tier} tier"
                + (f" — {', '.join(blocked)} blocked it." if blocked else ".")
            )
        else:
            rule = f"The policy escalated it at the {tier} tier: it needed a person."

    approved = None
    escalation = _member(decision, "escalation")
    if isinstance(escalation, Mapping):
        quorum = escalation.get("quorum")
        if approved_ids:
            approved = (
                f"{len(approved_ids)} of {quorum} required approvers signed it: "
                f"{', '.join(approved_ids)}."
            )
        else:
            approved = (
                f"It needed {quorum} approver(s); no approval in this receipt verifies "
                "against a policy this verifier was given."
            )
    elif _member(decision, "outcome") == "allow":
        approved = "No person was asked: the policy allowed it outright."

    settled = None
    if isinstance(settlement, Mapping):
        destination = _member(intent, "destination") or "?"
        settled = (
            f"{_amount_words(intent)} went to {destination} on "
            f"{settlement.get('rail', envelope.rail)}, transaction "
            f"{str(settlement.get('tx_hash', ''))[:16]}…"
        )
    elif _member(result, "outcome") == "denied":
        settled = "Nothing settled. The refusal is what this receipt records."

    when = None
    close_time = _member(settlement, "close_time")
    if isinstance(close_time, str):
        when = f"The ledger closed it at {close_time}."
    elif isinstance(_member(intent, "expires_at"), str):
        when = f"The intent was valid until {_member(intent, 'expires_at')}."

    signer = (
        "The signer is unattested: leaf 3 is null, so nothing proves which "
        "machine held the policy key."
        if attestation is None
        else "The signer published an enclave attestation for its policy key."
    )

    testimony = None
    if isinstance(reasoning, Mapping):
        testimony = (
            "The receipt also commits to a hash of the model's reasoning. That is "
            "testimony, not proof: it shows the account was not edited afterwards, "
            "never that it was true."
        )

    return PlainSummary(
        instructed=instructed,
        rule=rule,
        approved=approved,
        settled=settled,
        when=when,
        signer=signer,
        testimony=testimony,
    )


# --------------------------------------------------------------------------- #
# The join to a session (plan D9, level 2)
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class SessionJoin:
    """A bundle to join this receipt to, and what the join found."""

    bundle: Mapping[str, Any]
    log: LogVerdict


def _log_join_check(envelope: Envelope, join: SessionJoin | None) -> Check:
    """Check 17: the envelope hash is what the session committed as an action.

    The whole join, in one comparison. The receipt names a session and a leaf
    index; the session's action at that index carries an ``input_hash``; if that
    hash is the canonical hash of this envelope, the two records are about the
    same event, and the log's own checks then say whether the session itself
    holds up.
    """
    if join is None:
        return no_data(
            CHECK_LOG_JOIN, "no session bundle was supplied, so this is a level-1 verdict"
        )
    locator = envelope.session_locator
    if locator is None:
        return no_data(
            CHECK_LOG_JOIN, "this receipt names no session, so there is nothing to join it to"
        )
    actions = join.bundle.get("actions")
    rows = [a for a in actions if isinstance(a, Mapping)] if isinstance(actions, list) else []
    session = join.bundle.get("session")
    session_id = str(session.get("session_id", "")) if isinstance(session, Mapping) else ""
    if session_id and session_id != locator.session_id:
        return Check(
            CHECK_LOG_JOIN,
            CheckStatus.FAIL,
            f"the receipt names session {locator.session_id}, the bundle is {session_id}",
        )
    if locator.leaf_index >= len(rows):
        return Check(
            CHECK_LOG_JOIN,
            CheckStatus.FAIL,
            f"the receipt names leaf {locator.leaf_index}, the bundle has {len(rows)} actions",
        )
    action = rows[locator.leaf_index]
    committed = str(action.get("input_hash", ""))
    derived = canonical_hash(envelope.to_content()).hex()
    if derived != committed:
        return Check(
            CHECK_LOG_JOIN,
            CheckStatus.FAIL,
            f"the envelope hashes to {derived}, action {locator.leaf_index} committed {committed}",
        )
    action_ok = any(
        r.index == locator.leaf_index and r.ok for r in join.log.actions
    )
    return outcome(
        CHECK_LOG_JOIN,
        action_ok,
        f"the envelope hash is action {locator.leaf_index} of session {locator.session_id}, "
        + (
            "and that action proves into the session root"
            if action_ok
            else "but that action does not prove into the session root"
        ),
    )


# --------------------------------------------------------------------------- #
# The checks that need material the verifier brought
# --------------------------------------------------------------------------- #


def _policy_document_check(
    envelope: Envelope, document: JSONValue, admin_public_key: str | None
) -> tuple[Check, PolicyDocument | None]:
    """Check: the supplied policy is the one the decision names, and it is signed.

    Looked up by hash rather than by version, because a policy replaced since
    cannot be shown in place of the one that actually decided. When the caller
    also pins the admin key, the document's own signature is verified — a policy
    nobody signed is a suggestion.
    """
    if document is None:
        return (
            no_data(
                CHECK_POLICY_DOCUMENT,
                "no policy document was supplied, so the rules that ran cannot be re-read",
            ),
            None,
        )
    parsed: PolicyDocument | None = None
    signature_note = ""
    try:
        if isinstance(document, Mapping) and "document" in document:
            signed = SignedPolicy.from_content(document)
            parsed = signed.document
            if admin_public_key is not None:
                if signed.signer_public_key != admin_public_key:
                    return (
                        Check(
                            CHECK_POLICY_DOCUMENT,
                            CheckStatus.FAIL,
                            f"the policy is signed by {signed.signer_public_key[:16]}…, "
                            f"the pinned admin key is {admin_public_key[:16]}…",
                        ),
                        parsed,
                    )
                if not ed25519_verify(
                    signed.signer_public_key, signed.signature, signed.document.pre_image()
                ):
                    return (
                        Check(
                            CHECK_POLICY_DOCUMENT,
                            CheckStatus.FAIL,
                            "the policy document's admin signature does not verify",
                        ),
                        parsed,
                    )
                signature_note = " and the pinned admin key signed it"
            else:
                signature_note = (
                    "; no admin key was pinned, so who authorized these rules is unchecked"
                )
        else:
            parsed = PolicyDocument.from_content(document)
            signature_note = "; this document carries no signature to check"
    except (PolicyError, ValidationError, CryptoError) as exc:
        return Check(CHECK_POLICY_DOCUMENT, CheckStatus.FAIL, str(exc)), None
    derived = parsed.policy_hash()
    if derived != envelope.policy_hash:
        return (
            Check(
                CHECK_POLICY_DOCUMENT,
                CheckStatus.FAIL,
                f"the supplied policy hashes to {derived}, the receipt names "
                f"{envelope.policy_hash}",
            ),
            parsed,
        )
    return (
        outcome(
            CHECK_POLICY_DOCUMENT,
            True,
            f"the supplied policy hashes to the {envelope.policy_hash[:16]}… the decision "
            f"names{signature_note}",
        ),
        parsed,
    )


def _escalation_challenge_check(
    contents: Sequence[JSONValue], escalation: Escalation | None
) -> Check:
    """Check: the challenge the approvers signed is LEFT_pre over these leaves.

    Without it, an escalation could carry any 32 bytes as its challenge and the
    approvals would verify against something other than this payment. LEFT_pre is
    LEFT with the escalation omitted and the outcome forced to ``escalate``
    (spec section 3.2) — the only two edits the format permits between the
    decision as it escalated and the decision as it was recorded.
    """
    if escalation is None:
        return no_data(
            CHECK_ESCALATION_CHALLENGE, "this decision did not escalate, so nothing was signed"
        )
    try:
        derived = escalation_challenge_from_contents(contents).hex()
    except (ValidationError, ValueError, TypeError) as exc:
        return Check(
            CHECK_ESCALATION_CHALLENGE, CheckStatus.FAIL, f"LEFT_pre does not compute: {exc}"
        )
    return outcome(
        CHECK_ESCALATION_CHALLENGE,
        derived == escalation.challenge.lower(),
        f"LEFT_pre over these leaves is {derived}, the escalation names {escalation.challenge}",
    )


def _approval_quorum_check(
    escalation: Escalation | None,
    challenge_ok: bool,
    policy: PolicyDocument | None,
) -> tuple[Check, tuple[str, ...]]:
    """Check: enough *distinct* approvers the policy names signed the challenge."""
    if escalation is None:
        return (
            no_data(CHECK_APPROVAL_QUORUM, "this decision did not escalate, so nobody approved"),
            (),
        )
    if policy is None:
        return (
            no_data(
                CHECK_APPROVAL_QUORUM,
                "no policy document was supplied, so nothing says whose signature counts",
            ),
            (),
        )
    if not challenge_ok:
        return (
            Check(
                CHECK_APPROVAL_QUORUM,
                CheckStatus.FAIL,
                "the challenge is not LEFT_pre, so the approvals are over another payment",
            ),
            (),
        )
    try:
        assertions = assertions_from_content(list(escalation.approvals))
        result = verify_quorum(
            assertions, bytes.fromhex(escalation.challenge), policy.approvers, escalation.quorum
        )
    except (ApprovalError, ValidationError, ValueError) as exc:
        return Check(CHECK_APPROVAL_QUORUM, CheckStatus.FAIL, str(exc)), ()
    detail = f"{len(result.accepted)} of {escalation.quorum} required approvals verify"
    if result.rejected:
        detail += f"; rejected: {'; '.join(c.detail for c in result.rejected)[:160]}"
    return outcome(CHECK_APPROVAL_QUORUM, result.reached, detail), tuple(result.accepted)


# --------------------------------------------------------------------------- #
# The verdict
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ReceiptVerdict:
    """Every check, the two settlement lines, the level, and the plain summary."""

    receipt_id: str
    result: VerificationResult
    summary: PlainSummary
    transaction_authorization: str
    transaction_authorization_detail: str
    ledger_inclusion: str
    ledger_inclusion_detail: str
    level: int
    level_detail: str
    attested: bool | None
    log: LogVerdict | None = None

    @property
    def ok(self) -> bool:
        """Nothing was contradicted. Not the same as "everything was checked"."""
        return self.result.ok and (self.log.ok if self.log is not None else True)

    @property
    def complete(self) -> bool:
        """Every check actually ran."""
        return self.result.complete and (self.log.complete if self.log is not None else True)

    def to_content(self) -> JSONObject:
        content: JSONObject = {
            "receipt_id": self.receipt_id,
            "ok": self.ok,
            "complete": self.complete,
            "level": self.level,
            "level_detail": self.level_detail,
            "settlement": {
                "transaction_authorization": self.transaction_authorization,
                "transaction_authorization_detail": self.transaction_authorization_detail,
                "ledger_inclusion": self.ledger_inclusion,
                "ledger_inclusion_detail": self.ledger_inclusion_detail,
            },
            "attested": self.attested,
            "summary": self.summary.to_content(),
            "checks": [
                {"name": c.name, "status": c.status.value, "detail": c.detail}
                for c in self.result.checks
            ],
        }
        if self.log is not None:
            content["log"] = self.log.to_content()
        return content


def _replace(checks: list[Check], name: str, replacement: Check) -> None:
    for i, check in enumerate(checks):
        if check.name == name:
            checks[i] = replacement
            return
    checks.append(replacement)


def _insert_before(checks: list[Check], name: str, extra: Sequence[Check]) -> None:
    for i, check in enumerate(checks):
        if check.name == name:
            checks[i:i] = list(extra)
            return
    checks.extend(extra)


def _authorization_line(result: VerificationResult, settled: bool) -> tuple[str, str]:
    signature = result.get(CHECK_POLICY_SIGNATURE)
    blob = result.get(CHECK_SIGNED_BLOB)
    if not settled:
        return AUTHORIZATION_ABSENT, "nothing settled, so no transaction was authorized"
    if signature is None or signature.status is CheckStatus.NOT_IMPLEMENTED:
        return (
            AUTHORIZATION_ABSENT,
            signature.detail if signature else "no policy signature was checked",
        )
    if signature.status is CheckStatus.FAIL:
        return AUTHORIZATION_CONTRADICTED, signature.detail
    if blob is not None and blob.status is CheckStatus.FAIL:
        return AUTHORIZATION_CONTRADICTED, blob.detail
    if blob is not None and blob.status is CheckStatus.PASS:
        return (
            AUTHORIZATION_VERIFIED,
            "the policy key signed a payload carrying LEFT, and the transaction id "
            "re-derives from the blob that was submitted",
        )
    return (
        AUTHORIZATION_VERIFIED,
        "the policy key signed a payload carrying LEFT; the blob itself was not supplied",
    )


def receipt_from_content(receipt: Mapping[str, Any]) -> tuple[Envelope, list[JSONValue]]:
    """Parse a v1.2 ``receipts[]`` entry into an envelope and its seven contents.

    Raises ``ValidationError`` when the envelope will not parse at all. Leaf
    contents are *not* parsed into models here: a tampered leaf must fail a
    named check rather than raise on the way in.
    """
    envelope = Envelope.from_content(receipt.get("envelope"))
    raw = receipt.get("leaves")
    contents: list[JSONValue] = list(raw) if isinstance(raw, list) else []
    return envelope, contents


def _parsed(model: Any, content: JSONValue) -> Any:
    if content is None:
        return None
    try:
        return model.from_content(content)
    except (ValidationError, ValueError, TypeError):
        return None


def verify_receipt(
    envelope: Envelope,
    leaves: ReceiptLeaves | Sequence[JSONValue],
    *,
    attestation_trust: AttestationTrust | None = None,
    now: datetime.datetime | None = None,
    validator_trust: ValidatorTrust | None = None,
    settlement_proof: JSONValue = None,
    policy_document: JSONValue = None,
    admin_public_key: str | None = None,
    session_bundle: Mapping[str, Any] | None = None,
    live_settlement: bool = False,
) -> ReceiptVerdict:
    """Verify a receipt as far as the supplied material allows, and say how far.

    Every argument after ``leaves`` is something the *verifier* brought: the PCR
    allowlist and the moment to judge it at, the validator key set, the policy
    document and the admin key that signed it, the session bundle to join. Each
    one absent turns its checks into named ``not_implemented`` entries — never
    into passes, and never into silence.
    """
    contents: list[JSONValue] = (
        list(leaves.contents()) if isinstance(leaves, ReceiptLeaves) else list(leaves)
    )
    structural = verify_receipt_structure(
        envelope, contents, attestation_trust=attestation_trust, now=now
    )
    checks = list(structural.checks)

    settlement = _parsed(Settlement, _content(contents, 4))
    decision = _parsed(PolicyDecision, _content(contents, 2))
    escalation = decision.escalation if decision is not None else None

    document_check, policy = _policy_document_check(envelope, policy_document, admin_public_key)
    challenge_check = _escalation_challenge_check(contents, escalation)
    quorum_check, approved_ids = _approval_quorum_check(
        escalation, challenge_check.status is CheckStatus.PASS, policy
    )
    _insert_before(
        checks, CHECK_POLICY_SIGNATURE, (document_check, challenge_check, quorum_check)
    )

    reading_checks: tuple[Check, ...]
    if settlement is None:
        reading_checks = (
            no_data(CHECK_PROOF_MATCHES, "nothing settled, so there is no proof to read"),
            no_data(CHECK_LEDGER_HEADER, "nothing settled, so there is no ledger to check"),
            no_data(CHECK_VALIDATOR_QUORUM, "nothing settled, so no validators signed anything"),
        )
        ledger_state = LEDGER_UNCHECKED
        ledger_detail = "nothing settled, so there is no ledger inclusion to establish"
    else:
        reading = read_settlement_proof(
            settlement_proof,
            rail=settlement.rail,
            tx_hash=settlement.tx_hash,
            ledger_index=settlement.ledger_index,
            trust=validator_trust,
            live=live_settlement,
        )
        reading_checks = reading.checks
        ledger_state = reading.ledger_inclusion
        ledger_detail = reading.detail
    _insert_before(checks, CHECK_LEDGER_INCLUSION, reading_checks)
    _replace(
        checks,
        CHECK_LEDGER_INCLUSION,
        Check(
            CHECK_LEDGER_INCLUSION,
            CheckStatus.PASS
            if ledger_state in ("proven-offline", "verified-live")
            else CheckStatus.FAIL
            if any(c.status is CheckStatus.FAIL for c in reading_checks)
            else CheckStatus.NOT_IMPLEMENTED,
            f"{ledger_state}: {ledger_detail}",
        ),
    )

    log: LogVerdict | None = None
    join: SessionJoin | None = None
    if session_bundle is not None:
        log = verify_log_bundle(session_bundle)
        join = SessionJoin(bundle=session_bundle, log=log)
    join_check = _log_join_check(envelope, join)
    _replace(checks, CHECK_LOG_JOIN, join_check)

    result = VerificationResult(tuple(checks))
    authorization, authorization_detail = _authorization_line(result, settlement is not None)

    level = LEVEL_SESSION if join_check.status is CheckStatus.PASS else LEVEL_RECEIPT
    level_detail = (
        "level 2: this receipt is committed in a session log whose checkpoint and "
        "inclusion proof were checked here"
        if level == LEVEL_SESSION
        else "level 1: verified against the signer key, the rail and this receipt alone — "
        "joining a session log would add completeness, a notary signature and an anchor"
    )

    attestation_check = result.get("signer.attestation")
    attested: bool | None
    if _content(contents, 3) is None:
        attested = False
    elif attestation_check is not None and attestation_check.status is CheckStatus.PASS:
        attested = True
    else:
        attested = None

    return ReceiptVerdict(
        receipt_id=envelope.receipt_id,
        result=result,
        summary=_summarize(contents, envelope, approved_ids),
        transaction_authorization=authorization,
        transaction_authorization_detail=authorization_detail,
        ledger_inclusion=ledger_state,
        ledger_inclusion_detail=ledger_detail,
        level=level,
        level_detail=level_detail,
        attested=attested,
        log=log,
    )


LEAF_NAMES_FOR_DISPLAY: Final[tuple[str, ...]] = LEAF_NAMES
"""Re-exported so a renderer does not import two modules to name seven leaves."""
