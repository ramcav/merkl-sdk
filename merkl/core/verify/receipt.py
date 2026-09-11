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
from merkl.core.crypto import CryptoError
from merkl.core.policy.approvals import (
    ApprovalError,
    assertions_from_content,
    verify_policy_signature,
    verify_quorum,
)
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
from merkl.core.verify.log import LogVerdict, leaf_index_of, verify_log_bundle
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
    "CHECK_LABELS",
    "CHECK_POLICY_DOCUMENT",
    "LEVEL_DETAIL_RECEIPT",
    "LEVEL_DETAIL_SESSION",
    "LEVEL_RECEIPT",
    "LEVEL_SESSION",
    "PlainSummary",
    "ReceiptVerdict",
    "SessionJoin",
    "UncheckedCheck",
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

LEVEL_DETAIL_SESSION: Final = (
    "Level 2: verified against the signer key, the ledger, and the notary's log "
    "(session sealed, checkpoint signed)."
)
"""One sentence, already naming its level — a page must not prefix it again."""

LEVEL_DETAIL_RECEIPT: Final = (
    "Level 1: verified against the signer key, the ledger and this receipt alone; "
    "no notary log was available to add completeness and an anchor."
)
"""The level-1 sentence. Not a lesser verdict: a different question, answered."""


CHECK_LABELS: Final[dict[str, str]] = {
    "signer.attestation": "enclave attestation",
    "settlement.ledger_inclusion": "ledger inclusion",
    "settlement.proof_matches_receipt": "the settlement capture",
    "settlement.ledger_header": "the ledger header",
    "settlement.validator_quorum": "the validator quorum",
    "settlement.signed_blob": "the submitted transaction blob",
    "settlement.anchor_equals_left": "the rail anchor",
    "settlement.policy_signature": "the policy signature",
    "policy.document": "the policy document",
    "policy.signature": "the policy signature",
    "policy.escalation_challenge": "the escalation challenge",
    "policy.approval_quorum": "the approval quorum",
    "intent.matches_settled_fields": "the settled fields",
    "session.log_join": "the session join",
    "log.actions": "the session actions",
    "log.session_root": "the session root",
    "log.continuation": "the continuation binding",
    "log.audit_entry": "the audit-log entry",
    "log.inclusion": "log inclusion",
    "log.checkpoint_body": "the checkpoint body",
    "log.checkpoint_signature": "the checkpoint signature",
    "log.evidence": "the evidence records",
}
"""Plain words for a check name, so an unchecked line reads as a sentence.

A name with no entry here is printed as its name. That is deliberate: an
unnamed check is still listed, because the whole point of this list is that
nothing goes unchecked *silently*.
"""


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
    testimony_note: str | None = None
    """Leaf 6's ``note``, verbatim — the one member that is *not* our sentence.

    It belongs on its own line, quieter than the testimony sentence above it and
    never run into it: the sentence is this verifier speaking about what a
    committed hash does and does not establish, and the note is the agent
    speaking about itself. Running them together would lend one the other's
    authority, which is the exact confusion leaf 6 exists to prevent.
    """

    def to_content(self) -> JSONObject:
        return {
            "instructed": self.instructed,
            "rule": self.rule,
            "approved": self.approved,
            "settled": self.settled,
            "when": self.when,
            "signer": self.signer,
            "testimony": self.testimony,
            "testimony_note": self.testimony_note,
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


def _currency_word(currency: JSONValue) -> str:
    if isinstance(currency, str):
        return currency
    if isinstance(currency, Mapping):
        return str(currency.get("code", "?"))
    return "?"


def _amount_words(intent: JSONValue) -> str:
    """What this intent moves, in words. A trade's outflow is its sell ceiling."""
    if _member(intent, "type") == "swap":
        sell = _member(intent, "sell")
        ceiling = _member(sell, "max_amount") or "?"
        return f"up to {ceiling} {_currency_word(_member(sell, 'currency'))}"
    amount = _member(intent, "amount")
    value = _member(amount, "value") or "?"
    return f"{value} {_currency_word(_member(amount, 'currency'))}"


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
            rule = f"The policy refused it at the {tier} tier" + (
                f" — {', '.join(blocked)} blocked it." if blocked else "."
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
    if isinstance(settlement, Mapping) and _member(intent, "type") == "swap":
        buy = _member(intent, "buy")
        spent = _member(result, "spent")
        cost = (
            f"{spent.get('value')} {_currency_word(spent.get('currency'))}"
            if isinstance(spent, Mapping)
            else _amount_words(intent)
        )
        settled = (
            f"The treasury bought {_member(buy, 'amount') or '?'} "
            f"{_currency_word(_member(buy, 'currency'))} for {cost} on "
            f"{settlement.get('rail', envelope.rail)}, transaction "
            f"{str(settlement.get('tx_hash', ''))[:16]}…"
        )
    elif isinstance(settlement, Mapping):
        destination = _member(intent, "destination") or "?"
        settled = (
            f"{_amount_words(intent)} went to {destination} on "
            f"{settlement.get('rail', envelope.rail)}, transaction "
            f"{str(settlement.get('tx_hash', ''))[:16]}…"
        )
    elif _member(result, "outcome") == "denied":
        settled = "Nothing settled. The refusal is what this receipt records."
    elif _member(result, "outcome") == "pending":
        settled = "Nothing has settled yet: this payment is waiting for a person to approve it."
    elif _member(result, "outcome") == "expired":
        settled = "Nothing settled. Nobody answered before the approval deadline passed."

    when = None
    close_time = _member(settlement, "close_time")
    if isinstance(close_time, str):
        when = f"The ledger closed it at {close_time}."
    elif isinstance(_member(intent, "expires_at"), str):
        when = f"The intent was valid until {_member(intent, 'expires_at')}."

    signer = (
        "The signer is unattested: leaf 3 is null, so nothing proves which "
        "machine held the policy key — expected for a dev signer; a Nitro "
        "signer attests."
        if attestation is None
        else "The signer published an enclave attestation for its policy key."
    )

    testimony = None
    testimony_note = None
    if isinstance(reasoning, Mapping):
        testimony = (
            "The receipt also commits to a hash of the model's reasoning. That is "
            "testimony, not proof: it shows the account was not edited afterwards, "
            "never that it was true."
        )
        note = reasoning.get("note")
        if isinstance(note, str) and note.strip():
            testimony_note = note.strip()

    return PlainSummary(
        instructed=instructed,
        rule=rule,
        approved=approved,
        settled=settled,
        when=when,
        signer=signer,
        testimony=testimony,
        testimony_note=testimony_note,
    )


# --------------------------------------------------------------------------- #
# The join to a session (plan D9, level 2)
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class SessionJoin:
    """A bundle to join this receipt to, and what the join found."""

    bundle: Mapping[str, Any]
    log: LogVerdict


def _row_at_leaf(rows: Sequence[Mapping[str, Any]], leaf_index: int) -> Mapping[str, Any] | None:
    """The action row that *is* this leaf, wherever the bundle chose to list it.

    A full export lists every action in leaf order, so this is the row at that
    position. A receipt bundle carries one row — the action that committed this
    envelope — and its position says nothing; its proof says which leaf it is
    (``docs/SPEC.md`` §9). Reading the position would join leaf 5 of a session
    to whatever happened to be listed first.
    """
    for position, row in enumerate(rows):
        if leaf_index_of(position, row) == leaf_index:
            return row
    return None


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
    # An open session has no root to prove into and no log entry to be included
    # in, so there is nothing yet for this receipt to be joined *to*. That is a
    # stage of the session's life, not a fault in the receipt: say which, and
    # say what will change it.
    if isinstance(session, Mapping) and session.get("sealed") is False:
        return no_data(
            CHECK_LOG_JOIN,
            f"session {locator.session_id} is not sealed yet; "
            "level 2 becomes available after sealing",
        )
    action = _row_at_leaf(rows, locator.leaf_index)
    if action is None:
        return Check(
            CHECK_LOG_JOIN,
            CheckStatus.FAIL,
            f"the receipt names leaf {locator.leaf_index}, the bundle carries "
            f"{len(rows)} action(s) and none of them is that leaf",
        )
    committed = str(action.get("input_hash", ""))
    derived = canonical_hash(envelope.to_content()).hex()
    if derived != committed:
        return Check(
            CHECK_LOG_JOIN,
            CheckStatus.FAIL,
            f"the envelope hashes to {derived}, action {locator.leaf_index} committed {committed}",
        )
    action_ok = any(r.index == locator.leaf_index and r.ok for r in join.log.actions)
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
                # Covers both signature shapes (legacy Ed25519 over the pre-image,
                # or an ApprovalAssertion — Ed25519 or WebAuthn — over
                # policy_hash): one verification path for either kind of admin.
                if not verify_policy_signature(signed, admin_public_key=admin_public_key):
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
class UncheckedCheck:
    """One check that did not run, in words, with the reason it gives itself."""

    name: str
    label: str
    reason: str

    def to_content(self) -> JSONObject:
        return {"name": self.name, "label": self.label, "reason": self.reason}


def _unchecked(checks: Sequence[Check]) -> tuple[UncheckedCheck, ...]:
    """Name every check that did not run, each with its *own* reason.

    The reason is the check's detail, verbatim. A summary that said "some checks
    are not implemented or unconfigured" would be true of every one of them and
    useful about none: a reader cannot tell whether nobody pinned an enclave
    measurement or nobody supplied a settlement proof, and those are different
    facts about how far this receipt has been established.
    """
    return tuple(
        UncheckedCheck(name=c.name, label=CHECK_LABELS.get(c.name, c.name), reason=c.detail)
        for c in checks
        if c.status is CheckStatus.NOT_IMPLEMENTED
    )


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

    @property
    def not_checked(self) -> tuple[UncheckedCheck, ...]:
        """Every check that did not run — the receipt's own, then the log's."""
        entries = list(_unchecked(self.result.checks))
        if self.log is not None:
            entries.extend(_unchecked(self.log.result.checks))
        return tuple(entries)

    @property
    def not_checked_line(self) -> str:
        """The completeness half of the verdict, as one sentence naming names."""
        entries = self.not_checked
        if not entries:
            return "Every check ran."
        return "Not checked: " + ", ".join(f"{e.label} ({e.reason})" for e in entries) + "."

    @property
    def verdict_line(self) -> str:
        """The whole verdict in two sentences: contradiction, then completeness.

        Never one boolean and never one sentence — "nothing was contradicted" and
        "everything was checked" are different claims, and a page that ran them
        together would be reporting the weaker one as if it were the stronger.
        """
        head = "Nothing was contradicted." if self.ok else "Something was contradicted."
        return f"{head} {self.not_checked_line}"

    def to_content(self) -> JSONObject:
        content: JSONObject = {
            "receipt_id": self.receipt_id,
            "ok": self.ok,
            "complete": self.complete,
            "level": self.level,
            "level_detail": self.level_detail,
            "not_checked": [e.to_content() for e in self.not_checked],
            "not_checked_line": self.not_checked_line,
            "verdict_line": self.verdict_line,
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
    _insert_before(checks, CHECK_POLICY_SIGNATURE, (document_check, challenge_check, quorum_check))

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
    level_detail = LEVEL_DETAIL_SESSION if level == LEVEL_SESSION else LEVEL_DETAIL_RECEIPT

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
