"""The receipt as a document — one model every surface renders.

A receipt is not a checklist. A person reading one asks five questions (how
much, to whom, from where, by whom, when), then how it was authorized, then
how far this copy has been checked. The hashes, the Merkle paths and the
seven leaves stay; they live under a fold, because they are how the document
proves itself, not how it is read.

This module is pure. It takes a :class:`~merkl.core.verify.receipt.ReceiptVerdict`
plus the seven leaf contents (and optional address labels) and produces a
:class:`ReceiptCard` whose JSON is the contract ``receiptCard()`` in
``@merkl-ai/verify`` must match byte for byte.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Mapping, Sequence
from typing import Any, Final, cast

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.checks import CheckStatus
from merkl.core.receipt import CHECK_LOG_JOIN, CHECK_POLICY_SIGNATURE, LEAF_NAMES, Envelope
from merkl.core.verify.receipt import CHECK_LABELS, ReceiptVerdict

__all__ = [
    "STATUS_AWAITING",
    "STATUS_EXPIRED",
    "STATUS_FAILED",
    "STATUS_REFUSED",
    "STATUS_REJECTED",
    "STATUS_SETTLED",
    "CardLine",
    "ReceiptCard",
    "StampCheck",
    "receipt_card",
    "render_card",
]

STATUS_SETTLED: Final = "SETTLED"
STATUS_REFUSED: Final = "REFUSED"
STATUS_AWAITING: Final = "AWAITING APPROVAL"
STATUS_REJECTED: Final = "REJECTED"
STATUS_EXPIRED: Final = "EXPIRED"
STATUS_FAILED: Final = "FAILED"

_SOURCE_WORDS: Final[dict[str, str]] = {
    "human_input": "a person typed it",
    "mandate": "a standing mandate authorized it",
    "system": "a system triggered it",
}

_RULE_NAMES: Final[dict[str, str]] = {
    "destination_allowlist": "destination not on allowlist",
    "asset_allowlist": "asset not on allowlist",
    "may_swap": "the agent may not trade",
    "per_tx_cap": "over the per-transaction cap",
    "sliding_window": "over the sliding-window cap",
    "reference_binding": "reference mismatch",
    "intent_expiry": "the intent had expired",
    "agent_known": "unknown agent",
    "treasury": "wrong treasury",
    "policy_version": "wrong policy version",
    "risk": "destination risk",
    "payload_encodes_intent": "the bytes did not match the intent",
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
    amount = _member(intent, "amount")
    value = _member(amount, "value") or "?"
    return f"{value} {_currency_word(_member(amount, 'currency'))}"


def _swap_lines(intent: JSONValue, result: JSONValue, *, settled: bool) -> list[CardLine]:
    """The lines a trade puts on a card, before the who and the when.

    Settled, a trade is read as three facts: what arrived, what it cost against
    the limit that was authorized, and the price those two imply. Refused, there
    is only what was asked — a limit and a target, with no price, because nothing
    was quoted and nothing was filled.
    """
    sell, buy = _member(intent, "sell"), _member(intent, "buy")
    sell_code = _currency_word(_member(sell, "currency"))
    buy_code = _currency_word(_member(buy, "currency"))
    ceiling = str(_member(sell, "max_amount") or "?")
    bought = str(_member(buy, "amount") or "?")
    if not settled:
        return [CardLine("Asked", f"to buy {bought} {buy_code} for up to {ceiling} {sell_code}")]

    spent = _member(result, "spent")
    spent_value = str(spent.get("value") or "") if isinstance(spent, Mapping) else ""
    lines = [
        CardLine("Bought", f"{bought} {buy_code}"),
        CardLine(
            "Sold",
            f"{spent_value} {sell_code} (limit {ceiling} {sell_code})"
            if spent_value
            else f"not stated (limit {ceiling} {sell_code})",
        ),
    ]
    rate = rate_string(spent_value, bought) if spent_value else None
    if rate is not None:
        lines.append(CardLine("Rate", f"{rate} {sell_code}/{buy_code}"))
    return lines


RATE_DIGITS: Final = 6
"""Significant digits a rendered rate carries. Six, in both implementations."""


def _split_decimal(value: str) -> tuple[int, int]:
    """A canonical decimal string as ``(mantissa, scale)``: ``"2.50" -> (250, 2)``."""
    whole, _, fraction = value.partition(".")
    return int(whole + fraction or "0"), len(fraction)


def _round_half_even(numerator: int, denominator: int) -> int:
    """``numerator / denominator`` to the nearest integer, ties to even. Integers only."""
    quotient, remainder = divmod(numerator, denominator)
    twice = remainder * 2
    if twice > denominator or (twice == denominator and quotient % 2):
        return quotient + 1
    return quotient


def rate_string(spent: str, bought: str) -> str | None:
    """``spent / bought`` as a decimal string of at most six significant digits.

    Integer arithmetic end to end — the two decimal strings become a fraction and
    the fraction is rounded once, half to even — so ``@merkl-ai/verify`` computes
    the same digits from the same two strings without a decimal library and
    without ever touching a float. Trailing fractional zeros are stripped and the
    result is never in scientific notation, because this number is read by a
    person on a receipt.

    ``None`` when either side is zero: a rate with no denominator is not a rate,
    and a card says nothing rather than something shaped like a number.
    """
    numerator, spent_scale = _split_decimal(spent)
    denominator, bought_scale = _split_decimal(bought)
    if numerator <= 0 or denominator <= 0:
        return None
    numerator *= 10**bought_scale
    denominator *= 10**spent_scale

    exponent = len(str(numerator)) - len(str(denominator))
    shift = RATE_DIGITS - exponent
    for _ in range(3):
        if shift >= 0:
            digits = _round_half_even(numerator * 10**shift, denominator)
        else:
            digits = _round_half_even(numerator, denominator * 10**-shift)
        length = len(str(digits))
        if length == RATE_DIGITS:
            break
        shift += RATE_DIGITS - length
    else:  # pragma: no cover - two corrections are always enough
        return None

    text = str(digits)
    if shift <= 0:
        return text + "0" * -shift
    if shift >= len(text):
        text = "0" * (shift - len(text) + 1) + text
    whole, fraction = text[: len(text) - shift], text[len(text) - shift :]
    fraction = fraction.rstrip("0")
    return f"{whole}.{fraction}" if fraction else whole


def _shorten(value: str, *, keep: int = 6) -> str:
    if len(value) <= keep * 2 + 1:
        return value
    return f"{value[:keep]}…{value[-keep:]}"


def _labelled(address: str, labels: Mapping[str, str]) -> str:
    name = labels.get(address)
    short = _shorten(address)
    return f"{name} · {short}" if name else short


def _when(settlement: JSONValue) -> str | None:
    close = _member(settlement, "close_time")
    if not isinstance(close, str) or not close:
        return None
    parsed: datetime.datetime | None = None
    try:
        parsed = datetime.datetime.fromisoformat(close.replace("Z", "+00:00"))
    except ValueError:
        return close
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    utc = parsed.astimezone(datetime.UTC)
    months = (
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    )
    stamp = f"{utc.day} {months[utc.month - 1]} {utc.year}, {utc.hour:02d}:{utc.minute:02d} UTC"
    ledger = _member(settlement, "ledger_index")
    rail = _member(settlement, "rail")
    parts = [stamp]
    if isinstance(rail, str) and rail:
        parts.append(f"{rail.upper()} ledger {ledger}" if ledger is not None else rail.upper())
    elif ledger is not None:
        parts.append(f"ledger {ledger}")
    return " · ".join(parts)


def _status(result: JSONValue, decision: JSONValue) -> str:
    outcome = str(_member(result, "outcome") or "")
    detail = str(_member(result, "detail") or "").lower()
    decision_outcome = str(_member(decision, "outcome") or "")
    if outcome == "settled":
        return STATUS_SETTLED
    if outcome == "failed":
        return STATUS_FAILED
    if outcome == "expired":
        return STATUS_EXPIRED
    if "rejected by" in detail:
        return STATUS_REJECTED
    if outcome == "denied" or decision_outcome == "deny":
        return STATUS_REFUSED
    if decision_outcome == "escalate":
        return STATUS_AWAITING
    if decision_outcome == "allow":
        return STATUS_SETTLED
    return STATUS_FAILED if outcome else STATUS_REFUSED


def _status_mark(status: str) -> str:
    if status == STATUS_SETTLED:
        return "✓"
    if status in (STATUS_REFUSED, STATUS_REJECTED, STATUS_FAILED, STATUS_EXPIRED):
        return "✗"
    return "…"


def _blocked_rule(decision: JSONValue) -> str | None:
    rules = _member(decision, "rules")
    if not isinstance(rules, list):
        return None
    # A skipped rule did not apply, so it did not block anything. Naming one here
    # would tell a reader a trade was refused by the destination allowlist, which
    # a trade does not have.
    blocked = [
        str(r.get("name") or "")
        for r in rules
        if isinstance(r, Mapping) and r.get("outcome") in ("fail", "escalate")
    ]
    if not blocked:
        return None
    name = blocked[0]
    return _RULE_NAMES.get(name, name.replace("_", " "))


def _because(instruction: JSONValue) -> str:
    source = str(_member(instruction, "source") or "")
    words = _SOURCE_WORDS.get(source, source or "the receipt does not say where this came from")
    return words


def _allowed_by(
    status: str,
    decision: JSONValue,
    policy_version: str | None,
    envelope: Envelope,
) -> str:
    version = policy_version or envelope.policy_hash[:8]
    if status in (STATUS_REFUSED, STATUS_REJECTED):
        reason = _blocked_rule(decision)
        if status == STATUS_REJECTED:
            return "Refused by a person" + (f": {reason}" if reason else "")
        return f"Refused by rule: {reason}" if reason else "Refused by policy"
    if status == STATUS_AWAITING:
        return f"policy {version} · awaiting a person"
    if status == STATUS_EXPIRED:
        return f"policy {version} · approval window closed"
    if status == STATUS_FAILED:
        return f"policy {version} · settlement failed"
    tier = str(_member(decision, "tier") or "instant")
    return f"policy {version} · {tier} tier · {rules_passed_phrase(_member(decision, 'rules'))}"


def rules_passed_phrase(rules: JSONValue) -> str:
    """ "All 10 rules passed · 1 did not apply": a skipped rule is neither passed nor failed."""
    if not isinstance(rules, list):
        return "no rules ran"
    outcomes = [r.get("outcome") for r in rules if isinstance(r, Mapping)]
    skipped = sum(1 for o in outcomes if o == "skip")
    applicable = len(outcomes) - skipped
    passed = sum(1 for o in outcomes if o in ("pass", None))
    if applicable == 0:
        phrase = "no rules applied"
    elif passed == applicable:
        phrase = f"all {applicable} rules passed"
    else:
        phrase = f"{passed} of {applicable} rules passed"
    return f"{phrase} · {skipped} did not apply" if skipped else phrase


def _approved_by(status: str, decision: JSONValue, approved_ids: Sequence[str]) -> str:
    escalation = _member(decision, "escalation")
    if status == STATUS_REJECTED:
        return "a named approver refused, signed"
    if not isinstance(escalation, Mapping):
        return "no one needed"
    quorum = escalation.get("quorum")
    if approved_ids:
        who = ", ".join(approved_ids)
        return f"{who} ({len(approved_ids)} of {quorum})"
    return (
        f"awaiting {quorum} of {quorum}" if status == STATUS_AWAITING else "no approval verified"
    )


def _signed_by(verdict: ReceiptVerdict, envelope: Envelope) -> str:
    key = _shorten(envelope.signer_public_key)
    if verdict.attested is True:
        return f"policy key {key} · attested enclave"
    if verdict.attested is False:
        return f"policy key {key} · unattested dev signer"
    return f"policy key {key} · attestation unchecked"


def _stamp_checks(verdict: ReceiptVerdict) -> tuple[StampCheck, ...]:
    signature = verdict.result.get(CHECK_POLICY_SIGNATURE)
    signature_ok = signature is not None and signature.status is CheckStatus.PASS
    ledger_ok = verdict.ledger_inclusion in ("proven-offline", "verified-live")
    join = verdict.result.get(CHECK_LOG_JOIN)
    log_ok = join is not None and join.status is CheckStatus.PASS
    return (
        StampCheck(name="signature", ok=signature_ok),
        StampCheck(name="ledger", ok=ledger_ok),
        StampCheck(name="notary log", ok=log_ok),
    )


@dataclasses.dataclass(frozen=True)
class CardLine:
    """One labelled row on the card."""

    label: str
    value: str

    def to_content(self) -> JSONObject:
        return {"label": self.label, "value": self.value}


@dataclasses.dataclass(frozen=True)
class StampCheck:
    """One tick on the verification stamp."""

    name: str
    ok: bool

    def to_content(self) -> JSONObject:
        return {"name": self.name, "ok": self.ok}


@dataclasses.dataclass(frozen=True)
class ReceiptCard:
    """The document a person reads. Complexity lives in ``folds``."""

    status: str
    status_mark: str
    headline: str
    body: tuple[CardLine, ...]
    provenance: tuple[CardLine, ...]
    stamp_checks: tuple[StampCheck, ...]
    level: int
    not_checked: tuple[JSONObject, ...]
    folds: JSONObject

    def to_content(self) -> JSONObject:
        return {
            "status": self.status,
            "status_mark": self.status_mark,
            "headline": self.headline,
            "body": [line.to_content() for line in self.body],
            "provenance": [line.to_content() for line in self.provenance],
            "stamp": {
                "label": "VERIFIED",
                "checks": [c.to_content() for c in self.stamp_checks],
                "level": self.level,
                "not_checked": list(self.not_checked),
            },
            "folds": self.folds,
        }


def receipt_card(
    verdict: ReceiptVerdict,
    envelope: Envelope,
    contents: Sequence[JSONValue],
    *,
    labels: Mapping[str, str] | None = None,
    policy_version: str | None = None,
) -> ReceiptCard:
    """Build the card from a verdict and the leaves it was computed over."""
    names = labels or {}
    instruction = _content(contents, 0)
    intent = _content(contents, 1)
    decision = _content(contents, 2)
    settlement = _content(contents, 4)
    result = _content(contents, 5)
    status = _status(result, decision)
    settled = status == STATUS_SETTLED and isinstance(settlement, Mapping)

    amount = _amount_words(intent)
    destination = str(_member(intent, "destination") or "")
    treasury = envelope.treasury
    agent = envelope.agent_id
    when = _when(settlement)
    tx = str(_member(settlement, "tx_hash") or "")

    swap = _member(intent, "type") == "swap"
    body: list[CardLine] = []
    if swap:
        # A trade's destination is the treasury, so "To" would repeat "From".
        body.extend(_swap_lines(intent, result, settled=settled))
    elif settled:
        body.append(CardLine("Paid", amount))
        if destination:
            body.append(CardLine("To", _labelled(destination, names)))
    else:
        body.append(CardLine("Asked", amount))
        if destination:
            body.append(CardLine("To", _labelled(destination, names)))
    body.append(CardLine("From", _labelled(treasury, names) if treasury else "?"))
    body.append(CardLine("By", agent))
    if when:
        body.append(CardLine("On", when))
    if settled and tx:
        body.append(CardLine("Ref", f"tx {_shorten(tx, keep=8)}"))

    approved_ids: list[str] = []
    quorum_check = verdict.result.get("policy.approval_quorum")
    if quorum_check is not None and quorum_check.status is CheckStatus.PASS:
        # The check's detail names "N of M"; the ids live on the leaf.
        escalation = _member(decision, "escalation")
        approvals = _member(escalation, "approvals") if isinstance(escalation, dict) else None
        if isinstance(approvals, list):
            for item in approvals:
                if isinstance(item, Mapping) and item.get("approver_id"):
                    approved_ids.append(str(item["approver_id"]))

    provenance = (
        CardLine("Because", _because(instruction)),
        CardLine("Allowed by", _allowed_by(status, decision, policy_version, envelope)),
        CardLine("Approved by", _approved_by(status, decision, approved_ids)),
        CardLine("Signed by", _signed_by(verdict, envelope)),
    )

    leaf_fold: list[JSONObject] = []
    for i, name in enumerate(LEAF_NAMES):
        content = _content(contents, i)
        check = verdict.result.get(f"leaf.{name}")
        leaf_fold.append(
            {
                "index": i,
                "name": name,
                "present": content is not None,
                "status": check.status.value if check is not None else "not_implemented",
                "detail": check.detail if check is not None else "",
                "plain": CHECK_LABELS.get(f"leaf.{name}", name),
            }
        )

    folds = cast(
        JSONObject,
        {
            "details": {
                "leaves": leaf_fold,
                "checks": [
                    {"name": c.name, "status": c.status.value} for c in verdict.result.checks
                ],
                "authorization": {
                    "state": verdict.transaction_authorization,
                    "detail": verdict.transaction_authorization_detail,
                },
                "ledger": {
                    "state": verdict.ledger_inclusion,
                    "detail": verdict.ledger_inclusion_detail,
                },
            },
            "reasoning": {
                "testimony": verdict.summary.testimony,
                "note": verdict.summary.testimony_note,
            },
            "verify": {
                "offline": "download the offline page",
                "cli": "merkl verify",
            },
        },
    )

    return ReceiptCard(
        status=status,
        status_mark=_status_mark(status),
        headline="MERKL RECEIPT",
        body=tuple(body),
        provenance=provenance,
        stamp_checks=_stamp_checks(verdict),
        level=verdict.level,
        not_checked=tuple(e.to_content() for e in verdict.not_checked),
        folds=folds,
    )


def render_card(card: ReceiptCard) -> str:
    """The ASCII form: status first, then the five lines, provenance, stamp."""
    width = 56
    rule = "─" * width
    head = f"{card.headline:<{width - 14}}{card.status_mark} {card.status}"
    lines = [head, rule]
    label_width = 12
    for row in (*card.body, None, *card.provenance):
        if row is None:
            lines.append(rule)
            continue
        lines.append(f"{row.label:<{label_width}}{row.value}")
    lines.append(rule)
    ticks = "  ".join(f"{c.name} {'✓' if c.ok else '–'}" for c in card.stamp_checks)
    lines.append(f"{'VERIFIED':<{label_width}}{ticks}        Level {card.level}")
    if card.not_checked:
        reasons = ", ".join(
            f"{e.get('label', e.get('name'))} ({e.get('reason')})" for e in card.not_checked
        )
        lines.append(f"{'':<{label_width}}not checked: {reasons}")
    lines.append(rule)
    lines.append("▸ Details      seven leaves, hashes, Merkle paths, proofs")
    lines.append("▸ Reasoning    the model's account (testimony)")
    lines.append("▸ Verify       download the offline page · merkl verify")
    return "\n".join(lines)
