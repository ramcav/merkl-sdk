"""ReceiptCard: the document a person reads, from the same verdict both languages share."""

from __future__ import annotations

import json

from merkl.core.vectors import VECTORS_DIR
from merkl.core.verify.card import STATUS_REFUSED, STATUS_SETTLED, receipt_card, render_card
from merkl.core.verify.receipt import receipt_from_content, verify_receipt
from merkl.core.verify.settlement import ValidatorTrust

CARDS = json.loads((VECTORS_DIR / "cards.json").read_text())
RECEIPTS = json.loads((VECTORS_DIR / "receipts.json").read_text())
VERDICTS = json.loads((VECTORS_DIR / "verdicts.json").read_text())
BY_NAME = {c["name"]: c for c in RECEIPTS["cases"]}
VERDICT_BY_NAME = {c["name"]: c for c in VERDICTS["cases"]}


def _run(name: str):
    case = VERDICT_BY_NAME[name]
    receipt = BY_NAME[case.get("receipt", name)]
    envelope, leaves = receipt_from_content(receipt)
    material = case["material"]
    trust = material["validator_trust"]
    verdict = verify_receipt(
        envelope,
        leaves,
        settlement_proof=material["settlement_proof"],
        validator_trust=(
            ValidatorTrust(validators=trust["validators"], quorum=trust["quorum"])
            if trust
            else None
        ),
        policy_document=material["policy_document"],
        admin_public_key=material["admin_public_key"],
        session_bundle=material.get("session_bundle"),
    )
    return receipt_card(verdict, envelope, leaves), verdict, envelope


def test_every_card_matches_the_fixture() -> None:
    for case in CARDS["cases"]:
        card, _, _ = _run(case["name"])
        assert card.to_content() == case["card"]


def test_a_settled_receipt_says_paid_not_asked() -> None:
    card, _, _ = _run("allow-settled")
    assert card.status == STATUS_SETTLED
    assert card.body[0].label == "Paid"
    ascii_form = render_card(card)
    assert "MERKL RECEIPT" in ascii_form
    assert "SETTLED" in ascii_form


def test_a_denied_receipt_says_asked_and_refused() -> None:
    card, _, _ = _run("deny-not-submitted")
    assert card.status == STATUS_REFUSED
    assert card.body[0].label == "Asked"
    assert card.provenance[1].value.startswith("Refused by rule:")


def test_rules_passed_phrase_reads_plainly() -> None:
    from merkl.core.verify.card import rules_passed_phrase

    assert rules_passed_phrase([{"outcome": "pass"}] * 3) == "all 3 rules passed"
    assert (
        rules_passed_phrase([{"outcome": "pass"}] * 10 + [{"outcome": "skip"}])
        == "all 10 rules passed · 1 did not apply"
    )
    assert rules_passed_phrase([{"outcome": "pass"}, {"outcome": "fail"}]) == "1 of 2 rules passed"
    assert rules_passed_phrase(None) == "no rules ran"
