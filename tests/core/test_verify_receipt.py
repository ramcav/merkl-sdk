"""The whole verdict: every check, both settlement lines, the level, the words."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from merkl.core.checks import CheckStatus
from merkl.core.vectors import VECTORS_DIR
from merkl.core.vectors.bundles import BUNDLES_DIR
from merkl.core.verify.receipt import (
    AUTHORIZATION_ABSENT,
    AUTHORIZATION_CONTRADICTED,
    AUTHORIZATION_VERIFIED,
    LEVEL_RECEIPT,
    LEVEL_SESSION,
    receipt_from_content,
    verify_receipt,
)
from merkl.core.verify.settlement import (
    LEDGER_PROVEN_OFFLINE,
    LEDGER_SUPPLIED_UNVERIFIED,
    LEDGER_UNCHECKED,
    ValidatorTrust,
)

VERDICTS: dict[str, Any] = json.loads((VECTORS_DIR / "verdicts.json").read_text())
RECEIPTS: dict[str, Any] = json.loads((VECTORS_DIR / "receipts.json").read_text())
BY_NAME = {c["name"]: c for c in RECEIPTS["cases"]}


def _case(name: str) -> dict[str, Any]:
    return next(c for c in VERDICTS["cases"] if c["name"] == name)


def _run(case: dict[str, Any], **overrides: Any) -> Any:
    material = {**case["material"], **overrides}
    receipt = BY_NAME[case["name"]]
    envelope, leaves = receipt_from_content(receipt)
    trust = material["validator_trust"]
    return verify_receipt(
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


class TestTheCommittedVerdicts:
    @pytest.mark.parametrize("case", VERDICTS["cases"], ids=lambda c: str(c["name"]))
    def test_the_verdict_matches_the_fixture_byte_for_byte(self, case: dict[str, Any]) -> None:
        assert _run(case).to_content() == case["verdict"]


class TestTheTwoSettlementLines:
    def test_a_settled_receipt_says_who_authorized_it(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert verdict.transaction_authorization == AUTHORIZATION_VERIFIED

    def test_a_denial_authorizes_nothing_and_says_absent_not_failed(self) -> None:
        verdict = _run(_case("deny-not-submitted"))
        assert verdict.transaction_authorization == AUTHORIZATION_ABSENT
        assert verdict.ledger_inclusion == LEDGER_UNCHECKED
        assert verdict.ok

    def test_an_xrpl_capture_stops_at_supplied_unverified(self) -> None:
        """The header hashes and validators agree; the last hop is still missing."""
        verdict = _run(_case("allow-settled"))
        assert verdict.ledger_inclusion == LEDGER_SUPPLIED_UNVERIFIED
        assert "shamap_path" in verdict.ledger_inclusion_detail

    def test_a_complete_capture_reaches_proven_offline(self) -> None:
        verdict = _run(_case("allow-settled-fake-rail"))
        assert verdict.ledger_inclusion == LEDGER_PROVEN_OFFLINE
        assert verdict.result.get("settlement.ledger_inclusion").status is CheckStatus.PASS

    def test_a_signature_over_another_payload_is_contradicted_not_absent(self) -> None:
        case = _case("allow-settled")
        receipt = copy.deepcopy(BY_NAME["allow-settled"])
        receipt["leaves"][4]["policy_signature"]["signature"] = "00" * 64
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(
            envelope, leaves, settlement_proof=case["material"]["settlement_proof"]
        )
        assert verdict.transaction_authorization == AUTHORIZATION_CONTRADICTED
        assert not verdict.ok

    def test_a_proof_for_another_transaction_is_the_wrong_evidence(self) -> None:
        case = _case("allow-settled")
        proof = copy.deepcopy(case["material"]["settlement_proof"])
        proof["tx_hash"] = "FF" * 32
        verdict = _run(case, settlement_proof=proof)
        assert verdict.result.get("settlement.proof_matches_receipt").status is CheckStatus.FAIL
        assert not verdict.ok


class TestTheApprovals:
    def test_the_challenge_is_left_pre_over_these_leaves(self) -> None:
        verdict = _run(_case("escalated-approved-settled"))
        assert verdict.result.get("policy.escalation_challenge").status is CheckStatus.PASS
        assert verdict.result.get("policy.approval_quorum").status is CheckStatus.PASS
        assert "alice@example.com" in (verdict.summary.approved or "")

    def test_a_challenge_that_is_not_left_pre_invalidates_the_approvals(self) -> None:
        case = _case("escalated-approved-settled")
        receipt = copy.deepcopy(BY_NAME["escalated-approved-settled"])
        receipt["leaves"][2]["escalation"]["challenge"] = "ab" * 32
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(
            envelope, leaves, policy_document=case["material"]["policy_document"]
        )
        assert verdict.result.get("policy.escalation_challenge").status is CheckStatus.FAIL
        quorum = verdict.result.get("policy.approval_quorum")
        assert quorum.status is CheckStatus.FAIL
        assert "another payment" in quorum.detail

    def test_without_a_policy_nobody_knows_whose_signature_counts(self) -> None:
        receipt = BY_NAME["escalated-approved-settled"]
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves)
        assert verdict.result.get("policy.approval_quorum").status is CheckStatus.NOT_IMPLEMENTED

    def test_a_policy_that_hashes_elsewhere_is_not_this_receipts_policy(self) -> None:
        case = _case("allow-settled")
        document = copy.deepcopy(case["material"]["policy_document"])
        document["document"]["version"] = "2099.99.9"
        verdict = _run(case, policy_document=document)
        assert verdict.result.get("policy.document").status is CheckStatus.FAIL


class TestTheLevel:
    def test_a_receipt_alone_is_level_one_and_says_what_that_means(self) -> None:
        verdict = _run(_case("deny-not-submitted"))
        assert verdict.level == LEVEL_RECEIPT
        assert "level 1" in verdict.level_detail

    def test_joining_the_session_that_committed_it_reaches_level_two(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert verdict.level == LEVEL_SESSION
        assert verdict.result.get("session.log_join").status is CheckStatus.PASS
        assert verdict.log is not None and verdict.log.ok

    def test_a_join_to_a_bundle_that_commits_something_else_fails(self) -> None:
        case = _case("allow-settled")
        bundle = copy.deepcopy(case["material"]["session_bundle"])
        bundle["actions"][7]["input_hash"] = "ab" * 32
        verdict = _run(case, session_bundle=bundle)
        assert verdict.result.get("session.log_join").status is CheckStatus.FAIL
        assert verdict.level == LEVEL_RECEIPT

    def test_a_bundle_for_another_session_fails_the_join_loudly(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "receipts-v1.2.json").read_text())
        receipt = copy.deepcopy(bundle["receipts"][0])
        bundle["session"]["session_id"] = "01a07441-0000-7000-8000-00000000dead"
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves, session_bundle=bundle)
        assert verdict.result.get("session.log_join").status is CheckStatus.FAIL


class TestPlainLanguage:
    def test_an_unattested_signer_is_stated_not_omitted(self) -> None:
        verdict = _run(_case("allow-settled-fake-rail"))
        assert verdict.attested is False
        assert "unattested" in (verdict.summary.signer or "")

    def test_reasoning_is_labelled_testimony(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert "testimony, not proof" in (verdict.summary.testimony or "")

    def test_the_summary_says_what_settled_in_words(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert "250.00 RLUSD" in (verdict.summary.settled or "")
        assert "rSUPPLIER" in (verdict.summary.settled or "")

    def test_a_refusal_reads_as_a_refusal(self) -> None:
        verdict = _run(_case("deny-not-submitted"))
        assert "refused" in (verdict.summary.rule or "")
        assert "Nothing settled" in (verdict.summary.settled or "")
