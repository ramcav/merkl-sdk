"""The whole verdict: every check, both settlement lines, the level, the words."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from merkl.core.checks import CheckStatus
from merkl.core.receipt import PADDED_LEAF_COUNT, Envelope
from merkl.core.vectors import VECTORS_DIR
from merkl.core.vectors.bundles import BUNDLES_DIR
from merkl.core.verify.receipt import (
    AUTHORIZATION_ABSENT,
    AUTHORIZATION_CONTRADICTED,
    AUTHORIZATION_VERIFIED,
    LEVEL_DETAIL_RECEIPT,
    LEVEL_DETAIL_SESSION,
    LEVEL_RECEIPT,
    LEVEL_SESSION,
    _policy_document_check,
    receipt_from_content,
    verify_receipt,
)
from merkl.core.verify.settlement import (
    LEDGER_PROVEN_OFFLINE,
    LEDGER_SUPPLIED_UNVERIFIED,
    LEDGER_UNCHECKED,
    ValidatorTrust,
)
from merkl.shared.hashing import SHA256Hash

VERDICTS: dict[str, Any] = json.loads((VECTORS_DIR / "verdicts.json").read_text())
RECEIPTS: dict[str, Any] = json.loads((VECTORS_DIR / "receipts.json").read_text())
BY_NAME = {c["name"]: c for c in RECEIPTS["cases"]}


def _case(name: str) -> dict[str, Any]:
    return next(c for c in VERDICTS["cases"] if c["name"] == name)


def verdict_detail(verdict: Any, name: str) -> str:
    """The detail of a check by name, from the receipt's own checks or the log's."""
    check = verdict.result.get(name)
    if check is None and verdict.log is not None:
        check = verdict.log.result.get(name)
    return str(check.detail)


def _run(case: dict[str, Any], **overrides: Any) -> Any:
    material = {**case["material"], **overrides}
    # Two cases may read one receipt against different material — the receipt
    # page's scoped join is the same `allow-settled` leaves, joined differently.
    receipt = BY_NAME[case.get("receipt", case["name"])]
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
        assert verdict.level_detail == LEVEL_DETAIL_RECEIPT

    def test_the_level_line_is_one_sentence_that_names_its_own_level(self) -> None:
        """A page prefixing "Level 2." said it twice; the sentence carries it."""
        joined = _run(_case("allow-settled"))
        assert joined.level_detail == LEVEL_DETAIL_SESSION
        assert joined.level_detail.startswith("Level 2:")
        assert joined.level_detail.count("evel 2") == 1
        assert _run(_case("deny-not-submitted")).level_detail.count("evel 1") == 1

    def test_an_unsealed_session_says_so_rather_than_reading_as_a_bare_level_one(
        self,
    ) -> None:
        case = _case("allow-settled")
        bundle = copy.deepcopy(case["material"]["session_bundle"])
        bundle["session"]["sealed"] = False
        verdict = _run(case, session_bundle=bundle)
        join = verdict.result.get("session.log_join")
        assert join.status is CheckStatus.NOT_IMPLEMENTED
        assert "is not sealed yet; level 2 becomes available after sealing" in join.detail
        assert verdict.level == LEVEL_RECEIPT

    def test_a_scoped_bundle_carrying_only_this_receipts_action_still_joins(self) -> None:
        """The receipt page ships one action, not the whole session (SPEC §9).

        Its position in the list says nothing; its proof says which leaf it is.
        """
        case = _case("allow-settled")
        bundle = copy.deepcopy(case["material"]["session_bundle"])
        leaf_index = BY_NAME["allow-settled"]["envelope"]["session_locator"]["leaf_index"]
        assert leaf_index > 0, "a scoped bundle only proves anything past position 0"
        bundle["actions"] = [
            a for a in bundle["actions"] if a["proof"]["leaf_index"] == leaf_index
        ]
        verdict = _run(case, session_bundle=bundle)
        assert verdict.result.get("session.log_join").status is CheckStatus.PASS
        assert verdict.level == LEVEL_SESSION

    def test_a_scoped_bundle_whose_one_action_is_another_leaf_does_not_join(self) -> None:
        case = _case("allow-settled")
        bundle = copy.deepcopy(case["material"]["session_bundle"])
        leaf_index = BY_NAME["allow-settled"]["envelope"]["session_locator"]["leaf_index"]
        bundle["actions"] = [
            a for a in bundle["actions"] if a["proof"]["leaf_index"] != leaf_index
        ][:1]
        verdict = _run(case, session_bundle=bundle)
        join = verdict.result.get("session.log_join")
        assert join.status is CheckStatus.FAIL
        assert "none of them is that leaf" in join.detail
        assert verdict.level == LEVEL_RECEIPT

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

    def test_the_models_note_is_a_separate_member_not_run_into_the_sentence(self) -> None:
        """The sentence is ours; the note is the agent's. They never share a line."""
        verdict = _run(_case("allow-settled"))
        note = verdict.summary.testimony_note
        assert note and note == BY_NAME["allow-settled"]["leaves"][6]["note"]
        assert note not in (verdict.summary.testimony or "")

    def test_a_receipt_with_no_reasoning_leaf_has_no_note(self) -> None:
        receipt = copy.deepcopy(BY_NAME["allow-settled"])
        receipt["leaves"][6] = None
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves)
        assert verdict.summary.testimony is None
        assert verdict.summary.testimony_note is None

    def test_a_reasoning_leaf_with_an_empty_note_offers_no_preview(self) -> None:
        receipt = copy.deepcopy(BY_NAME["allow-settled"])
        receipt["leaves"][6]["note"] = "   "
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves)
        assert verdict.summary.testimony is not None
        assert verdict.summary.testimony_note is None

    def test_an_unattested_signer_says_a_dev_signer_is_the_ordinary_reason(self) -> None:
        verdict = _run(_case("allow-settled-fake-rail"))
        assert verdict.attested is False
        assert "a Nitro signer attests" in (verdict.summary.signer or "")

    def test_an_attested_signer_does_not_get_the_dev_signer_clause(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert "Nitro" not in (verdict.summary.signer or "")


class TestWhatWasNotChecked:
    def test_every_unchecked_check_is_named_with_its_own_reason(self) -> None:
        verdict = _run(_case("allow-settled"))
        deferred = {c.name for c in verdict.result.deferred} | {
            c.name for c in (verdict.log.result.deferred if verdict.log else ())
        }
        assert {e.name for e in verdict.not_checked} == deferred
        assert all(e.reason == verdict_detail(verdict, e.name) for e in verdict.not_checked)

    def test_the_line_names_the_check_in_words_and_the_reason_in_parentheses(self) -> None:
        receipt = BY_NAME["allow-settled"]
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves)
        assert "enclave attestation (" in verdict.not_checked_line
        assert "no settlement proof was supplied with this receipt)" in verdict.not_checked_line
        assert "ledger inclusion (" in verdict.not_checked_line
        assert verdict.not_checked_line.endswith(".")

    def test_the_verdict_line_separates_contradiction_from_completeness(self) -> None:
        receipt = BY_NAME["allow-settled"]
        envelope, leaves = receipt_from_content(receipt)
        verdict = verify_receipt(envelope, leaves)
        assert verdict.verdict_line.startswith("Nothing was contradicted. Not checked: ")
        assert "unconfigured" not in verdict.verdict_line

    def test_a_fully_checked_verdict_says_every_check_ran(self) -> None:
        verdict = _run(_case("allow-settled-fake-rail"))
        checked = verdict.complete
        assert checked == (verdict.not_checked == ())
        if checked:
            assert verdict.not_checked_line == "Every check ran."

    def test_nothing_that_did_not_run_is_left_out_of_the_list(self) -> None:
        """`complete` and the list are two readings of one fact, never two facts."""
        for case in VERDICTS["cases"]:
            verdict = _run(case)
            assert verdict.complete == (len(verdict.not_checked) == 0)

    def test_the_summary_says_what_settled_in_words(self) -> None:
        verdict = _run(_case("allow-settled"))
        assert "250.00 RLUSD" in (verdict.summary.settled or "")
        assert "rSUPPLIER" in (verdict.summary.settled or "")

    def test_a_refusal_reads_as_a_refusal(self) -> None:
        verdict = _run(_case("deny-not-submitted"))
        assert "refused" in (verdict.summary.rule or "")
        assert "Nothing settled" in (verdict.summary.settled or "")


POLICY_VECTORS: dict[str, Any] = json.loads((VECTORS_DIR / "policies.json").read_text())


@pytest.mark.parametrize(
    "case",
    [c for c in POLICY_VECTORS["document_cases"] if c["expected_findings"]],
    ids=lambda c: c["name"],
)
def test_a_signed_policy_with_a_dead_rule_is_a_finding(case: dict[str, Any]) -> None:
    """Parity with `@merkl-ai/verify`'s policyDocumentCheck: same detail, same nothing.

    Every one of these documents carries a valid admin signature over a hash that
    matches, so the only thing left to notice is that the rule cannot run. The
    check reports the sentence `merkl.core` would have refused the document with,
    and hands back no policy — a document this broken says nothing about who may
    approve either.
    """
    envelope = Envelope(
        receipt_id="rcp_0000000000000000000000000",
        root=SHA256Hash(bytes.fromhex("22" * 32)),
        left=SHA256Hash(bytes.fromhex("00" * 32)),
        leaf_hashes=tuple(SHA256Hash(bytes.fromhex("33" * 32)) for _ in range(PADDED_LEAF_COUNT)),
        rail="xrpl",
        treasury="rADMINVECTORTREASURY0000000000000000",
        agent_id="agent-admin-vector",
        policy_hash=case["policy_hash"],
        signer_public_key="ab" * 32,
    )
    check, policy = _policy_document_check(
        envelope, case["signed_policy"], case["signed_policy"]["signer_public_key"]
    )
    assert check.status is CheckStatus.FAIL
    assert check.detail == case["expected_findings"][0]
    assert policy is None
