"""The log verifier against bundles merkl-api actually exported.

These fixtures are the contract with the JavaScript verifier: the same files,
the same case names, the same check statuses. ``tests/js`` runs the other
implementation over the same ``cases.json``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from merkl.core.checks import CheckStatus
from merkl.core.vectors.bundles import BUNDLES_DIR
from merkl.core.vectors.bundles.generate import build as build_cases
from merkl.core.verify.log import (
    CHECK_EVIDENCE,
    audit_entry_hash,
    binding_leaf_hash,
    checkpoint_body_matches,
    evidence_records,
    leaf_hash_of,
    rfc6962_leaf,
    verify_evidence,
    verify_log_bundle,
    verify_log_inclusion,
)
from merkl.shared.hashing import canonical_hash

CASES: list[dict[str, Any]] = json.loads((BUNDLES_DIR / "cases.json").read_text())["cases"]


def _bundle(case: dict[str, Any]) -> dict[str, Any]:
    if case["tamper"] is not None:
        return dict(case["bundle"])
    return json.loads((BUNDLES_DIR / case["file"]).read_text())


class TestTheCommittedCases:
    @pytest.mark.parametrize("case", CASES, ids=lambda c: str(c["name"]))
    def test_every_check_reports_the_status_the_fixture_records(
        self, case: dict[str, Any]
    ) -> None:
        verdict = verify_log_bundle(_bundle(case))
        assert {c.name: c.status.value for c in verdict.result.checks} == case["checks"]
        assert verdict.ok is case["ok"]
        assert verdict.complete is case["complete"]

    def test_the_committed_cases_file_is_current(self) -> None:
        committed = json.loads((BUNDLES_DIR / "cases.json").read_text())
        assert build_cases() == committed


class TestRealBundlesVerify:
    def test_a_sealed_session_verifies_end_to_end(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        verdict = verify_log_bundle(bundle)
        assert verdict.ok
        assert all(a.ok for a in verdict.actions)

    def test_a_v1_2_bundle_verifies_exactly_as_a_v1_1_one_does(self) -> None:
        """Additive means the log checks do not notice the receipts block."""
        v11 = verify_log_bundle(json.loads((BUNDLES_DIR / "session-v1.1.json").read_text()))
        v12 = verify_log_bundle(json.loads((BUNDLES_DIR / "receipts-v1.2.json").read_text()))
        assert [c.name for c in v11.result.checks] == [c.name for c in v12.result.checks]

    def test_a_bundle_with_no_log_reports_the_gap_by_name(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        bundle.pop("transparency")
        bundle.pop("audit_log")
        verdict = verify_log_bundle(bundle)
        deferred = {c.name for c in verdict.result.deferred}
        assert {"log.audit_entry", "log.inclusion", "log.checkpoint_body"} <= deferred
        assert verdict.ok and not verdict.complete


class TestTheEncodings:
    def test_the_drift_score_string_wins_over_the_parsed_number(self) -> None:
        """JSON turns "0.0" into 0.0 and back into "0"; the leaf notices."""
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        action = dict(bundle["actions"][0])
        with_string = leaf_hash_of(action)
        action.pop("drift_score_str")
        action["drift_score"] = 0
        assert leaf_hash_of(action) != with_string

    def test_the_binding_leaf_is_tagged(self) -> None:
        assert binding_leaf_hash("s", "00" * 32, "force_seal") != binding_leaf_hash(
            "s", "00" * 32, "idle_timeout"
        )

    def test_the_audit_entry_hash_matches_the_bundle(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        assert audit_entry_hash(bundle["audit_log"]) == bundle["audit_log"]["current_hash"]

    def test_the_rfc6962_leaf_is_prefixed_with_zero(self) -> None:
        assert rfc6962_leaf("ab" * 32).hex() != ("ab" * 32)

    def test_a_checkpoint_whose_body_claims_another_root_is_caught(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        checkpoint = dict(bundle["transparency"]["checkpoint"])
        assert checkpoint_body_matches(checkpoint)[0]
        checkpoint["root_hash"] = "00" * 32
        assert not checkpoint_body_matches(checkpoint)[0]

    def test_an_inclusion_proof_for_the_wrong_sequence_fails(self) -> None:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        inclusion = dict(bundle["transparency"]["log_inclusion"])
        inclusion["sequence"] = int(inclusion["tree_size"]) + 5
        assert not verify_log_inclusion(inclusion)[0]


class TestEvidence:
    def _records(self) -> tuple[dict[str, Any], list[Any]]:
        bundle = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
        return bundle, bundle["actions"]

    def test_a_record_that_rehashes_to_the_leaf_is_the_document(self) -> None:
        raw_input = {"query": "SELECT 1", "unicode": "café ☕"}
        raw_output = ["ok", 42]
        action = {
            "action_id": "01a07441-0000-7000-8000-000000000001",
            "tool_name": "query_db",
            "input_hash": canonical_hash(raw_input).hex(),
            "output_hash": canonical_hash(raw_output).hex(),
        }
        readings = verify_evidence(
            [{"action_id": action["action_id"], "input": raw_input, "output": raw_output}],
            [action],
        )
        assert readings[0].verdict == "ok"

    def test_one_edited_byte_makes_the_record_stop_being_the_document(self) -> None:
        raw_input = {"query": "SELECT 1"}
        action = {
            "action_id": "a",
            "tool_name": "query_db",
            "input_hash": canonical_hash(raw_input).hex(),
            "output_hash": canonical_hash(None).hex(),
        }
        readings = verify_evidence(
            [{"action_id": "a", "input": {"query": "SELECT 2"}, "output": None}], [action]
        )
        assert readings[0].verdict == "bad"
        assert "INPUT hash mismatch" in readings[0].detail

    def test_a_record_for_another_bundle_is_unknown_not_failed(self) -> None:
        _, actions = self._records()
        readings = verify_evidence([{"action_id": "not-in-this-bundle"}], actions)
        assert readings[0].verdict == "unknown"

    def test_an_unparseable_line_is_reported_not_skipped(self) -> None:
        _, actions = self._records()
        readings = verify_evidence(evidence_records("{not json}\n"), actions)
        assert readings[0].verdict == "bad"

    def test_evidence_adds_its_own_check_to_the_verdict(self) -> None:
        bundle, actions = self._records()
        verdict = verify_log_bundle(
            bundle, evidence=[{"action_id": actions[0]["action_id"], "input": 1, "output": 2}]
        )
        check = verdict.result.get(CHECK_EVIDENCE)
        assert check is not None and check.status is CheckStatus.FAIL
