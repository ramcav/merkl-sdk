"""``merkl verify``, ``merkl receipt show`` and ``merkl reconcile``."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from merkl.cli.approve import load_approver_key, sign_challenge
from merkl.cli.receipt import receipt_show_command, resolve_receipt
from merkl.cli.reconcile import reconcile, reconcile_command
from merkl.cli.verify import load_input, verify_command
from merkl.core.vectors import VECTORS_DIR
from merkl.core.vectors.bundles import BUNDLES_DIR
from merkl.core.verify.render import render_verify_html

RECEIPTS = json.loads((VECTORS_DIR / "receipts.json").read_text())["cases"]
BY_NAME = {c["name"]: c for c in RECEIPTS}


def _receipt_file(tmp_path: Path, name: str = "allow-settled") -> Path:
    case = BY_NAME[name]
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps({"envelope": case["envelope"], "leaves": case["leaves"]}))
    return path


class TestReadingInput:
    def test_a_receipt_file_becomes_a_one_receipt_bundle(self, tmp_path: Path) -> None:
        bundle = load_input(_receipt_file(tmp_path))
        assert len(bundle["receipts"]) == 1
        assert bundle["session"] is None

    def test_a_session_bundle_is_read_as_is(self) -> None:
        bundle = load_input(BUNDLES_DIR / "session-v1.1.json")
        assert bundle["session"]["session_id"]

    def test_a_rendered_page_is_itself_a_valid_input(self, tmp_path: Path) -> None:
        """The auditor can check the page against a second implementation."""
        source = json.loads((BUNDLES_DIR / "receipts-v1.2.json").read_text())
        page = tmp_path / "verify.html"
        page.write_text(render_verify_html(source))
        bundle = load_input(page)
        assert bundle["session"]["session_id"] == source["session"]["session_id"]
        assert bundle["receipts"][0]["envelope"] == source["receipts"][0]["envelope"]

    def test_a_page_with_no_bundle_says_so(self, tmp_path: Path) -> None:
        page = tmp_path / "x.html"
        page.write_text("<html>nothing here</html>")
        with pytest.raises(ValueError, match="does not carry"):
            load_input(page)


class TestExitCodes:
    def test_a_sound_receipt_exits_zero(self, tmp_path: Path, capsys: Any) -> None:
        assert verify_command(_receipt_file(tmp_path)) == 0
        assert "nothing was contradicted" in capsys.readouterr().out

    def test_a_tampered_receipt_exits_one(self, tmp_path: Path, capsys: Any) -> None:
        case = json.loads((VECTORS_DIR / "tampered.json").read_text())["cases"][0]
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"envelope": case["envelope"], "leaves": case["leaves"]}))
        assert verify_command(path) == 1
        assert "SOMETHING WAS CONTRADICTED" in capsys.readouterr().out

    def test_an_unreadable_file_exits_two(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.json"
        path.write_text("{not json")
        assert verify_command(path) == 2

    def test_require_complete_turns_an_unchecked_check_into_a_failure(
        self, tmp_path: Path
    ) -> None:
        path = _receipt_file(tmp_path)
        assert verify_command(path) == 0
        assert verify_command(path, require_complete=True) == 1


class TestOutput:
    def test_the_verdict_leads_with_words(self, tmp_path: Path, capsys: Any) -> None:
        verify_command(_receipt_file(tmp_path))
        out = capsys.readouterr().out
        assert "Told to" in out
        assert "Allowed by" in out
        assert "Authorization" in out
        assert "Ledger" in out
        assert "Level" in out

    def test_unchecked_checks_are_listed_by_name(self, tmp_path: Path, capsys: Any) -> None:
        verify_command(_receipt_file(tmp_path))
        out = capsys.readouterr().out
        assert "signer.attestation" in out
        assert "none of them is a pass" in out

    def test_json_output_is_the_structured_verdict(self, tmp_path: Path, capsys: Any) -> None:
        verify_command(_receipt_file(tmp_path), as_json=True)
        body = json.loads(capsys.readouterr().out)
        assert body["ok"] is True
        assert body["receipts"][0]["settlement"]["transaction_authorization"] == "verified"
        assert body["receipts"][0]["level"] == 1

    def test_pinning_a_validator_set_runs_the_quorum_check(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        verdicts = json.loads((VECTORS_DIR / "verdicts.json").read_text())["cases"]
        case = next(c for c in verdicts if c["name"] == "allow-settled-fake-rail")
        path = _receipt_file(tmp_path, "allow-settled-fake-rail")
        proof = tmp_path / "proof.json"
        proof.write_text(json.dumps(case["material"]["settlement_proof"]))
        trust = case["material"]["validator_trust"]
        code = verify_command(
            path,
            proof=proof,
            validator=[f"{k}={v}" for k, v in trust["validators"].items()],
            quorum=trust["quorum"],
            as_json=True,
        )
        assert code == 0
        body = json.loads(capsys.readouterr().out)
        assert body["receipts"][0]["settlement"]["ledger_inclusion"] == "proven-offline"


class TestReceiptShow:
    def test_a_file_path_resolves(self, tmp_path: Path) -> None:
        assert "envelope" in resolve_receipt(str(_receipt_file(tmp_path)))

    def test_an_id_resolves_out_of_the_local_store_first(self, tmp_path: Path) -> None:
        store = tmp_path / "store"
        store.mkdir()
        case = BY_NAME["allow-settled"]
        (store / "r-1.json").write_text(
            json.dumps({"envelope": case["envelope"], "leaves": case["leaves"]})
        )
        assert resolve_receipt("r-1", store=store)["envelope"]["root"] == case["root"]

    def test_a_missing_receipt_says_where_it_looked(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="not a file, not in"):
            resolve_receipt("nope", store=tmp_path / "store")

    def test_show_prints_the_seven_leaves_in_plain_language(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        assert receipt_show_command(str(_receipt_file(tmp_path))) == 0
        out = capsys.readouterr().out
        for name in (
            "instruction",
            "intent",
            "policy_decision",
            "signer_attestation",
            "settlement",
            "result",
            "reasoning",
        ):
            assert name in out
        assert "Testimony, not proof" in out
        assert "authorization    verified" in out

    def test_a_denial_reads_as_a_refusal(self, tmp_path: Path, capsys: Any) -> None:
        assert receipt_show_command(str(_receipt_file(tmp_path, "deny-not-submitted"))) == 0
        out = capsys.readouterr().out
        assert "refused" in out
        assert "absent, and committed as absent" in out


class TestReconcile:
    def _outflow(self, tx: str, anchor: str) -> dict[str, Any]:
        return {
            "tx_hash": tx,
            "destination": "rSUPPLIER",
            "value": "250.00",
            "asset": "RLUSD",
            "ledger_index": 1,
            "anchor": anchor,
        }

    def _receipt(self, name: str = "allow-settled") -> dict[str, Any]:
        case = BY_NAME[name]
        return {"envelope": case["envelope"], "leaves": case["leaves"]}

    def test_a_matching_pair_is_clean(self) -> None:
        receipt = self._receipt()
        tx = receipt["leaves"][4]["tx_hash"]
        report = reconcile([self._outflow(tx, receipt["envelope"]["left"])], [receipt])
        assert report.clean
        assert len(report.matched) == 1

    def test_an_outflow_with_no_receipt_is_the_finding_that_matters(self) -> None:
        report = reconcile([self._outflow("DEADBEEF", "00" * 32)], [])
        assert not report.clean
        assert len(report.outflows_without_receipts) == 1

    def test_a_receipt_with_no_outflow_is_reported_too(self) -> None:
        report = reconcile([], [self._receipt()])
        assert not report.clean
        assert len(report.receipts_without_outflows) == 1

    def test_an_anchor_the_ledger_did_not_carry_is_a_mismatch(self) -> None:
        receipt = self._receipt()
        tx = receipt["leaves"][4]["tx_hash"]
        report = reconcile([self._outflow(tx, "ab" * 32)], [receipt])
        assert not report.clean
        assert report.anchor_mismatches[0][0] == tx.upper()

    def test_the_command_needs_a_history_file_and_says_so(self, tmp_path: Path) -> None:
        assert reconcile_command("rTREASURY", store=tmp_path) == 2

    def test_the_command_names_the_absent_notary(self, tmp_path: Path, capsys: Any) -> None:
        history = tmp_path / "h.json"
        history.write_text("[]")
        assert reconcile_command("rTREASURY", history=history, store=tmp_path) == 0
        assert "no notary is configured" in capsys.readouterr().out


class TestApproverKeys:
    def test_a_world_readable_key_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "approver.key"
        path.write_text("11" * 32)
        path.chmod(0o644)
        with pytest.raises(PermissionError, match="chmod 600"):
            load_approver_key(path)

    def test_a_missing_key_says_how_to_make_one(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="32-byte Ed25519 seed"):
            load_approver_key(tmp_path / "nope.key")

    def test_the_signature_is_over_the_raw_challenge_bytes(self, tmp_path: Path) -> None:
        from merkl.core.crypto import ed25519_verify

        path = tmp_path / "approver.key"
        path.write_text("11" * 32)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        key = load_approver_key(path)
        challenge = "ab" * 32
        assertion = sign_challenge(key, challenge, "alice@example.com", "2026-01-02T03:20:11Z")
        public = key.public_key().public_bytes_raw().hex()
        assert ed25519_verify(public, assertion.signature, bytes.fromhex(challenge))
        assert assertion.credential_type == "ed25519"
        assert assertion.client_data_json is None

    def test_a_challenge_of_the_wrong_length_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "approver.key"
        path.write_text("11" * 32)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        with pytest.raises(ValueError, match="32 bytes"):
            sign_challenge(load_approver_key(path), "abcd", "alice", "2026-01-02T03:20:11Z")
