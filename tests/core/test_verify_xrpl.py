"""XRPL offline inclusion: the SHAMap, validations and manifests, over real material.

Every case in ``merkl/core/vectors/xrpl/cases.json`` is derived from real XRPL
testnet captures (see ``fixtures.json``): a ledger's whole binary transaction
set, two validators' actual ``STValidation`` messages and manifests, and the
testnet UNL from ``vl.altnet.rippletest.net``. A verifier that passes these
agrees with rippled and with real validator signatures, not merely with itself.
"""

from __future__ import annotations

import json

import pytest

from merkl.core.crypto import CryptoError
from merkl.core.vectors.xrpl import CASES_FILE
from merkl.core.verify.xrpl import (
    build_tx_path,
    evaluate_validation,
    fold_tx_path,
    parse_fields,
    pin_validator_list,
)

CASES = json.loads(CASES_FILE.read_text(encoding="utf-8"))


class TestVectorsAreCurrent:
    def test_cases_json_matches_a_fresh_generation(self) -> None:
        from merkl.core.vectors.xrpl.generate import check

        assert check(), "cases.json is stale — run python -m merkl.core.vectors.xrpl.generate"


@pytest.mark.parametrize("case", CASES["shamap_cases"], ids=lambda c: c["name"])
class TestSHAMap:
    def test_case(self, case: dict) -> None:
        if "expect_root" in case:
            items = []
            from merkl.core.rail import tx_id_from_blob

            for tx in case["transactions"]:
                tx_id = bytes.fromhex(tx_id_from_blob("xrpl", tx["tx_blob"]) or "")
                items.append((tx_id, bytes.fromhex(tx["tx_blob"]), bytes.fromhex(tx["meta"])))
            target = bytes.fromhex(case["target_tx_id"])
            root_hex, path = build_tx_path(target, items)
            assert root_hex == case["expect_root"]
            assert path == case["expect_path"]
        else:
            folded = fold_tx_path(
                case["target_tx_id"], case["target_tx_blob"], case["target_tx_meta"], case["path"]
            )
            assert folded != case["expect_root_mismatch"]


def test_shamap_path_requires_the_target_to_be_present() -> None:
    with pytest.raises(ValueError, match="not in this ledger"):
        build_tx_path(b"\x00" * 32, [(b"\x11" * 32, b"blob", b"meta")])


def test_shamap_empty_transaction_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="no transactions"):
        build_tx_path(b"\x00" * 32, [])


def test_fold_tx_path_is_none_on_malformed_input() -> None:
    assert fold_tx_path("00" * 32, "aa", "bb", [{"nibble": 16, "siblings": []}]) is None
    assert fold_tx_path("00" * 32, "aa", "bb", [{"nibble": 0, "siblings": ["zz"]}]) is None
    assert fold_tx_path("not-hex", "aa", "bb", []) is None


@pytest.mark.parametrize("case", CASES["validation_cases"], ids=lambda c: c["name"])
class TestValidations:
    def test_case(self, case: dict) -> None:
        entry = {"data": case["data"], "manifest": case["manifest"]}
        verdict = evaluate_validation(
            entry, ledger_hash=case["ledger_hash"], pinned_masters=case["pinned_masters"]
        )
        if case["expect_outcome"] is None:
            assert verdict is None
        else:
            assert verdict is not None
            assert verdict.outcome == case["expect_outcome"]
            if case["expect_master_key"] is not None:
                assert verdict.master_key == case["expect_master_key"]


def test_a_validation_with_no_data_field_is_unchecked() -> None:
    verdict = evaluate_validation({}, ledger_hash="ab" * 32, pinned_masters=["ed" + "11" * 32])
    assert verdict is not None
    assert verdict.outcome == "unchecked"


def test_a_validation_that_does_not_parse_is_unchecked_not_fatal() -> None:
    verdict = evaluate_validation(
        {"data": "00", "manifest": "x"}, ledger_hash="ab" * 32, pinned_masters=["ed" + "11" * 32]
    )
    assert verdict is not None
    assert verdict.outcome == "unchecked"


class TestFieldWalker:
    def test_a_truncated_field_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_fields(bytes.fromhex("22"))  # UInt32 header with no value

    def test_an_unsupported_field_type_raises(self) -> None:
        # type code 8 (AccountID) is not in the fixed-width table and has no VL
        # handling either — it never appears in a Validation or Manifest.
        with pytest.raises(ValueError, match="unsupported"):
            parse_fields(bytes.fromhex("81" + "00" * 20))

    def test_a_non_native_amount_raises(self) -> None:
        # type 6 (Amount), field 1, with the high bit of the value set: an
        # issued-currency amount, which never appears in Validation/Manifest.
        with pytest.raises(ValueError, match="non-native"):
            parse_fields(bytes.fromhex("61") + bytes([0x80]) + b"\x00" * 7)


@pytest.mark.parametrize("case", CASES["unl_cases"], ids=lambda c: c["name"])
class TestUNL:
    def test_case(self, case: dict) -> None:
        if case.get("expect_error"):
            with pytest.raises((ValueError, CryptoError)):
                pin_validator_list(case["document"])
            return
        reading = pin_validator_list(case["document"])
        assert len(reading.masters) == case["expect_master_count"]
        assert len(reading.skipped) == case["expect_skipped_count"]
        assert reading.quorum() == case["expect_quorum"]


def test_pin_validator_list_rejects_a_document_missing_fields() -> None:
    with pytest.raises(ValueError, match="not a validator-list document"):
        pin_validator_list({})


def test_quorum_is_ceil_of_eighty_percent() -> None:
    from merkl.core.verify.xrpl import PinnedUNLReading

    reading = PinnedUNLReading(
        publisher_key="ed" + "00" * 32,
        sequence=1,
        expiration=0,
        masters=tuple(f"ed{i:064x}" for i in range(7)),
        skipped=(),
    )
    assert reading.quorum() == 6  # ceil(0.8 * 7) == 6
