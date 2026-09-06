"""Every committed vector, checked by loading the JSON — never by regenerating it.

These tests are the Python half of the cross-implementation contract: the JS
verifier loads the same files and must reach the same conclusions.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from merkl.core.leaf import action_leaf, receipt_leaf
from merkl.core.merkle import MerkleProof, MerkleTree
from merkl.core.receipt import (
    HALF_LEVEL,
    LEAF_NAMES,
    RECEIPT_VERSION,
    Disclosure,
    Envelope,
    ReceiptLeaves,
    build_left,
    build_right,
    build_root,
    verify_disclosure,
    verify_receipt_structure,
)
from merkl.core.vectors import VECTOR_FILES, VECTORS_DIR
from merkl.core.vectors.generate import check as check_vectors
from merkl.shared.hashing import SHA256Hash


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    return data


def sha256(text: str) -> SHA256Hash:
    return SHA256Hash.from_bytes(text.encode())


def from_hex(value: str) -> SHA256Hash:
    return SHA256Hash(bytes.fromhex(value))


MERKLE = load("merkle.json")
ACTION_LEAF = load("action_leaf.json")
RECEIPT_LEAF = load("receipt_leaf.json")
RECEIPTS = load("receipts.json")
TAMPERED = load("tampered.json")
MANIFEST = load("manifest.json")


def ids(cases: list[dict[str, Any]]) -> list[str]:
    return [str(c["name"]) for c in cases]


class TestFixtureHygiene:
    def test_committed_vectors_are_up_to_date(self) -> None:
        assert check_vectors(VECTORS_DIR) == [], "run: python -m merkl.core.vectors.generate"

    def test_every_declared_file_exists_with_the_declared_count(self) -> None:
        counts = {entry["file"]: entry["cases"] for entry in MANIFEST["files"]}
        assert set(counts) == set(VECTOR_FILES)
        for name, count in counts.items():
            assert len(load(name)["cases"]) == count

    @pytest.mark.parametrize("name", VECTOR_FILES)
    def test_fixtures_are_plain_json(self, name: str) -> None:
        """No floats, so a JavaScript verifier reads every number exactly.

        The one exception is the tamper case that exists to be rejected for
        carrying a fractional amount.
        """

        def floats(node: Any, path: str) -> list[str]:
            if isinstance(node, float):
                return [path]
            if isinstance(node, dict):
                assert all(isinstance(k, str) for k in node)
                return [p for k, v in node.items() for p in floats(v, f"{path}.{k}")]
            if isinstance(node, list):
                return [p for i, v in enumerate(node) for p in floats(v, f"{path}[{i}]")]
            return []

        data = load(name)
        for case in data["cases"]:
            found = floats(case, "$")
            if case["name"] == "fractional-amount":
                assert found, "this case exists to carry a fractional amount"
            else:
                assert found == [], f"float in {name} case {case['name']}: {found}"

    def test_at_least_three_receipts_and_ten_tamper_cases(self) -> None:
        assert len(RECEIPTS["cases"]) >= 3
        assert len(TAMPERED["cases"]) >= 10


class TestMerkleVectors:
    @pytest.mark.parametrize("case", MERKLE["cases"], ids=ids(MERKLE["cases"]))
    def test_tree_matches(self, case: dict[str, Any]) -> None:
        leaves = [sha256(s) for s in case["leaf_inputs"]]
        assert [h.hex() for h in leaves] == case["leaves"]
        tree = MerkleTree.build(leaves)
        assert tree.root.hex() == case["root"]
        assert [h.hex() for h in tree.padded_leaves] == case["padded_leaves"]
        assert tree.depth == case["depth"]
        assert [[h.hex() for h in tree.level(i)] for i in range(tree.depth + 1)] == case["levels"]

    @pytest.mark.parametrize("case", MERKLE["cases"], ids=ids(MERKLE["cases"]))
    def test_proofs_match_and_verify(self, case: dict[str, Any]) -> None:
        leaves = [sha256(s) for s in case["leaf_inputs"]]
        root = from_hex(case["root"])
        for entry in case["proofs"]:
            proof = MerkleProof.from_dict(entry)
            assert proof.verify(leaves[entry["index"]], root) is True
            assert MerkleTree.build(leaves).get_proof(entry["index"]).to_dict() == {
                "siblings": entry["siblings"],
                "directions": entry["directions"],
            }

    @pytest.mark.parametrize("case", MERKLE["cases"], ids=ids(MERKLE["cases"]))
    def test_subtree_proofs_match_and_verify(self, case: dict[str, Any]) -> None:
        leaves = [sha256(s) for s in case["leaf_inputs"]]
        tree = MerkleTree.build(leaves)
        for entry in case["subtree_proofs"]:
            node = tree.subtree_root(entry["level"], entry["subtree_index"])
            assert node.hex() == entry["subtree_root"]
            assert MerkleProof.from_dict(entry).verify(leaves[entry["index"]], node) is True


class TestActionLeafVectors:
    def test_tag(self) -> None:
        assert ACTION_LEAF["tag"] == "merkl-leaf-v1"

    @pytest.mark.parametrize("case", ACTION_LEAF["cases"], ids=ids(ACTION_LEAF["cases"]))
    def test_leaf_matches(self, case: dict[str, Any]) -> None:
        assert action_leaf(**case["fields"]).hex() == case["leaf"]

    def test_every_case_is_distinct(self) -> None:
        leaves = [c["leaf"] for c in ACTION_LEAF["cases"]]
        assert len(set(leaves)) == len(leaves)


class TestReceiptLeafVectors:
    def test_tag(self) -> None:
        assert RECEIPT_LEAF["tag"] == "merkl-receipt-leaf-v1"

    @pytest.mark.parametrize("case", RECEIPT_LEAF["cases"], ids=ids(RECEIPT_LEAF["cases"]))
    def test_leaf_matches(self, case: dict[str, Any]) -> None:
        assert receipt_leaf(case["leaf_name"], case["content"]).hex() == case["leaf"]

    def test_key_order_does_not_change_the_leaf(self) -> None:
        by_name = {c["name"]: c for c in RECEIPT_LEAF["cases"]}
        assert by_name["key-order-a"]["leaf"] == by_name["key-order-b"]["leaf"]

    def test_null_leaves_differ_per_name(self) -> None:
        nulls = {c["leaf"] for c in RECEIPT_LEAF["cases"] if c["name"].startswith("null-")}
        assert len(nulls) == len(LEAF_NAMES)


class TestReceiptVectors:
    def test_version(self) -> None:
        assert RECEIPTS["version"] == RECEIPT_VERSION

    def test_the_four_shapes_are_present(self) -> None:
        assert {c["name"] for c in RECEIPTS["cases"]} == {
            "allow-settled",
            "deny-not-submitted",
            "escalated-approved-settled",
            "allow-settled-fake-rail",
        }

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_leaf_hashes_left_right_root(self, case: dict[str, Any]) -> None:
        assert case["leaf_names"] == list(LEAF_NAMES)
        computed = [
            receipt_leaf(name, content)
            for name, content in zip(LEAF_NAMES, case["leaves"], strict=True)
        ]
        padded = [*computed, computed[-1]]
        assert [h.hex() for h in padded] == case["leaf_hashes"]
        assert build_left(padded[0:4]).hex() == case["left"]
        assert build_right(padded[4:8]).hex() == case["right"]
        assert build_root(padded).hex() == case["root"]
        assert (
            SHA256Hash.from_bytes(
                from_hex(case["left"]).bytes + from_hex(case["right"]).bytes
            ).hex()
            == case["root"]
        )

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_envelope_and_its_hash(self, case: dict[str, Any]) -> None:
        envelope = Envelope.from_content(case["envelope"])
        assert envelope.to_content() == case["envelope"]
        assert envelope.envelope_hash().hex() == case["envelope_hash"]
        assert envelope.root.hex() == case["root"]
        assert envelope.left.hex() == case["left"]

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_leaf_contents_parse_into_models_and_back(self, case: dict[str, Any]) -> None:
        leaves = ReceiptLeaves.from_contents(case["leaves"])
        assert list(leaves.contents()) == case["leaves"]

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_proofs(self, case: dict[str, Any]) -> None:
        root = from_hex(case["root"])
        for i, name in enumerate(LEAF_NAMES):
            leaf = from_hex(case["leaf_hashes"][i])
            entry = case["proofs"][name]
            assert entry["index"] == i
            assert MerkleProof.from_dict(entry).verify(leaf, root) is True
            half = case["half_proofs"][name]
            assert half["level"] == HALF_LEVEL
            assert half["half"] == ("left" if i < 4 else "right")
            assert half["subtree_root"] == (case["left"] if i < 4 else case["right"])
            assert MerkleProof.from_dict(half).verify(leaf, from_hex(half["subtree_root"])) is True

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_verification_matches_the_recorded_result(self, case: dict[str, Any]) -> None:
        result = verify_receipt_structure(Envelope.from_content(case["envelope"]), case["leaves"])
        assert result.to_content() == case["verification"]
        assert result.ok is True
        assert result.complete is False

    @pytest.mark.parametrize("case", RECEIPTS["cases"], ids=ids(RECEIPTS["cases"]))
    def test_disclosure(self, case: dict[str, Any]) -> None:
        disclosure = Disclosure.from_content(case["disclosure"])
        assert disclosure.to_content() == case["disclosure"]
        result = verify_disclosure(disclosure, from_hex(case["root"]))
        assert result.to_content() == case["disclosure_verification"]
        assert result.ok is True
        assert disclosure.disclosed_names
        assert disclosure.withheld_names

    def test_a_denied_receipt_has_null_leaves(self) -> None:
        case = next(c for c in RECEIPTS["cases"] if c["name"] == "deny-not-submitted")
        assert case["leaves"][3] is None
        assert case["leaves"][4] is None
        assert case["leaves"][5]["outcome"] == "denied"

    def test_an_escalated_receipt_carries_its_approvals(self) -> None:
        case = next(c for c in RECEIPTS["cases"] if c["name"] == "escalated-approved-settled")
        escalation = case["leaves"][2]["escalation"]
        assert escalation["quorum"] == 2
        assert len(escalation["approvals"]) == 2

    def test_the_settled_receipts_anchor_left(self) -> None:
        for name in ("allow-settled", "escalated-approved-settled"):
            case = next(c for c in RECEIPTS["cases"] if c["name"] == name)
            assert case["leaves"][4]["observed_anchor"] == case["left"]


_RECEIPT_TAMPERS = [c for c in TAMPERED["cases"] if c["kind"] == "receipt"]
_DISCLOSURE_TAMPERS = [c for c in TAMPERED["cases"] if c["kind"] == "disclosure"]


class TestTamperedVectors:
    def test_the_families_are_covered(self) -> None:
        names = {c["name"] for c in TAMPERED["cases"]}
        assert len([n for n in names if "one-byte-changed" in n]) == len(LEAF_NAMES)
        assert "swapped-leaf-names" in names
        assert "wrong-padding" in names
        assert len(_DISCLOSURE_TAMPERS) >= 3

    @pytest.mark.parametrize("case", _RECEIPT_TAMPERS, ids=ids(_RECEIPT_TAMPERS))
    def test_receipt_tampering_fails_exactly_the_expected_checks(
        self, case: dict[str, Any]
    ) -> None:
        result = verify_receipt_structure(Envelope.from_content(case["envelope"]), case["leaves"])
        assert result.ok is case["expected_ok"]
        assert sorted(c.name for c in result.failures) == case["expected_failing_checks"]

    @pytest.mark.parametrize("case", _DISCLOSURE_TAMPERS, ids=ids(_DISCLOSURE_TAMPERS))
    def test_disclosure_tampering_fails_exactly_the_expected_checks(
        self, case: dict[str, Any]
    ) -> None:
        result = verify_disclosure(
            Disclosure.from_content(case["disclosure"]), from_hex(case["root"])
        )
        assert result.ok is case["expected_ok"]
        assert sorted(c.name for c in result.failures) == case["expected_failing_checks"]

    def test_every_case_names_at_least_one_failing_check(self) -> None:
        for case in TAMPERED["cases"]:
            assert case["expected_failing_checks"]
            assert case["expected_ok"] is False
