"""The seven-leaf receipt: order, halves, envelope, disclosure, verification."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from merkl.core.canonical import ContentError
from merkl.core.leaf import receipt_leaf
from merkl.core.merkle import MerkleProof, MerkleTree
from merkl.core.receipt import (
    CHECK_ENVELOPE_POLICY_HASH,
    CHECK_ENVELOPE_RAIL,
    CHECK_ENVELOPE_TREASURY,
    CHECK_LEAF_COUNT,
    CHECK_LEFT,
    CHECK_PADDING,
    CHECK_REQUIRED_LEAVES,
    CHECK_RIGHT,
    CHECK_ROOT,
    CHECK_VERSION,
    DEFERRED_CHECKS,
    HALF_LEVEL,
    LEAF_NAMES,
    RECEIPT_VERSION,
    CheckStatus,
    Disclosure,
    Envelope,
    Escalation,
    Instruction,
    PolicyDecision,
    PolicyRule,
    Reasoning,
    Receipt,
    ReceiptError,
    ReceiptLeaves,
    Result,
    SessionLocator,
    Settlement,
    build_left,
    build_right,
    build_root,
    build_tree,
    leaf_check,
    proof_check,
    verify_disclosure,
    verify_receipt_structure,
)
from merkl.shared.hashing import SHA256Hash, canonical_bytes
from tests.core.factories import (
    POLICY_HASH,
    attested,
    digest,
    make_intent,
    make_leaves,
    make_receipt,
)


class TestLeafOrder:
    def test_names_and_order_are_the_format(self) -> None:
        assert LEAF_NAMES == (
            "instruction",
            "intent",
            "policy_decision",
            "signer_attestation",
            "settlement",
            "result",
            "reasoning",
        )

    def test_seven_contents_seven_hashes_eight_padded(self) -> None:
        leaves = make_leaves()
        assert len(leaves.contents()) == 7
        assert len(leaves.hashes()) == 7
        padded = leaves.padded_hashes()
        assert len(padded) == 8
        assert padded[7] == padded[6]

    def test_each_leaf_hash_is_its_content_under_its_name(self) -> None:
        leaves = make_leaves()
        for name, content, digest_ in zip(
            LEAF_NAMES, leaves.contents(), leaves.hashes(), strict=True
        ):
            assert receipt_leaf(name, content) == digest_

    def test_absent_leaf_is_hashed_as_null(self) -> None:
        leaves = make_leaves(signer_attestation=None)
        assert leaves.hashes()[3] == receipt_leaf("signer_attestation", None)

    def test_contents_round_trip_through_models(self) -> None:
        leaves = make_leaves(signer_attestation=attested())
        assert ReceiptLeaves.from_contents(leaves.contents()) == leaves


class TestHalves:
    def test_left_right_root_agree_with_the_tree(self) -> None:
        leaves = make_leaves()
        padded = leaves.padded_hashes()
        tree = MerkleTree.build(list(leaves.hashes()))
        assert build_left(padded[0:4]) == tree.subtree_root(HALF_LEVEL, 0)
        assert build_right(padded[4:8]) == tree.subtree_root(HALF_LEVEL, 1)
        assert build_root(padded) == tree.root
        assert build_root(leaves.hashes()) == tree.root

    def test_root_is_left_then_right(self) -> None:
        receipt = make_receipt()
        assert receipt.root == SHA256Hash.from_bytes(receipt.left.bytes + receipt.right.bytes)

    def test_left_only_depends_on_leaves_0_to_3(self) -> None:
        base = make_receipt()
        changed = make_receipt(
            leaves=make_leaves(
                result=Result(outcome="failed", engine_result="tecUNFUNDED_PAYMENT")
            )
        )
        assert changed.left == base.left
        assert changed.root != base.root

    def test_right_changes_when_settlement_changes(self) -> None:
        base = make_receipt()
        changed = make_receipt(
            leaves=make_leaves(
                settlement=Settlement(
                    rail="xrpl",
                    tx_hash="0" * 64,
                    ledger_index=94_211_338,
                    close_time="2026-01-02T03:04:42Z",
                )
            )
        )
        assert changed.right != base.right
        assert changed.left == base.left

    @pytest.mark.parametrize("count", [0, 1, 3, 5, 9])
    def test_halves_need_exactly_four_hashes(self, count: int) -> None:
        hashes = [SHA256Hash.from_bytes(str(i).encode()) for i in range(count)]
        with pytest.raises(ReceiptError):
            build_left(hashes)
        with pytest.raises(ReceiptError):
            build_right(hashes)

    @pytest.mark.parametrize("count", [0, 6, 9])
    def test_root_needs_seven_or_eight(self, count: int) -> None:
        hashes = [SHA256Hash.from_bytes(str(i).encode()) for i in range(count)]
        with pytest.raises(ReceiptError):
            build_root(hashes)
        with pytest.raises(ReceiptError):
            build_tree(hashes)


class TestEnvelope:
    def test_build_derives_the_commitments(self) -> None:
        receipt = make_receipt()
        envelope = receipt.envelope
        assert envelope.version == RECEIPT_VERSION
        assert envelope.leaf_hashes == receipt.leaves.padded_hashes()
        assert envelope.left == build_left(envelope.leaf_hashes[0:4])
        assert envelope.root == build_root(envelope.leaf_hashes)

    def test_build_derives_rail_treasury_and_policy_hash(self) -> None:
        envelope = make_receipt().envelope
        assert envelope.rail == "xrpl"
        assert envelope.treasury == make_intent().treasury
        assert envelope.policy_hash == POLICY_HASH

    def test_build_rejects_a_disagreeing_override(self) -> None:
        with pytest.raises(ReceiptError, match="disagrees"):
            make_receipt(rail="fake")

    def test_build_requires_intent_and_decision(self) -> None:
        with pytest.raises(ReceiptError, match="intent"):
            make_receipt(leaves=make_leaves(intent=None))
        with pytest.raises(ReceiptError, match="policy_decision"):
            make_receipt(leaves=make_leaves(policy_decision=None))

    def test_envelope_hash_is_the_canonical_content_hash(self) -> None:
        envelope = make_receipt().envelope
        assert envelope.envelope_hash() == SHA256Hash.from_bytes(
            canonical_bytes(envelope.to_content())
        )

    def test_envelope_hash_changes_with_any_member(self) -> None:
        base = make_receipt().envelope
        other = make_receipt(agent_id="agent-other").envelope
        assert other.envelope_hash() != base.envelope_hash()

    def test_session_locator_is_optional_and_omitted(self) -> None:
        assert "session_locator" not in make_receipt().envelope.to_content()
        located = make_receipt(
            session_locator=SessionLocator(session_id="01936b2e-1111-7000-8000-0001", leaf_index=4)
        ).envelope
        assert located.to_content()["session_locator"] == {
            "session_id": "01936b2e-1111-7000-8000-0001",
            "leaf_index": 4,
        }

    def test_round_trips(self) -> None:
        envelope = make_receipt().envelope
        assert Envelope.from_content(envelope.to_content()) == envelope

    def test_rejects_wrong_leaf_hash_count(self) -> None:
        content = make_receipt().envelope.to_content()
        assert isinstance(content["leaf_hashes"], list)
        content["leaf_hashes"] = content["leaf_hashes"][:7]
        with pytest.raises(ReceiptError, match="8 hashes"):
            Envelope.from_content(content)

    def test_rejects_unknown_members(self) -> None:
        content = make_receipt().envelope.to_content()
        content["previous_root"] = "0" * 64
        with pytest.raises(ReceiptError, match="unknown members"):
            Envelope.from_content(content)


class TestProofs:
    def test_every_leaf_proves_to_the_root(self) -> None:
        receipt = make_receipt()
        for name, digest_ in zip(LEAF_NAMES, receipt.leaves.hashes(), strict=True):
            assert receipt.proof(name).verify(digest_, receipt.root) is True

    def test_every_leaf_proves_to_its_half(self) -> None:
        receipt = make_receipt()
        for i, (name, digest_) in enumerate(zip(LEAF_NAMES, receipt.leaves.hashes(), strict=True)):
            half = receipt.left if i < 4 else receipt.right
            assert receipt.half_proof(name).verify(digest_, half) is True

    def test_unknown_leaf_name(self) -> None:
        with pytest.raises(ReceiptError, match="unknown leaf name"):
            make_receipt().proof("memo")


class TestStructuralVerification:
    def test_a_good_receipt_passes_everything_implemented(self) -> None:
        result = make_receipt().verify_structure()
        assert result.ok is True
        assert result.complete is False
        assert result.failures == ()

    def test_check_order_follows_the_spec(self) -> None:
        names = [c.name for c in make_receipt().verify_structure().checks]
        assert names == [
            CHECK_VERSION,
            CHECK_LEAF_COUNT,
            CHECK_REQUIRED_LEAVES,
            *[leaf_check(n) for n in LEAF_NAMES],
            CHECK_PADDING,
            CHECK_LEFT,
            "policy.signature",
            "signer.attestation",
            "intent.matches_settled_fields",
            "settlement.anchor_equals_left",
            "settlement.signed_blob",
            "settlement.ledger_inclusion",
            CHECK_RIGHT,
            CHECK_ROOT,
            CHECK_ENVELOPE_RAIL,
            CHECK_ENVELOPE_TREASURY,
            CHECK_ENVELOPE_POLICY_HASH,
            "session.log_join",
        ]

    def test_deferred_checks_are_named_not_silent(self) -> None:
        result = make_receipt().verify_structure()
        deferred = {c.name for c in result.deferred}
        assert deferred == {name for name, _ in DEFERRED_CHECKS}
        for check in result.deferred:
            assert check.status is CheckStatus.NOT_IMPLEMENTED
            assert "phase" in check.detail

    def test_a_denied_receipt_verifies(self) -> None:
        leaves = make_leaves(
            policy_decision=PolicyDecision(
                policy_hash=POLICY_HASH,
                rules=(PolicyRule(name="per_tx_cap", outcome="fail", detail="over cap"),),
                outcome="deny",
                tier="instant",
            ),
            settlement=None,
            result=Result(outcome="denied", detail="policy denied the payment"),
        )
        result = make_receipt(leaves=leaves).verify_structure()
        assert result.ok is True
        assert leaves.contents()[4] is None

    def test_an_escalated_receipt_verifies(self) -> None:
        escalation = Escalation(
            challenge=digest("left-pre"),
            expires_at="2026-01-02T04:04:05Z",
            quorum=2,
            approvals=(
                {"approver": "alice", "method": "webauthn", "signature": "AAAA"},
                {"approver": "bob", "method": "ed25519", "signature": "BBBB"},
            ),
        )
        leaves = make_leaves(
            policy_decision=PolicyDecision(
                policy_hash=POLICY_HASH,
                rules=(PolicyRule(name="per_tx_cap", outcome="escalate", detail="over 100"),),
                outcome="allow",
                tier="human",
                escalation=escalation,
            )
        )
        assert make_receipt(leaves=leaves).verify_structure().ok is True

    @pytest.mark.parametrize("index", range(7))
    def test_a_changed_leaf_fails_its_own_check(self, index: int) -> None:
        receipt = make_receipt()
        contents = list(receipt.leaves.contents())
        contents[index] = {"tampered": True}
        result = verify_receipt_structure(receipt.envelope, contents)
        assert result.ok is False
        failures = {c.name for c in result.failures}
        assert leaf_check(LEAF_NAMES[index]) in failures
        assert CHECK_LEFT in failures or CHECK_RIGHT in failures

    def test_a_changed_leaf_does_not_move_the_committed_root(self) -> None:
        receipt = make_receipt()
        contents = list(receipt.leaves.contents())
        contents[5] = None
        result = verify_receipt_structure(receipt.envelope, contents)
        assert result.get(CHECK_ROOT) is not None
        assert result.get(CHECK_ROOT).status is CheckStatus.PASS  # type: ignore[union-attr]
        assert result.get(CHECK_RIGHT).status is CheckStatus.FAIL  # type: ignore[union-attr]

    def test_swapped_leaf_names_fail(self) -> None:
        receipt = make_receipt()
        contents = list(receipt.leaves.contents())
        contents[1], contents[2] = contents[2], contents[1]
        result = verify_receipt_structure(receipt.envelope, contents)
        failures = {c.name for c in result.failures}
        assert leaf_check("intent") in failures
        assert leaf_check("policy_decision") in failures
        assert CHECK_ENVELOPE_RAIL in failures

    def test_wrong_padding_fails(self) -> None:
        receipt = make_receipt()
        hashes = list(receipt.envelope.leaf_hashes)
        hashes[7] = SHA256Hash.from_bytes(b"not the sixth leaf")
        envelope = dataclass_replace(receipt.envelope, leaf_hashes=tuple(hashes))
        result = verify_receipt_structure(envelope, receipt.leaves)
        failures = {c.name for c in result.failures}
        assert CHECK_PADDING in failures
        assert CHECK_ROOT in failures

    def test_wrong_root_fails(self) -> None:
        receipt = make_receipt()
        envelope = dataclass_replace(receipt.envelope, root=SHA256Hash.from_bytes(b"forged"))
        result = verify_receipt_structure(envelope, receipt.leaves)
        assert {c.name for c in result.failures} == {CHECK_ROOT}

    def test_wrong_left_fails(self) -> None:
        receipt = make_receipt()
        envelope = dataclass_replace(receipt.envelope, left=SHA256Hash.from_bytes(b"forged"))
        result = verify_receipt_structure(envelope, receipt.leaves)
        assert {c.name for c in result.failures} == {CHECK_LEFT}

    def test_envelope_fields_must_match_the_leaves(self) -> None:
        receipt = make_receipt()
        envelope = dataclass_replace(receipt.envelope, treasury="rSOMEWHEREELSE")
        result = verify_receipt_structure(envelope, receipt.leaves)
        assert {c.name for c in result.failures} == {CHECK_ENVELOPE_TREASURY}

    def test_missing_required_leaf_fails(self) -> None:
        receipt = make_receipt()
        contents = list(receipt.leaves.contents())
        contents[0] = None
        result = verify_receipt_structure(receipt.envelope, contents)
        failures = {c.name for c in result.failures}
        assert CHECK_REQUIRED_LEAVES in failures
        assert leaf_check("instruction") in failures

    def test_wrong_leaf_count_fails_without_raising(self) -> None:
        receipt = make_receipt()
        result = verify_receipt_structure(receipt.envelope, list(receipt.leaves.contents())[:5])
        failures = {c.name for c in result.failures}
        assert CHECK_LEAF_COUNT in failures
        assert leaf_check("reasoning") in failures

    def test_non_canonical_content_fails_the_leaf_rather_than_raising(self) -> None:
        receipt = make_receipt()
        contents: list[Any] = list(receipt.leaves.contents())
        contents[1] = {"amount": {"value": 250.0, "currency": "XRP"}}
        result = verify_receipt_structure(receipt.envelope, contents)
        assert result.get(leaf_check("intent")).status is CheckStatus.FAIL  # type: ignore[union-attr]

    def test_wrong_version_fails(self) -> None:
        receipt = make_receipt()
        envelope = dataclass_replace(receipt.envelope, version="merkl-receipt-v2")
        assert {c.name for c in verify_receipt_structure(envelope, receipt.leaves).failures} == {
            CHECK_VERSION
        }

    def test_result_content_is_plain_json(self) -> None:
        content = make_receipt().verify_structure().to_content()
        assert content["ok"] is True
        assert content["complete"] is False
        checks = content["checks"]
        assert isinstance(checks, list)
        assert checks[0] == {"name": CHECK_VERSION, "status": "pass"}


class TestDisclosure:
    def test_reveals_only_what_was_asked(self) -> None:
        disclosure = make_receipt().disclose(["intent", "result"])
        assert disclosure.disclosed_names == ("intent", "result")
        assert disclosure.withheld_names == (
            "instruction",
            "policy_decision",
            "signer_attestation",
            "settlement",
            "reasoning",
        )
        assert [leaf.name for leaf in disclosure.leaves] == ["intent", "result"]

    def test_orders_by_leaf_index_and_deduplicates(self) -> None:
        disclosure = make_receipt().disclose(["result", "intent", "result"])
        assert disclosure.disclosed_names == ("intent", "result")

    def test_verifies_against_the_root(self) -> None:
        receipt = make_receipt()
        result = verify_disclosure(receipt.disclose(["intent"]), receipt.root)
        assert result.ok is True
        assert result.get(proof_check("intent")) is not None

    def test_verifies_every_leaf_singly_and_together(self) -> None:
        receipt = make_receipt()
        for name in LEAF_NAMES:
            assert verify_disclosure(receipt.disclose([name]), receipt.root).ok is True
        assert verify_disclosure(receipt.disclose(LEAF_NAMES), receipt.root).ok is True

    def test_empty_disclosure_still_proves_the_commitments(self) -> None:
        receipt = make_receipt()
        result = verify_disclosure(receipt.disclose([]), receipt.root)
        assert result.ok is True
        assert result.get(CHECK_ROOT) is not None

    def test_round_trips_through_json(self) -> None:
        disclosure = make_receipt().disclose(["intent", "settlement"])
        assert Disclosure.from_content(disclosure.to_content()) == disclosure

    def test_tampered_content_fails(self) -> None:
        receipt = make_receipt()
        content = receipt.disclose(["intent"]).to_content()
        leaves = content["leaves"]
        assert isinstance(leaves, list)
        leaf = leaves[0]
        assert isinstance(leaf, dict)
        intent = copy.deepcopy(leaf["content"])
        assert isinstance(intent, dict)
        intent["destination"] = "rATTACKER00000000000000000000000000"
        leaf["content"] = intent
        result = verify_disclosure(Disclosure.from_content(content), receipt.root)
        assert result.ok is False
        assert {c.name for c in result.failures} == {leaf_check("intent"), proof_check("intent")}

    def test_tampered_proof_fails(self) -> None:
        receipt = make_receipt()
        disclosure = receipt.disclose(["settlement"])
        leaf = disclosure.leaves[0]
        broken = MerkleProof(
            siblings=(SHA256Hash.from_bytes(b"wrong"), *leaf.proof.siblings[1:]),
            directions=leaf.proof.directions,
        )
        tampered = dataclass_replace(disclosure, leaves=(dataclass_replace(leaf, proof=broken),))
        result = verify_disclosure(tampered, receipt.root)
        assert {c.name for c in result.failures} == {proof_check("settlement")}

    def test_wrong_root_fails(self) -> None:
        receipt = make_receipt()
        result = verify_disclosure(receipt.disclose(["intent"]), SHA256Hash.from_bytes(b"other"))
        failures = {c.name for c in result.failures}
        assert "disclosure.root" in failures
        assert proof_check("intent") in failures

    def test_leaf_name_must_match_its_index(self) -> None:
        receipt = make_receipt()
        content = receipt.disclose(["intent"]).to_content()
        leaves = content["leaves"]
        assert isinstance(leaves, list) and isinstance(leaves[0], dict)
        leaves[0]["name"] = "result"
        with pytest.raises(ReceiptError, match="must be named"):
            Disclosure.from_content(content)

    def test_unknown_leaf_name_rejected(self) -> None:
        with pytest.raises(ReceiptError, match="unknown leaf names"):
            make_receipt().disclose(["memo"])

    def test_disclosure_from_a_doctored_envelope_fails(self) -> None:
        receipt = make_receipt()
        forged = Receipt(
            envelope=dataclass_replace(receipt.envelope, root=SHA256Hash.from_bytes(b"forged")),
            leaves=receipt.leaves,
        )
        disclosure = forged.disclose(["intent"])
        assert verify_disclosure(disclosure, forged.envelope.root).ok is False


class TestLeafModels:
    def test_instruction_source_is_closed(self) -> None:
        with pytest.raises(ReceiptError, match="source"):
            Instruction(source="vibes", content_hash=digest("x"))

    def test_instruction_content_hash_must_be_hex(self) -> None:
        with pytest.raises(ContentError, match="64 hex"):
            Instruction(source="system", content_hash="nope")

    def test_policy_outcome_is_closed(self) -> None:
        with pytest.raises(ReceiptError, match="outcome"):
            PolicyDecision(policy_hash=POLICY_HASH, rules=(), outcome="maybe", tier="instant")

    def test_escalation_quorum_must_be_a_positive_integer(self) -> None:
        for quorum in (0, -1, True, "2"):
            with pytest.raises(ReceiptError, match="quorum"):
                Escalation(challenge=digest("c"), expires_at="2026-01-02T03:04:05Z", quorum=quorum)

    def test_escalation_approvals_must_be_canonical(self) -> None:
        with pytest.raises(ContentError):
            Escalation(
                challenge=digest("c"),
                expires_at="2026-01-02T03:04:05Z",
                quorum=1,
                approvals=({"weight": 0.5},),
            )

    def test_receipt_errors_are_content_errors(self) -> None:
        assert issubclass(ReceiptError, ContentError)

    def test_settlement_ledger_index_is_an_integer(self) -> None:
        with pytest.raises(ReceiptError, match="ledger_index"):
            Settlement(
                rail="xrpl",
                tx_hash="A",
                ledger_index="94211337",
                close_time="2026-01-02T03:04:05Z",
            )

    def test_settlement_close_time_must_be_utc_z(self) -> None:
        with pytest.raises(ContentError, match="close_time"):
            Settlement(
                rail="xrpl", tx_hash="A", ledger_index=1, close_time="2026-01-02T03:04:05+00:00"
            )

    def test_result_outcome_is_closed(self) -> None:
        with pytest.raises(ReceiptError, match="outcome"):
            Result(outcome="probably_fine")

    def test_balance_deltas_may_be_negative_but_never_floats(self) -> None:
        content = make_leaves().contents()[5]
        assert isinstance(content, dict)
        deltas = content["balance_deltas"]
        assert isinstance(deltas, list) and isinstance(deltas[0], dict)
        assert deltas[0]["value"] == "-250.00"

    def test_reasoning_is_labelled_testimony(self) -> None:
        content = Reasoning(content_hash=digest("trace")).to_content()
        assert content["testimony"] is True

    def test_reasoning_without_the_label_is_rejected(self) -> None:
        with pytest.raises(ReceiptError, match="testimony"):
            Reasoning.from_content({"content_hash": digest("trace")})


def dataclass_replace(obj: Any, **changes: Any) -> Any:
    import dataclasses

    return dataclasses.replace(obj, **changes)
