"""Settlement proofs: what the capture proves, and what it only asserts."""

from __future__ import annotations

import hashlib
import json

import pytest

from merkl.adapters.fake.rail import merkle_root, validator_set
from merkl.core.checks import CheckStatus
from merkl.core.rail import tx_id_from_blob
from merkl.core.vectors.xrpl import XRPL_VECTORS_DIR
from merkl.core.verify.settlement import (
    CHECK_LEDGER_HEADER,
    CHECK_PROOF_MATCHES,
    CHECK_VALIDATOR_QUORUM,
    LEDGER_PROVEN_OFFLINE,
    LEDGER_SUPPLIED_UNVERIFIED,
    LEDGER_UNCHECKED,
    LEDGER_VERIFIED_LIVE,
    ValidatorTrust,
    fake_ledger_hash,
    read_settlement_proof,
    xrpl_ledger_hash,
)
from merkl.core.verify.xrpl import build_tx_path, pin_validator_list

TX = "AA" * 32
LEDGER = 1_000_001


def _fake_proof(*, validators: int = 3, tx_hash: str = TX) -> dict:
    header = {
        "ledger_index": LEDGER,
        "close_time": "2026-01-02T03:04:41Z",
        "transaction_hash": merkle_root([bytes.fromhex(tx_hash)]),
        "transaction_count": 1,
    }
    ledger_hash = fake_ledger_hash(header)
    return {
        "rail": "fake",
        "tx_hash": tx_hash,
        "ledger_index": LEDGER,
        "ledger_hash": ledger_hash,
        "ledger_header": header,
        "tx_path": {"leaf_index": 0, "siblings": [], "directions": []},
        "validations": [v.sign(ledger_hash, LEDGER) for v in validator_set(validators)],
        "captured": ["ledger_header", "transaction", "shamap_path", "validator_signatures"],
        "missing": [],
    }


def _trust(count: int = 3, quorum: int = 2) -> ValidatorTrust:
    return ValidatorTrust(
        validators={v.name: v.public_key for v in validator_set(count)}, quorum=quorum
    )


def _read(proof, **kw):
    return read_settlement_proof(
        proof,
        rail=kw.pop("rail", "fake"),
        tx_hash=kw.pop("tx_hash", TX),
        ledger_index=kw.pop("ledger_index", LEDGER),
        **kw,
    )


class TestNothingSupplied:
    def test_no_proof_is_unchecked_not_a_pass(self) -> None:
        reading = _read(None)
        assert reading.ledger_inclusion == LEDGER_UNCHECKED
        assert all(c.status is CheckStatus.NOT_IMPLEMENTED for c in reading.checks)

    def test_a_live_query_is_weaker_than_a_proof_and_says_so(self) -> None:
        reading = _read(None, live=True)
        assert reading.ledger_inclusion == LEDGER_VERIFIED_LIVE


class TestTheProofIsAboutThisTransaction:
    def test_another_transaction_fails_rather_than_weakening(self) -> None:
        reading = _read(_fake_proof(tx_hash="BB" * 32))
        check = next(c for c in reading.checks if c.name == CHECK_PROOF_MATCHES)
        assert check.status is CheckStatus.FAIL
        assert reading.ledger_inclusion == LEDGER_SUPPLIED_UNVERIFIED

    def test_another_ledger_fails(self) -> None:
        proof = _fake_proof()
        proof["ledger_index"] = LEDGER + 5
        reading = _read(proof)
        assert (
            next(c for c in reading.checks if c.name == CHECK_PROOF_MATCHES).status
            is CheckStatus.FAIL
        )


class TestTheLedgerHeader:
    def test_the_header_hashes_to_the_ledger_hash_it_claims(self) -> None:
        reading = _read(_fake_proof(), trust=_trust())
        assert (
            next(c for c in reading.checks if c.name == CHECK_LEDGER_HEADER).status
            is CheckStatus.PASS
        )

    def test_a_transaction_root_swapped_after_the_fact_is_caught(self) -> None:
        proof = _fake_proof()
        proof["ledger_header"]["transaction_hash"] = "cd" * 32
        reading = _read(proof, trust=_trust())
        assert (
            next(c for c in reading.checks if c.name == CHECK_LEDGER_HEADER).status
            is CheckStatus.FAIL
        )
        assert reading.ledger_inclusion == LEDGER_SUPPLIED_UNVERIFIED

    def test_an_unknown_rail_has_no_rule_and_says_so(self) -> None:
        proof = _fake_proof()
        proof["rail"] = "solana"
        reading = _read(proof, rail="solana")
        assert (
            next(c for c in reading.checks if c.name == CHECK_LEDGER_HEADER).status
            is CheckStatus.NOT_IMPLEMENTED
        )

    def test_the_xrpl_rule_is_the_ledger_header_hash(self) -> None:
        header = {
            "ledger_index": 94211337,
            "total_coins": "99999999999999999",
            "parent_hash": "11" * 32,
            "transaction_hash": "22" * 32,
            "account_hash": "33" * 32,
            "parent_close_time": 792000000,
            "close_time": 792000010,
            "close_time_resolution": 10,
            "close_flags": 0,
        }
        body = (
            bytes.fromhex("4C575200")
            + (94211337).to_bytes(4, "big")
            + (99999999999999999).to_bytes(8, "big")
            + bytes.fromhex("11" * 32)
            + bytes.fromhex("22" * 32)
            + bytes.fromhex("33" * 32)
            + (792000000).to_bytes(4, "big")
            + (792000010).to_bytes(4, "big")
            + bytes([10, 0])
        )
        assert xrpl_ledger_hash(header) == hashlib.sha512(body).digest()[:32].hex()


class TestValidatorQuorum:
    def test_no_pinned_set_means_nothing_is_proved(self) -> None:
        reading = _read(_fake_proof())
        assert (
            next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM).status
            is CheckStatus.NOT_IMPLEMENTED
        )

    def test_a_pinned_quorum_over_signed_validations_passes(self) -> None:
        reading = _read(_fake_proof(), trust=_trust())
        assert (
            next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM).status
            is CheckStatus.PASS
        )
        assert reading.ledger_inclusion == LEDGER_PROVEN_OFFLINE

    def test_a_forged_validation_signature_fails(self) -> None:
        proof = _fake_proof()
        proof["validations"][1]["signature"] = "00" * 64
        reading = _read(proof, trust=_trust())
        assert (
            next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM).status
            is CheckStatus.FAIL
        )

    def test_validators_nobody_pinned_do_not_count(self) -> None:
        trust = ValidatorTrust(validators={"someone-else": "ab" * 32}, quorum=1)
        reading = _read(_fake_proof(), trust=trust)
        check = next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM)
        assert check.status is CheckStatus.FAIL
        assert "0 of 1" in check.detail

    def test_too_few_signatures_for_the_quorum_fails(self) -> None:
        trust = ValidatorTrust(
            validators={v.name: v.public_key for v in validator_set(3)}, quorum=3
        )
        proof = _fake_proof(validators=2)
        reading = _read(proof, trust=trust)
        assert (
            next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM).status
            is CheckStatus.FAIL
        )

    def test_an_unverifiable_capture_counts_agreement_and_says_so(self) -> None:
        """XRPL's stream names validators but does not republish what they signed."""
        header = {
            "ledger_index": LEDGER,
            "total_coins": "99999999999999999",
            "parent_hash": "11" * 32,
            "transaction_hash": "22" * 32,
            "account_hash": "33" * 32,
            "parent_close_time": 792000000,
            "close_time": 792000010,
            "close_time_resolution": 10,
            "close_flags": 0,
        }
        ledger_hash = xrpl_ledger_hash(header)
        proof = {
            "rail": "xrpl",
            "tx_hash": TX,
            "ledger_index": LEDGER,
            "ledger_hash": ledger_hash,
            "ledger_header": header,
            "validations": [{"validation_public_key": "validator-0", "ledger_hash": ledger_hash}],
            "captured": ["ledger_header", "validator_validations"],
            "missing": ["shamap_path"],
        }
        trust = ValidatorTrust(validators={"validator-0": ""}, quorum=1)
        reading = read_settlement_proof(
            proof, rail="xrpl", tx_hash=TX, ledger_index=LEDGER, trust=trust
        )
        check = next(c for c in reading.checks if c.name == CHECK_VALIDATOR_QUORUM)
        assert check.status is CheckStatus.NOT_IMPLEMENTED
        assert "counted, not proved" in check.detail

    def test_a_quorum_larger_than_the_pinned_set_is_a_configuration_error(self) -> None:
        with pytest.raises(ValueError, match="exceeds"):
            ValidatorTrust(validators={"a": "ab" * 32}, quorum=2)


class TestOfflineInclusion:
    def test_a_missing_shamap_path_is_named_not_hidden(self) -> None:
        proof = _fake_proof()
        proof["missing"] = ["shamap_path"]
        proof.pop("tx_path")
        reading = _read(proof, trust=_trust())
        assert reading.ledger_inclusion == LEDGER_SUPPLIED_UNVERIFIED
        assert "shamap_path" in reading.detail

    def test_a_path_that_folds_elsewhere_does_not_prove_inclusion(self) -> None:
        proof = _fake_proof()
        proof["tx_path"] = {"leaf_index": 0, "siblings": ["ee" * 32], "directions": ["right"]}
        reading = _read(proof, trust=_trust())
        assert reading.ledger_inclusion == LEDGER_SUPPLIED_UNVERIFIED

    def test_a_longer_path_folds_the_same_way_the_tree_does(self) -> None:
        others = [bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), bytes.fromhex("33" * 32)]
        leaves = [bytes.fromhex(TX), *others]
        root = merkle_root(leaves)
        sib1 = others[0]
        sib2 = hashlib.sha256(others[1] + others[2]).digest()
        proof = _fake_proof()
        proof["ledger_header"]["transaction_hash"] = root
        proof["ledger_header"]["transaction_count"] = 4
        proof["ledger_hash"] = fake_ledger_hash(proof["ledger_header"])
        proof["validations"] = [v.sign(proof["ledger_hash"], LEDGER) for v in validator_set(3)]
        proof["tx_path"] = {
            "leaf_index": 0,
            "siblings": [sib1.hex(), sib2.hex()],
            "directions": ["right", "right"],
        }
        reading = _read(proof, trust=_trust())
        assert reading.ledger_inclusion == LEDGER_PROVEN_OFFLINE


class TestXrplRealOfflineInclusion:
    """A real XRPL testnet ledger, real validator signatures, a real UNL.

    ``ledger_20537819.json`` is not synthetic: it is ledger 20537819's whole
    binary transaction set and header, and the five validations that ledger
    actually received on the ``validations`` stream, each with the manifest in
    effect for that validator at the time — captured together in one session,
    the same way the XRPL adapter captures a settlement proof. ``fixtures.json``
    carries the real testnet UNL from ``vl.altnet.rippletest.net``. Nothing
    here is faked; this is the mechanism plan D20 asks for, reaching
    ``proven-offline`` against material XRPL itself produced.
    """

    def test_a_real_testnet_ledger_reaches_proven_offline(self) -> None:
        fixture = json.loads((XRPL_VECTORS_DIR / "ledger_20537819.json").read_text())
        unl = json.loads((XRPL_VECTORS_DIR / "fixtures.json").read_text())["unl"]

        items = []
        for tx in fixture["transactions"]:
            tx_id = bytes.fromhex(tx_id_from_blob("xrpl", tx["tx_blob"]) or "")
            items.append((tx_id, bytes.fromhex(tx["tx_blob"]), bytes.fromhex(tx["meta"])))
        target = items[0]
        root_hex, steps = build_tx_path(target[0], items)
        assert root_hex == fixture["header"]["transaction_hash"].lower()

        reading = pin_validator_list(unl)
        trust = ValidatorTrust(validators={m: m for m in reading.masters}, quorum=reading.quorum())

        tx_hash = target[0].hex().upper()
        proof = {
            "rail": "xrpl",
            "tx_hash": tx_hash,
            "ledger_index": fixture["ledger_index"],
            "ledger_hash": fixture["header"]["ledger_hash"],
            "ledger_header": fixture["header"],
            "tx_path": {"tx_blob": target[1].hex(), "tx_meta": target[2].hex(), "steps": steps},
            "validations": fixture["validations"],
            "captured": (
                "ledger_header",
                "validated_transaction_with_metadata",
                "shamap_path",
                "validator_validations",
            ),
            "missing": (),
        }
        result = read_settlement_proof(
            proof, rail="xrpl", tx_hash=tx_hash, ledger_index=fixture["ledger_index"], trust=trust
        )
        assert result.ledger_inclusion == LEDGER_PROVEN_OFFLINE, result.detail
        for check in result.checks:
            assert check.status is CheckStatus.PASS, (check.name, check.detail)

    def test_a_tampered_transaction_root_is_not_proven(self) -> None:
        fixture = json.loads((XRPL_VECTORS_DIR / "ledger_20537819.json").read_text())
        unl = json.loads((XRPL_VECTORS_DIR / "fixtures.json").read_text())["unl"]
        items = []
        for tx in fixture["transactions"]:
            tx_id = bytes.fromhex(tx_id_from_blob("xrpl", tx["tx_blob"]) or "")
            items.append((tx_id, bytes.fromhex(tx["tx_blob"]), bytes.fromhex(tx["meta"])))
        target = items[0]
        _, steps = build_tx_path(target[0], items)
        steps = [dict(s) for s in steps]
        siblings = list(steps[0]["siblings"])
        siblings[0] = "ee" * 32
        steps[0]["siblings"] = siblings

        reading = pin_validator_list(unl)
        trust = ValidatorTrust(validators={m: m for m in reading.masters}, quorum=reading.quorum())
        tx_hash = target[0].hex().upper()
        proof = {
            "rail": "xrpl",
            "tx_hash": tx_hash,
            "ledger_index": fixture["ledger_index"],
            "ledger_hash": fixture["header"]["ledger_hash"],
            "ledger_header": fixture["header"],
            "tx_path": {"tx_blob": target[1].hex(), "tx_meta": target[2].hex(), "steps": steps},
            "validations": fixture["validations"],
            "captured": (),
            "missing": (),
        }
        result = read_settlement_proof(
            proof, rail="xrpl", tx_hash=tx_hash, ledger_index=fixture["ledger_index"], trust=trust
        )
        assert result.ledger_inclusion != LEDGER_PROVEN_OFFLINE
