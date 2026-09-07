"""Generate the committed receipt test vectors.

    python -m merkl.core.vectors.generate            # write the JSON fixtures
    python -m merkl.core.vectors.generate --check     # fail if they are stale

Deterministic by construction: every value is either a literal, a digest of a
literal, or drawn from a :class:`random.Random` seeded with :data:`SEED`. Running
this twice must produce byte-identical files, which is what ``--check`` asserts
in CI.

Output is plain JSON — objects, arrays, strings, integers, booleans, null, with
every hash as lowercase hex. Nothing here is Python-specific, because the same
fixtures have to drive the JavaScript verifier.

This is the one module in ``merkl.core`` that touches the filesystem, and only
when run as a script; importing it does no I/O.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import pathlib
import random
import sys
from collections.abc import Iterable
from typing import Any, cast

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.crypto import tagged
from merkl.core.intent import Amount, Intent, IssuedCurrency, Reference
from merkl.core.leaf import action_leaf, receipt_leaf
from merkl.core.merkle import MerkleProof, MerkleTree
from merkl.core.policy.approvals import (
    ADMIN_APPROVER_ID,
    ApprovalAssertion,
    verify_assertion,
    verify_policy_signature,
    verify_quorum,
)
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    POLICY_TAG,
    AdminCredential,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    HumanTier,
    PolicyDocument,
    ReferenceBinding,
    SignedPolicy,
    Tiers,
    WindowRule,
    unenforceable_rules,
)
from merkl.core.rail import RAIL_FAKE, fake_tx_id, xrpl_tx_id
from merkl.core.receipt import (
    HALF_LEVEL,
    LEAF_NAMES,
    RECEIPT_VERSION,
    BalanceDelta,
    Disclosure,
    Envelope,
    Escalation,
    Instruction,
    PolicyDecision,
    PolicyRule,
    PolicySignature,
    Reasoning,
    Receipt,
    ReceiptLeaves,
    Result,
    SessionLocator,
    Settlement,
    SignerAttestation,
    authorization_commitment,
    escalation_challenge,
    verify_disclosure,
    verify_receipt_structure,
)
from merkl.core.vectors import VECTORS_DIR, fixtures
from merkl.core.verify.receipt import verify_receipt
from merkl.core.verify.settlement import (
    ValidatorTrust,
    fake_ledger_hash,
    xrpl_ledger_hash,
)
from merkl.shared.hashing import SHA256Hash, canonical_bytes

SEED = 20260905
SPEC = "docs/RECEIPT-SPEC.md"

TREASURY = "rTREASURY0000000000000000000000000"
DESTINATION = "rSUPPLIER0000000000000000000000000"
ATTACKER = "rATTACKER0000000000000000000000000"
ISSUER = "rISSUER000000000000000000000000000"
RLUSD = IssuedCurrency(code="RLUSD", issuer=ISSUER)

AGENT_PRIVATE = fixtures.ed25519_key("agent-accounts-payable")
SIGNER_PRIVATE = fixtures.ed25519_key("policy-signer")
AGENT_KEY = fixtures.ed25519_public_hex(AGENT_PRIVATE)
SIGNER_KEY = fixtures.ed25519_public_hex(SIGNER_PRIVATE)

ADMIN_PRIVATE = fixtures.ed25519_key("policy-admin")
ADMIN_KEY = fixtures.ed25519_public_hex(ADMIN_PRIVATE)

VALIDATOR_PRIVATE = tuple(fixtures.ed25519_key(f"fake-validator-{i}") for i in range(3))
VALIDATOR_KEYS = {
    f"validator-{i}": fixtures.ed25519_public_hex(key) for i, key in enumerate(VALIDATOR_PRIVATE)
}

ALICE_PRIVATE = fixtures.ed25519_key("approver-alice")
BOB_PRIVATE = fixtures.ed25519_key("approver-bob")
CAROL_PRIVATE = fixtures.ed25519_key("approver-carol")


def digest(label: str) -> str:
    """A stable stand-in digest derived from a label, not from randomness."""
    return SHA256Hash.from_bytes(label.encode()).hex()


def _blob(rng: random.Random, size: int) -> str:
    return rng.randbytes(size).hex()


def _strings(values: Iterable[str]) -> list[JSONValue]:
    """A JSON array of strings (list invariance makes the comprehension necessary)."""
    return [value for value in values]


def _proof(proof: MerkleProof) -> JSONObject:
    """A proof as plain JSON: hex siblings and their directions."""
    return {
        "siblings": _strings(s.hex() for s in proof.siblings),
        "directions": _strings(proof.directions),
    }


# --------------------------------------------------------------------------- #
# 1. Merkle tree vectors
# --------------------------------------------------------------------------- #


def merkle_vectors() -> JSONObject:
    cases: list[JSONValue] = []
    for count in (1, 2, 3, 4, 5, 7, 8, 16):
        inputs = [f"merkl-vector-leaf-{i}" for i in range(count)]
        leaves = [SHA256Hash.from_bytes(s.encode()) for s in inputs]
        tree = MerkleTree.build(leaves)
        cases.append(
            {
                "name": f"leaves-{count}",
                "leaf_inputs": _strings(inputs),
                "leaf_input_encoding": "utf-8",
                "leaves": [h.hex() for h in leaves],
                "padded_leaves": [h.hex() for h in tree.padded_leaves],
                "depth": tree.depth,
                "levels": [[h.hex() for h in tree.level(i)] for i in range(tree.depth + 1)],
                "root": tree.root.hex(),
                "proofs": [{"index": i, **_proof(tree.get_proof(i))} for i in range(count)],
                "subtree_proofs": [
                    {
                        "index": i,
                        "level": level,
                        "subtree_index": i >> level,
                        "subtree_root": tree.subtree_root(level, i >> level).hex(),
                        **_proof(tree.subtree_proof(i, level)),
                    }
                    for level in range(tree.depth + 1)
                    for i in range(count)
                ],
            }
        )
    return {
        "description": (
            "Merkle trees over SHA-256 leaves. Leaves are padded to the next power "
            "of two by repeating the last leaf; an interior node is "
            "SHA-256(left || right) over raw 32-byte digests. leaf = SHA-256(utf8 "
            "bytes of leaf_input)."
        ),
        "spec": SPEC,
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 2. Action leaf vectors (merkl-leaf-v1, frozen)
# --------------------------------------------------------------------------- #


def action_leaf_vectors() -> JSONObject:
    base: dict[str, Any] = {
        "action_id": "01936b2e-0000-7000-8000-000000000001",
        "session_id": "01936b2e-1111-7000-8000-000000000001",
        "action_type": "transaction",
        "tool_name": "submit_payment",
        "input_hash": digest("action input"),
        "output_hash": digest("action output"),
        "timestamp": "2026-01-02T03:04:05+00:00",
        "drift_score": "0.25",
        "guardrail_result": "passed",
        "display_name": "Submit payment",
        "depends_on": ["01936b2e-0000-7000-8000-000000000000"],
        "status": "success",
        "category": "payments",
    }
    variants: list[tuple[str, dict[str, Any]]] = [
        ("baseline", {}),
        ("empty-optional-fields", {"display_name": "", "depends_on": [], "category": ""}),
        ("depends-on-unsorted", {"depends_on": ["zzz", "aaa", "mmm"]}),
        ("drift-zero", {"drift_score": "0.0"}),
        ("drift-one", {"drift_score": "1.0"}),
        ("drift-exponent", {"drift_score": "1e-05"}),
        ("timestamp-microseconds", {"timestamp": "2026-01-02T03:04:05.678901+00:00"}),
        ("unicode-tool-name", {"tool_name": "café ☕ — 日本語", "display_name": "支払い"}),
        ("blocked-guardrail", {"guardrail_result": "blocked", "status": "blocked"}),
        ("human-input", {"action_type": "human_input", "tool_name": ""}),
    ]
    cases: list[JSONValue] = []
    for name, overrides in variants:
        fields = {**base, **overrides}
        cases.append({"name": name, "fields": fields, "leaf": action_leaf(**fields).hex()})
    return {
        "description": (
            "merkl-leaf-v1 action leaves. leaf = SHA-256('merkl-leaf-v1' || NUL || "
            "action_id || NUL || session_id || NUL || action_type || NUL || tool_name "
            "|| NUL || input_hash || NUL || output_hash || NUL || timestamp || NUL || "
            "drift_score || NUL || guardrail_result || NUL || display_name || NUL || "
            "depends_on (sorted, comma-joined) || NUL || status || NUL || category). "
            "drift_score is the exact string, never a re-rendered number."
        ),
        "tag": "merkl-leaf-v1",
        "spec": "merkl-api/docs/SPEC.md section 2",
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 3. Receipt leaf vectors (merkl-receipt-leaf-v1)
# --------------------------------------------------------------------------- #


def receipt_leaf_vectors() -> JSONObject:
    cases: list[JSONValue] = []
    for name in LEAF_NAMES:
        cases.append(
            {
                "name": f"null-{name}",
                "leaf_name": name,
                "content": None,
                "leaf": receipt_leaf(name, None).hex(),
            }
        )
    extra: list[tuple[str, str, JSONValue]] = [
        ("empty-object", "result", {}),
        ("empty-array-member", "policy_decision", {"rules": []}),
        ("key-order-a", "result", {"a": "1", "b": "2"}),
        ("key-order-b", "result", {"b": "2", "a": "1"}),
        ("unicode", "reasoning", {"note": "café ☕ — 日本語 — naïve", "testimony": True}),
        ("nested", "settlement", {"a": [1, [2, [3, {"b": None}]]], "c": {"d": {"e": "f"}}}),
        ("booleans-and-null", "instruction", {"t": True, "f": False, "n": None}),
        ("large-safe-integer", "settlement", {"ledger_index": 9007199254740991}),
        ("negative-integer", "result", {"delta": -42}),
        ("string-that-looks-numeric", "result", {"value": "250.00"}),
        ("scalar-string", "reasoning", "plain string content"),
        ("scalar-integer", "reasoning", 7),
        ("scalar-true", "reasoning", True),
        ("empty-string", "reasoning", ""),
    ]
    for name, leaf_name, content in extra:
        cases.append(
            {
                "name": name,
                "leaf_name": leaf_name,
                "content": content,
                "leaf": receipt_leaf(leaf_name, content).hex(),
            }
        )
    return {
        "description": (
            "merkl-receipt-leaf-v1 leaves. leaf = SHA-256('merkl-receipt-leaf-v1' || "
            "NUL || leaf_name || NUL || canonical_bytes(content)), where "
            "canonical_bytes is JSON with sorted keys, ',' and ':' separators and "
            "non-ASCII escaped as \\uXXXX. Absent content is the literal null. "
            "key-order-a and key-order-b must produce the same leaf."
        ),
        "tag": "merkl-receipt-leaf-v1",
        "spec": SPEC,
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 4. Approval assertions
# --------------------------------------------------------------------------- #


def _assertion_case(
    name: str,
    description: str,
    credential: ApproverCredential,
    assertion: ApprovalAssertion,
    challenge: bytes,
    expected_valid: bool,
) -> JSONObject:
    check = verify_assertion(assertion, challenge, credential)
    if check.valid is not expected_valid:
        raise AssertionError(
            f"{name}: expected valid={expected_valid}, verifier said "
            f"{check.valid} ({check.detail})"
        )
    return {
        "name": name,
        "description": description,
        "challenge": challenge.hex(),
        "credential": credential.to_content(),
        "assertion": assertion.to_content(),
        "expected_valid": expected_valid,
    }


def approval_vectors() -> JSONObject:
    """Approvals over an escalation challenge: WebAuthn and Ed25519, good and bad."""
    fixtures.check_webauthn_fixture()
    challenge = fixtures.WEBAUTHN_CHALLENGE
    other = SHA256Hash.from_bytes(b"a challenge from another escalation").bytes
    passkey = fixtures.webauthn_credential()
    good = fixtures.webauthn_assertion()

    cases: list[JSONValue] = [
        _assertion_case(
            "webauthn-valid",
            "A passkey assertion over the challenge. The signature covers "
            "authenticatorData || SHA-256(clientDataJSON); clientDataJSON is carried "
            "as the exact bytes, hex-encoded, because re-serializing it would break "
            "the signature.",
            passkey,
            good,
            challenge,
            True,
        ),
        _assertion_case(
            "webauthn-wrong-challenge",
            "The same assertion checked against a different escalation. An approval "
            "harvested from one payment must not authorize another.",
            passkey,
            good,
            other,
            False,
        ),
        _assertion_case(
            "webauthn-origin-not-allowed",
            "The credential allows only https://app.merkl.ai; the assertion came "
            "from a page pretending to be it.",
            dataclasses.replace(passkey, origins=("https://console.example.com",)),
            good,
            challenge,
            False,
        ),
        _assertion_case(
            "webauthn-rp-id-mismatch",
            "rpIdHash does not match the relying party in the policy.",
            dataclasses.replace(passkey, rp_id="evil.example.com", origins=()),
            good,
            challenge,
            False,
        ),
        _assertion_case(
            "webauthn-user-present-flag-clear",
            "Flags say nobody touched the authenticator. Rejected before the "
            "signature is even considered.",
            passkey,
            dataclasses.replace(
                good,
                authenticator_data=fixtures.authenticator_data(
                    fixtures.WEBAUTHN_RP_ID, flags=0x00
                ).hex(),
            ),
            challenge,
            False,
        ),
        _assertion_case(
            "webauthn-user-verification-required-but-absent",
            "The policy requires a verified user (PIN or biometric) and only "
            "user-presence was asserted.",
            passkey,
            dataclasses.replace(
                good,
                authenticator_data=fixtures.authenticator_data(
                    fixtures.WEBAUTHN_RP_ID, flags=0x01
                ).hex(),
            ),
            challenge,
            False,
        ),
    ]

    ed_credential = ApproverCredential(
        id="bob@example.com",
        credential_type="ed25519",
        public_key=fixtures.ed25519_public_hex(BOB_PRIVATE),
    )
    ed_assertion = fixtures.ed25519_assertion(
        approver_id="bob@example.com",
        key=BOB_PRIVATE,
        challenge=challenge,
        signed_at="2026-01-02T03:22:47Z",
    )
    cases.extend(
        [
            _assertion_case(
                "ed25519-valid",
                "An Ed25519 approval signs the raw 32-byte challenge, with no envelope around it.",
                ed_credential,
                ed_assertion,
                challenge,
                True,
            ),
            _assertion_case(
                "ed25519-wrong-challenge",
                "The same signature against a different escalation.",
                ed_credential,
                ed_assertion,
                other,
                False,
            ),
            _assertion_case(
                "ed25519-signed-by-someone-else",
                "Carol signed, but the assertion claims Bob's credential.",
                ed_credential,
                fixtures.ed25519_assertion(
                    approver_id="bob@example.com",
                    key=CAROL_PRIVATE,
                    challenge=challenge,
                    signed_at="2026-01-02T03:22:47Z",
                ),
                challenge,
                False,
            ),
            _assertion_case(
                "credential-type-disagrees-with-the-policy",
                "The policy registers this approver as a passkey; the assertion "
                "arrives as a bare Ed25519 signature.",
                passkey,
                ed_assertion,
                challenge,
                False,
            ),
        ]
    )

    alice = ApproverCredential(
        id="alice@example.com",
        credential_type="ed25519",
        public_key=fixtures.ed25519_public_hex(ALICE_PRIVATE),
    )
    carol = ApproverCredential(
        id="carol@example.com",
        credential_type="ed25519",
        public_key=fixtures.ed25519_public_hex(CAROL_PRIVATE),
    )
    approvers = (alice, ed_credential, carol)

    def signed(approver_id: str, key: Any, at: str) -> ApprovalAssertion:
        return fixtures.ed25519_assertion(
            approver_id=approver_id, key=key, challenge=challenge, signed_at=at
        )

    alice_ok = signed("alice@example.com", ALICE_PRIVATE, "2026-01-02T03:20:11Z")
    bob_ok = signed("bob@example.com", BOB_PRIVATE, "2026-01-02T03:22:47Z")
    carol_bad = signed("carol@example.com", ALICE_PRIVATE, "2026-01-02T03:23:02Z")
    stranger = signed("mallory@example.com", CAROL_PRIVATE, "2026-01-02T03:23:40Z")

    quorum_inputs: list[tuple[str, str, list[ApprovalAssertion], int, bool, list[str]]] = [
        (
            "two-of-three-reached",
            "Two of the three named approvers signed. Quorum met.",
            [alice_ok, bob_ok],
            2,
            True,
            ["alice@example.com", "bob@example.com"],
        ),
        (
            "same-approver-twice-is-one-approval",
            "One person signing twice is one approval, not two. Distinct approver "
            "ids are the whole point of a quorum.",
            [alice_ok, alice_ok],
            2,
            False,
            ["alice@example.com"],
        ),
        (
            "invalid-signature-does-not-count",
            "Carol's assertion was signed with Alice's key, so it counts for nobody.",
            [alice_ok, carol_bad],
            2,
            False,
            ["alice@example.com"],
        ),
        (
            "unknown-approver-does-not-count",
            "Someone the policy never named signed. A valid signature by a stranger "
            "is still a stranger.",
            [alice_ok, stranger],
            2,
            False,
            ["alice@example.com"],
        ),
    ]

    quorum_cases: list[JSONValue] = []
    for name, description, assertions, quorum, reached, accepted in quorum_inputs:
        result = verify_quorum(assertions, challenge, approvers, quorum)
        if result.reached is not reached or list(result.accepted) != accepted:
            raise AssertionError(
                f"{name}: expected reached={reached} accepted={accepted}, got "
                f"reached={result.reached} accepted={list(result.accepted)}"
            )
        quorum_cases.append(
            {
                "name": name,
                "description": description,
                "challenge": challenge.hex(),
                "approvers": [a.to_content() for a in approvers],
                "assertions": [a.to_content() for a in assertions],
                "quorum": quorum,
                "expected_reached": reached,
                "expected_accepted": _strings(accepted),
            }
        )

    return {
        "description": (
            "Approval assertions over an escalation challenge. The challenge is "
            "LEFT_pre, 32 raw bytes. An ed25519 approval signs those bytes directly. "
            "A webauthn approval signs authenticator_data || SHA-256(client_data_json), "
            "where both are carried as hex of the exact bytes the browser produced; "
            "the challenge inside clientDataJSON is base64url, as WebAuthn requires. "
            "Quorum counts distinct approver ids."
        ),
        "spec": SPEC,
        "webauthn_message": (
            "authenticator_data || SHA-256(client_data_json), ECDSA P-256 with SHA-256, "
            "DER signature, uncompressed SEC1 public key"
        ),
        "cases": cases,
        "quorum_cases": quorum_cases,
    }


# --------------------------------------------------------------------------- #
# 3b. Policy signatures — Ed25519 (legacy and assertion-shaped) and WebAuthn admins
# --------------------------------------------------------------------------- #


def _policy_signature_case(
    name: str,
    description: str,
    signed: SignedPolicy,
    *,
    admin_public_key: str | None = None,
    admin: AdminCredential | None = None,
    expected_valid: bool,
) -> JSONObject:
    valid = verify_policy_signature(signed, admin_public_key=admin_public_key, admin=admin)
    if valid is not expected_valid:
        raise AssertionError(f"{name}: expected valid={expected_valid}, verifier said {valid}")
    case: JSONObject = {
        "name": name,
        "description": description,
        "signed_policy": signed.to_content(),
        "expected_valid": expected_valid,
    }
    if admin_public_key is not None:
        case["pinned_admin_public_key"] = admin_public_key
    if admin is not None:
        case["pinned_admin"] = admin.to_content()
    return case


def _rule_check_document() -> PolicyDocument:
    """A small, wholly enforceable document: one agent, one cap, one window, one tier.

    Every ``document_cases`` entry is this document with one rule appended, so the
    finding is always the appended rule and never something else about the shape.
    """
    rlusd = IssuedCurrency(code="RLUSD", issuer=fixtures.ADMIN_VECTOR_ISSUER)
    return PolicyDocument(
        version="2026.03.0",
        treasury=fixtures.ADMIN_VECTOR_TREASURY,
        rail="xrpl",
        admin_public_key=fixtures.ed25519_public_hex(
            fixtures.ed25519_key("admin-vector-legacy-admin")
        ),
        agents=(
            AgentSection(
                agent_id="agent-admin-vector",
                public_key=fixtures.ed25519_public_hex(fixtures.ed25519_key("admin-vector-agent")),
                allowlist_destinations=(fixtures.ADMIN_VECTOR_DESTINATION,),
                allowlist_assets=(rlusd,),
                per_tx_cap=(AssetLimit(asset=rlusd, amount="500.00"),),
                windows=(WindowRule(asset=rlusd, amount="2000.00", seconds=86400),),
            ),
        ),
        tiers=Tiers(human=HumanTier(thresholds=(AssetLimit(asset=rlusd, amount="250.00"),))),
    )


def _document_case(
    name: str,
    description: str,
    content: JSONObject,
    *,
    expected_findings: list[str],
) -> JSONObject:
    """One policy document, signed by a real admin key, and what it cannot enforce.

    The signature is made over the *mutated* content, so every case here is a
    document whose admin signature verifies and whose ``policy_hash`` matches —
    the rule is dead anyway. A verifier that only checked the signature would
    report nothing wrong.
    """
    findings = unenforceable_rules(content)
    if findings != expected_findings:
        raise AssertionError(f"{name}: expected {expected_findings}, the checker said {findings}")
    admin = fixtures.ed25519_key("admin-vector-legacy-admin")
    pre_image = tagged(POLICY_TAG, canonical_bytes(content))
    return {
        "name": name,
        "description": description,
        "signed_policy": {
            "document": content,
            "signature": admin.sign(pre_image).hex(),
            "signer_public_key": fixtures.ed25519_public_hex(admin),
        },
        "policy_hash": SHA256Hash.from_bytes(pre_image).hex(),
        "expected_findings": list(expected_findings),
    }


def _rule_check_cases() -> list[JSONValue]:
    """Documents whose rules the engine would never run (the phase-9 finding).

    ``per_tx_cap`` and ``tiers.human.thresholds`` are read first-match-per-asset
    and ``windows`` all-matches-per-asset, so a duplicate is signed and ignored.
    A limit for an asset outside the agent's ``allowlist_assets`` is the same
    problem from the other end: the asset rule denies first, so the limit never
    runs. Both implementations must refuse to construct such a document and must
    report the same sentence when one arrives already signed.
    """
    base = _rule_check_document().to_content()
    agent_id = "agent-admin-vector"
    asset: JSONObject = {"code": "RLUSD", "issuer": fixtures.ADMIN_VECTOR_ISSUER}
    xrp_cap: JSONObject = {"asset": "XRP", "amount": "1.00"}
    xrp_window: JSONObject = {"asset": "XRP", "amount": "5.00", "seconds": 3600}

    def with_agent_rule(field: str, rule: JSONObject) -> JSONObject:
        """A copy of the base document with one more rule on its only agent."""
        content: JSONObject = copy.deepcopy(base)
        agent = cast(dict[str, Any], cast(list[Any], content["agents"])[0])
        cast(list[Any], agent[field]).append(rule)
        return content

    def with_threshold(rule: JSONObject) -> JSONObject:
        """A copy of the base document with one more human-approval threshold."""
        content: JSONObject = copy.deepcopy(base)
        human = cast(dict[str, Any], cast(dict[str, Any], content["tiers"])["human"])
        cast(list[Any], human["thresholds"]).append(rule)
        return content

    duplicate_cap = with_agent_rule("per_tx_cap", {"asset": asset, "amount": "100.00"})
    foreign_cap = with_agent_rule("per_tx_cap", xrp_cap)
    duplicate_window = with_agent_rule(
        "windows", {"asset": asset, "amount": "100.00", "seconds": 86400}
    )
    second_window = with_agent_rule(
        "windows", {"asset": asset, "amount": "100.00", "seconds": 3600}
    )
    foreign_window = with_agent_rule("windows", xrp_window)
    duplicate_threshold = with_threshold({"asset": asset, "amount": "10.00"})
    foreign_threshold = with_threshold({"asset": "XRP", "amount": "10.00"})

    return [
        _document_case(
            "enforceable-document",
            "The base document every case below is a copy of: one cap, one window "
            "and one threshold, all for the one asset the agent may move.",
            base,
            expected_findings=[],
        ),
        _document_case(
            "two-windows-different-lengths-are-both-enforced",
            "A second window over the same asset but a different length is not a "
            "duplicate — the engine runs every window that matches the asset, so "
            "both an hourly and a daily limit apply. This case exists to stop the "
            "duplicate check from being over-eager.",
            second_window,
            expected_findings=[],
        ),
        _document_case(
            "duplicate-per-tx-cap",
            "An operator 'tightens' a cap by appending a second one for the same "
            "asset. The admin signs it, policy_hash covers it, and the engine "
            "takes the first cap only — so the payment the tighter number was "
            "meant to stop still settles.",
            duplicate_cap,
            expected_findings=[
                f"agent {agent_id!r} names more than one per_tx_cap for "
                f"RLUSD.{fixtures.ADMIN_VECTOR_ISSUER}; the engine enforces the first, so "
                "the rest cannot be enforced"
            ],
        ),
        _document_case(
            "per-tx-cap-for-an-asset-the-agent-may-not-move",
            "A cap for XRP on an agent whose allowlist_assets is RLUSD only. The "
            "asset rule denies XRP before the cap is ever consulted, so the cap "
            "reads as a limit and is a decoration.",
            foreign_cap,
            expected_findings=[
                f"agent {agent_id!r} has a per_tx_cap for XRP, which is not in its "
                "allowlist_assets, so that cap cannot be enforced"
            ],
        ),
        _document_case(
            "duplicate-window",
            "Two windows over the same asset and the same length. The engine "
            "evaluates both, so the pair is not silently ignored the way a "
            "duplicate cap is — but nothing says which of two contradictory "
            "limits an operator meant, and the receipt would carry two "
            "window_cap rules for one asset.",
            duplicate_window,
            expected_findings=[
                f"agent {agent_id!r} names more than one window for "
                f"RLUSD.{fixtures.ADMIN_VECTOR_ISSUER} over 86400s; the engine enforces one "
                "per (asset, seconds), so the rest cannot be enforced"
            ],
        ),
        _document_case(
            "window-for-an-asset-the-agent-may-not-move",
            "A rolling limit on an asset the agent's allowlist_assets does not "
            "name. Same shape as the foreign cap: the asset rule fires first.",
            foreign_window,
            expected_findings=[
                f"agent {agent_id!r} has a window for XRP, which is not in its "
                "allowlist_assets, so that window cannot be enforced"
            ],
        ),
        _document_case(
            "duplicate-human-threshold",
            "Two human-approval thresholds for one asset. tiers.human.threshold_for "
            "returns the first match, so a lower second threshold never escalates "
            "anything — the payment that should have gone to people settles instantly.",
            duplicate_threshold,
            expected_findings=[
                "tiers.human.thresholds names more than one threshold for "
                f"RLUSD.{fixtures.ADMIN_VECTOR_ISSUER}; the engine enforces the first, so "
                "the rest cannot be enforced"
            ],
        ),
        _document_case(
            "human-threshold-for-an-asset-nobody-may-move",
            "An escalation threshold for an asset no agent in the document is "
            "allowed to move at all. Nothing can ever reach it.",
            foreign_threshold,
            expected_findings=[
                "tiers.human.thresholds has a threshold for XRP, which no agent in this "
                "policy may move, so that threshold cannot be enforced"
            ],
        ),
    ]


def policy_vectors() -> JSONObject:
    """Admin signatures over a policy document (plan D16, extended).

    Two wire shapes name the same thing: a raw Ed25519 signature over the
    tagged pre-image (legacy, ``admin_public_key``), or an
    ``ApprovalAssertion`` — Ed25519 or WebAuthn — over the 32-byte
    ``policy_hash`` (``admin``). One verification function checks both, and it
    is the same one an approver's assertion goes through.
    """
    fixtures.check_admin_webauthn_fixture()
    legacy_admin = fixtures.ed25519_key("admin-vector-legacy-admin")
    legacy_admin_key = fixtures.ed25519_public_hex(legacy_admin)
    rogue_admin = fixtures.ed25519_key("admin-vector-rogue-admin")
    rogue_admin_key = fixtures.ed25519_public_hex(rogue_admin)
    new_admin = fixtures.ed25519_key("admin-vector-new-admin")
    new_admin_key = fixtures.ed25519_public_hex(new_admin)

    legacy_document = fixtures.admin_test_document(admin_public_key=legacy_admin_key)
    legacy_signed = SignedPolicy(
        document=legacy_document,
        signature=legacy_admin.sign(legacy_document.pre_image()).hex(),
        signer_public_key=legacy_admin_key,
    )

    rogue_document = fixtures.admin_test_document(admin_public_key=rogue_admin_key)
    rogue_signed = SignedPolicy(
        document=rogue_document,
        signature=rogue_admin.sign(rogue_document.pre_image()).hex(),
        signer_public_key=rogue_admin_key,
    )

    edited_document = fixtures.admin_test_document(
        admin_public_key=legacy_admin_key, version="2026.02.1"
    )
    edited_signed = dataclasses.replace(legacy_signed, document=edited_document)

    ed25519_admin_credential = AdminCredential(
        credential_type=CREDENTIAL_ED25519, public_key=new_admin_key
    )
    ed25519_admin_document = fixtures.admin_test_document(
        admin_public_key=None, admin=ed25519_admin_credential
    )
    ed25519_admin_digest = bytes.fromhex(ed25519_admin_document.policy_hash())
    ed25519_admin_assertion = ApprovalAssertion(
        approver_id=ADMIN_APPROVER_ID,
        credential_type=CREDENTIAL_ED25519,
        signature=new_admin.sign(ed25519_admin_digest).hex(),
        signed_at="2026-02-01T09:05:00Z",
    )
    ed25519_admin_signed = SignedPolicy(
        document=ed25519_admin_document,
        signature=ed25519_admin_assertion.to_content(),
        signer_public_key=new_admin_key,
    )

    webauthn_document = fixtures.admin_webauthn_document()
    webauthn_credential = fixtures.admin_webauthn_credential()
    webauthn_assertion = fixtures.admin_webauthn_assertion()
    webauthn_signed = SignedPolicy(
        document=webauthn_document,
        signature=webauthn_assertion.to_content(),
        signer_public_key=webauthn_credential.public_key,
    )

    webauthn_edited_document = fixtures.admin_test_document(
        admin_public_key=None, admin=webauthn_credential, version="2026.02.1"
    )
    webauthn_edited_signed = dataclasses.replace(
        webauthn_signed, document=webauthn_edited_document
    )

    misnamed_assertion = dataclasses.replace(ed25519_admin_assertion, approver_id="mallory")
    misnamed_signed = SignedPolicy(
        document=ed25519_admin_document,
        signature=misnamed_assertion.to_content(),
        signer_public_key=new_admin_key,
    )

    cases: list[JSONValue] = [
        _policy_signature_case(
            "legacy-ed25519-valid",
            "The legacy scheme: a raw Ed25519 signature over the tagged pre-image, "
            "pinned to the admin key the operator actually trusts.",
            legacy_signed,
            admin_public_key=legacy_admin_key,
            expected_valid=True,
        ),
        _policy_signature_case(
            "legacy-ed25519-unpinned-trusts-the-document",
            "With no admin pinned, the document's own admin_public_key is trusted — "
            "the same thing an unpinned check has always done.",
            legacy_signed,
            expected_valid=True,
        ),
        _policy_signature_case(
            "wrong-admin",
            "A rogue document nominates its own admin and signs itself; the operator "
            "pins the real admin key instead. This is the whole point of pinning.",
            rogue_signed,
            admin_public_key=legacy_admin_key,
            expected_valid=False,
        ),
        _policy_signature_case(
            "edited-rule-after-signing",
            "The signature and signer_public_key are untouched, but the document "
            "attached to them was edited after signing (the per-tx cap's version "
            "bumped). The pre-image no longer matches what was actually signed.",
            edited_signed,
            admin_public_key=legacy_admin_key,
            expected_valid=False,
        ),
        _policy_signature_case(
            "ed25519-assertion-admin-valid",
            "The newer wire shape: an ApprovalAssertion carrying a plain Ed25519 "
            "signature over policy_hash, not the legacy pre-image scheme — the same "
            "shape a WebAuthn admin's ceremony produces, just signed differently.",
            ed25519_admin_signed,
            admin=ed25519_admin_credential,
            expected_valid=True,
        ),
        _policy_signature_case(
            "webauthn-admin-valid",
            "An org signs a policy change with a WebAuthn admin credential from the "
            "dashboard. The challenge is the 32-byte policy_hash, checked exactly the "
            "way an approver's assertion is checked.",
            webauthn_signed,
            admin=webauthn_credential,
            expected_valid=True,
        ),
        _policy_signature_case(
            "webauthn-origin-not-allowed",
            "The same valid assertion, but the operator pins an admin credential "
            "whose allowed origins do not include the one clientDataJSON names — "
            "a signature harvested from a phishing page must not count.",
            webauthn_signed,
            admin=dataclasses.replace(webauthn_credential, origins=("https://evil.example.com",)),
            expected_valid=False,
        ),
        _policy_signature_case(
            "webauthn-edited-rule-after-signing",
            "Same admin, same assertion, but the document was edited after signing: "
            "policy_hash no longer matches the challenge the passkey actually signed.",
            webauthn_edited_signed,
            admin=webauthn_credential,
            expected_valid=False,
        ),
        _policy_signature_case(
            "assertion-does-not-name-the-admin-role",
            "An otherwise-valid-looking assertion whose approver_id is not 'admin' — "
            "the fixed role every admin assertion must name.",
            misnamed_signed,
            admin=ed25519_admin_credential,
            expected_valid=False,
        ),
    ]

    return {
        "description": (
            "SignedPolicy admin signatures: the legacy raw Ed25519 signature over "
            "the tagged pre-image, and the newer ApprovalAssertion-shaped signature "
            "(Ed25519 or WebAuthn) over the 32-byte policy_hash. verify_policy_signature "
            "checks both; the legacy form's policy_hash is byte-identical to every "
            "policy signed before this shape existed."
        ),
        "spec": SPEC,
        "admin_challenge": "the 32-byte policy_hash, not the legacy pre-image and not LEFT_pre",
        "cases": cases,
        "document_rules": (
            "A document may only carry rules the engine would actually run: one "
            "per_tx_cap per asset per agent, one window per (asset, seconds) per "
            "agent, one tiers.human threshold per asset, and no cap, window or "
            "threshold for an asset nobody may move. Construction refuses such a "
            "document; a verifier handed one already signed reports the same "
            "sentence as a finding, because the admin signature and the "
            "policy_hash are both perfectly valid over a rule that is dead."
        ),
        "document_cases": _rule_check_cases(),
    }


# --------------------------------------------------------------------------- #
# 4. Full receipts
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# The policy the receipts were decided under
# --------------------------------------------------------------------------- #


def _policy_document() -> PolicyDocument:
    """The document whose hash every receipt in these vectors names.

    Real, not a placeholder: ``policy.document`` looks the policy up **by hash**,
    so a fixture whose policy_hash was a digest of a sentence could never exercise
    that check. Publishing the document is also what makes the escalated receipt
    checkable by a stranger — the approver keys are in here, and without them
    "two people signed" is a claim rather than a finding.
    """
    return PolicyDocument(
        version="2026.01.0",
        treasury=TREASURY,
        rail="xrpl",
        admin_public_key=ADMIN_KEY,
        agents=(
            AgentSection(
                agent_id="agent-accounts-payable",
                public_key=AGENT_KEY,
                allowlist_destinations=(DESTINATION,),
                allowlist_assets=(RLUSD,),
                per_tx_cap=(AssetLimit(asset=RLUSD, amount="10000.00"),),
                windows=(WindowRule(asset=RLUSD, amount="20000.00", seconds=86400),),
                reference_binding=ReferenceBinding(
                    required=True, allowed_kinds=("invoice", "contract")
                ),
            ),
        ),
        tiers=Tiers(
            human=HumanTier(
                thresholds=(AssetLimit(asset=RLUSD, amount="1000.00"),),
                quorum=2,
                expires_seconds=3600,
            )
        ),
        approvers=(
            ApproverCredential(
                id="alice@example.com",
                credential_type="ed25519",
                public_key=fixtures.ed25519_public_hex(ALICE_PRIVATE),
            ),
            ApproverCredential(
                id="bob@example.com",
                credential_type="ed25519",
                public_key=fixtures.ed25519_public_hex(BOB_PRIVATE),
            ),
            ApproverCredential(
                id="carol@example.com",
                credential_type="ed25519",
                public_key=fixtures.ed25519_public_hex(CAROL_PRIVATE),
            ),
        ),
    )


POLICY = _policy_document()
POLICY_HASH = POLICY.policy_hash()
SIGNED_POLICY = SignedPolicy(
    document=POLICY,
    signer_public_key=ADMIN_KEY,
    signature=ADMIN_PRIVATE.sign(POLICY.pre_image()).hex(),
)


def _intent(**overrides: Any) -> Intent:
    fields: dict[str, Any] = {
        "rail": "xrpl",
        "treasury": TREASURY,
        "destination": DESTINATION,
        "amount": Amount(value="250.00", currency=RLUSD),
        "policy_version": "2026.01.0",
        "agent_public_key": AGENT_KEY,
        "nonce": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "expires_at": "2026-01-02T03:09:05Z",
        "reference": Reference(kind="invoice", id="INV-2026-0042", hash=digest("invoice pdf")),
    }
    fields.update(overrides)
    return Intent(**fields)


def _authorization(
    instruction: Instruction,
    intent: Intent,
    decision: PolicyDecision,
    attestation: SignerAttestation | None,
) -> ReceiptLeaves:
    return ReceiptLeaves(
        instruction=instruction,
        intent=intent,
        policy_decision=decision,
        signer_attestation=attestation,
    )


def _settlement(
    rng: random.Random,
    left: SHA256Hash,
    *,
    ledger_index: int,
    close_time: str,
    proof_ref: str,
) -> Settlement:
    """Leaf 4, bound to the LEFT that authorized it.

    The blob carries LEFT because the real transaction does (the memo *is* LEFT),
    the transaction hash is derived from the blob the way rippled derives it, and
    the policy signature is a real Ed25519 signature over a payload containing
    LEFT. Every one of those three is a check a verifier runs, so a plausible-
    looking fixture would be a fixture that fails.
    """
    payload = bytes.fromhex(_blob(rng, 40)) + left.bytes + bytes.fromhex(_blob(rng, 20))
    blob_bytes = bytes.fromhex("12000022") + left.bytes + bytes.fromhex(_blob(rng, 60))
    return Settlement(
        rail="xrpl",
        tx_hash=xrpl_tx_id(blob_bytes),
        ledger_index=ledger_index,
        close_time=close_time,
        signed_tx_blob=blob_bytes.hex(),
        observed_anchor=left.hex(),
        settlement_proof_ref=proof_ref,
        policy_signature=PolicySignature(
            algorithm="ed25519",
            public_key=SIGNER_KEY,
            signature=SIGNER_PRIVATE.sign(payload).hex(),
            payload=payload.hex(),
        ),
    )


def _allow_receipt(rng: random.Random) -> Receipt:
    instruction = Instruction(
        source="human_input",
        content_hash=digest("pay invoice INV-2026-0042"),
        ref="01936b2e-3333-7000-8000-000000000001",
    )
    intent = _intent()
    decision = PolicyDecision(
        policy_hash=POLICY_HASH,
        rules=(
            PolicyRule("destination_allowlist", "pass", "rSUPPLIER is on the allowlist"),
            PolicyRule("per_tx_cap", "pass", "250.00 RLUSD is under the 1000 RLUSD cap"),
            PolicyRule("daily_cap", "pass", "1250.00 of 5000 RLUSD used today"),
            PolicyRule("reference_required", "pass", "invoice INV-2026-0042 supplied"),
        ),
        outcome="allow",
        tier="instant",
    )
    attestation = SignerAttestation(
        document=_blob(rng, 96), policy_public_key=SIGNER_KEY, format="aws-nitro"
    )
    left = authorization_commitment(_authorization(instruction, intent, decision, attestation))
    leaves = ReceiptLeaves(
        instruction=instruction,
        intent=intent,
        policy_decision=decision,
        signer_attestation=attestation,
        settlement=_settlement(
            rng,
            left,
            ledger_index=94_211_337,
            close_time="2026-01-02T03:04:41Z",
            proof_ref="settlement-proof-0001",
        ),
        result=Result(
            outcome="settled",
            engine_result="tesSUCCESS",
            balance_deltas=(
                BalanceDelta(TREASURY, RLUSD, "-250.00"),
                BalanceDelta(DESTINATION, RLUSD, "250.00"),
            ),
            outcome_hash=digest("raw xrpl tx result"),
        ),
        reasoning=Reasoning(
            content_hash=digest("model trace for INV-2026-0042"),
            source="claude-code",
            note="Invoice matched the supplier on file; amount under the per-transaction cap.",
        ),
    )
    return Receipt.build(
        receipt_id="01936b2e-2222-7000-8000-000000000001",
        leaves=leaves,
        agent_id="agent-accounts-payable",
        signer_public_key=SIGNER_KEY,
        session_locator=SessionLocator(
            session_id="01936b2e-1111-7000-8000-000000000001", leaf_index=7
        ),
    )


def _deny_receipt(rng: random.Random) -> Receipt:
    leaves = ReceiptLeaves(
        instruction=Instruction(
            source="mandate",
            content_hash=digest("standing mandate: pay supplier invoices"),
            signature=_blob(rng, 64),
        ),
        intent=_intent(
            destination=ATTACKER,
            amount=Amount(value="9000.00", currency=RLUSD),
            nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            reference=None,
        ),
        policy_decision=PolicyDecision(
            policy_hash=POLICY_HASH,
            rules=(
                PolicyRule("destination_allowlist", "fail", "rATTACKER is not on the allowlist"),
                PolicyRule("per_tx_cap", "fail", "9000.00 RLUSD is over the 1000 RLUSD cap"),
                PolicyRule("reference_required", "fail", "no invoice supplied"),
            ),
            outcome="deny",
            tier="instant",
        ),
        signer_attestation=None,
        settlement=None,
        result=Result(
            outcome="denied",
            detail="Denied by policy; nothing was submitted to the rail.",
        ),
        reasoning=Reasoning(
            content_hash=digest("model trace for the denied payment"),
            source="claude-code",
            note="The instruction arrived inside retrieved content, not from the operator.",
        ),
    )
    return Receipt.build(
        receipt_id="01936b2e-2222-7000-8000-000000000002",
        leaves=leaves,
        agent_id="agent-accounts-payable",
        signer_public_key=SIGNER_KEY,
    )


def _escalated_receipt(rng: random.Random) -> Receipt:
    """A payment over the human threshold, approved by two people, then settled.

    Built the way the signer builds it: the escalated decision first, then
    ``LEFT_pre`` from those four leaves, then the approvals over that digest, then
    the resolved decision. Resolving changes exactly two things — the outcome and
    the escalation member — which is what lets a reader recompute the challenge
    from the finished receipt and see that the approvers signed *this* payment.
    """
    instruction = Instruction(
        source="human_input",
        content_hash=digest("pay the quarterly retainer"),
        ref="01936b2e-3333-7000-8000-000000000002",
    )
    intent = _intent(
        amount=Amount(value="4500.00", currency=RLUSD),
        nonce="99887766554433221100ffeeddccbbaa",
        reference=Reference(kind="contract", id="RET-2026-Q1", hash=digest("retainer pdf")),
    )
    attestation = SignerAttestation(
        document=_blob(rng, 96), policy_public_key=SIGNER_KEY, format="aws-nitro"
    )
    rules = (
        PolicyRule("destination_allowlist", "pass", "known supplier"),
        PolicyRule("per_tx_cap", "pass", "4500.00 RLUSD is within the 10000 RLUSD cap"),
        PolicyRule(
            "tier_threshold",
            "escalate",
            "4500.00 is at or above the human-approval threshold 1000.00 RLUSD.rISSUER"
            "000000000000000000000000000",
        ),
    )
    escalated = PolicyDecision(
        policy_hash=POLICY_HASH,
        rules=rules,
        outcome="escalate",
        tier="human",
    )
    challenge = escalation_challenge(_authorization(instruction, intent, escalated, attestation))
    approvals = (
        fixtures.ed25519_assertion(
            approver_id="alice@example.com",
            key=ALICE_PRIVATE,
            challenge=challenge.bytes,
            signed_at="2026-01-02T03:20:11Z",
        ),
        fixtures.ed25519_assertion(
            approver_id="bob@example.com",
            key=BOB_PRIVATE,
            challenge=challenge.bytes,
            signed_at="2026-01-02T03:22:47Z",
        ),
    )
    decision = dataclasses.replace(
        escalated,
        outcome="allow",
        escalation=Escalation(
            challenge=challenge.hex(),
            expires_at="2026-01-02T04:04:05Z",
            quorum=2,
            approvals=tuple(a.to_content() for a in approvals),
        ),
    )
    left = authorization_commitment(_authorization(instruction, intent, decision, attestation))
    leaves = ReceiptLeaves(
        instruction=instruction,
        intent=intent,
        policy_decision=decision,
        signer_attestation=attestation,
        settlement=_settlement(
            rng,
            left,
            ledger_index=94_212_004,
            close_time="2026-01-02T03:25:02Z",
            proof_ref="settlement-proof-0002",
        ),
        result=Result(
            outcome="settled",
            engine_result="tesSUCCESS",
            balance_deltas=(
                BalanceDelta(TREASURY, RLUSD, "-4500.00"),
                BalanceDelta(DESTINATION, RLUSD, "4500.00"),
            ),
        ),
        reasoning=Reasoning(
            content_hash=digest("model trace for the retainer"),
            source="claude-code",
            note="Over the cap, so the signer escalated; two approvers signed the challenge.",
        ),
    )
    return Receipt.build(
        receipt_id="01936b2e-2222-7000-8000-000000000003",
        leaves=leaves,
        agent_id="agent-accounts-payable",
        signer_public_key=SIGNER_KEY,
        session_locator=SessionLocator(
            session_id="01936b2e-1111-7000-8000-000000000002", leaf_index=12
        ),
    )


def _fake_settlement(rng: random.Random, left: SHA256Hash) -> tuple[Settlement, JSONObject]:
    """A settlement on the fake rail, with the capture that proves it offline.

    XRPL captures still name ``shamap_path`` as missing, so on that rail the
    ledger-inclusion line stops at ``supplied-unverified`` no matter how good the
    validator set is. The fake rail closes that last link, which is the only way
    ``proven-offline`` is a state both verifiers can be tested against.
    """
    blob_bytes = bytes.fromhex("beef") + left.bytes + bytes.fromhex(_blob(rng, 30))
    tx_hash = fake_tx_id(blob_bytes)
    payload = bytes.fromhex(_blob(rng, 24)) + left.bytes + bytes.fromhex(_blob(rng, 8))
    ledger_index = 1_000_042
    header: JSONObject = {
        "ledger_index": ledger_index,
        "close_time": "2026-01-02T03:31:00Z",
        "transaction_hash": MerkleTree.build([SHA256Hash(bytes.fromhex(tx_hash))]).root.hex(),
        "transaction_count": 1,
    }
    ledger_hash = fake_ledger_hash(header)
    proof: JSONObject = {
        "rail": RAIL_FAKE,
        "tx_hash": tx_hash,
        "ledger_index": ledger_index,
        "ledger_hash": ledger_hash,
        "ledger_header": header,
        "transaction": {"blob": blob_bytes.hex(), "engine_result": "tesSUCCESS"},
        "tx_path": {"leaf_index": 0, "siblings": [], "directions": []},
        "validations": [
            {
                "validator": name,
                "ledger_index": ledger_index,
                "ledger_hash": ledger_hash,
                "signature": key.sign(
                    b"merkl-fake-validation-v1\x00"
                    + bytes.fromhex(ledger_hash)
                    + ledger_index.to_bytes(8, "big")
                ).hex(),
            }
            for name, key in zip(VALIDATOR_KEYS, VALIDATOR_PRIVATE, strict=True)
        ],
        "captured": ["ledger_header", "transaction", "shamap_path", "validator_signatures"],
        "missing": [],
    }
    settlement = Settlement(
        rail=RAIL_FAKE,
        tx_hash=tx_hash,
        ledger_index=ledger_index,
        close_time="2026-01-02T03:31:00Z",
        signed_tx_blob=blob_bytes.hex(),
        observed_anchor=left.hex(),
        settlement_proof_ref=f"{RAIL_FAKE}:{ledger_index}:{tx_hash[:16].lower()}",
        policy_signature=PolicySignature(
            algorithm="ed25519",
            public_key=SIGNER_KEY,
            signature=SIGNER_PRIVATE.sign(payload).hex(),
            payload=payload.hex(),
        ),
    )
    return settlement, proof


FAKE_PROOF: JSONObject = {}
"""Filled by :func:`_fake_receipt`; the capture the fake-rail verdict is read against."""


def _fake_receipt(rng: random.Random) -> Receipt:
    """The same allow, settled on the fake rail so inclusion can be proven offline."""
    global FAKE_PROOF  # noqa: PLW0603 - one fixture, built once, read by the verdicts
    instruction = Instruction(
        source="system",
        content_hash=digest("scheduled supplier run"),
        ref="01936b2e-3333-7000-8000-000000000004",
    )
    intent = _intent(
        rail=RAIL_FAKE,
        amount=Amount(value="120.00", currency=RLUSD),
        nonce="1122334455667788990011223344556677",
    )
    decision = PolicyDecision(
        policy_hash=POLICY_HASH,
        rules=(
            PolicyRule("destination_allowlist", "pass", "rSUPPLIER is on the allowlist"),
            PolicyRule("per_tx_cap", "pass", "120.00 RLUSD is under the 10000 RLUSD cap"),
            PolicyRule("reference_required", "pass", "invoice INV-2026-0042 supplied"),
        ),
        outcome="allow",
        tier="instant",
    )
    left = authorization_commitment(_authorization(instruction, intent, decision, None))
    settlement, proof = _fake_settlement(rng, left)
    FAKE_PROOF = proof
    leaves = ReceiptLeaves(
        instruction=instruction,
        intent=intent,
        policy_decision=decision,
        signer_attestation=None,
        settlement=settlement,
        result=Result(
            outcome="settled",
            engine_result="tesSUCCESS",
            balance_deltas=(
                BalanceDelta(TREASURY, RLUSD, "-120.00"),
                BalanceDelta(DESTINATION, RLUSD, "120.00"),
            ),
        ),
        reasoning=Reasoning(
            content_hash=digest("model trace for the scheduled run"),
            source="claude-code",
            note="Unattested dev signer: leaf 3 is null and the receipt says so.",
        ),
    )
    return Receipt.build(
        receipt_id="01936b2e-2222-7000-8000-000000000004",
        leaves=leaves,
        agent_id="agent-accounts-payable",
        signer_public_key=SIGNER_KEY,
    )


def _receipt_case(name: str, description: str, receipt: Receipt, reveal: list[str]) -> JSONObject:
    tree = receipt.tree()
    disclosure = receipt.disclose(reveal)
    return {
        "name": name,
        "description": description,
        "leaf_names": _strings(LEAF_NAMES),
        "leaves": [content for content in receipt.leaves.contents()],
        "leaf_hashes": [h.hex() for h in receipt.envelope.leaf_hashes],
        "left": receipt.left.hex(),
        "right": receipt.right.hex(),
        "root": receipt.root.hex(),
        "envelope": receipt.envelope.to_content(),
        "envelope_hash": receipt.envelope_hash().hex(),
        "proofs": {
            leaf_name: {"index": i, **_proof(receipt.proof(leaf_name))}
            for i, leaf_name in enumerate(LEAF_NAMES)
        },
        "half_proofs": {
            leaf_name: {
                "index": i,
                "level": HALF_LEVEL,
                "half": "left" if i < 4 else "right",
                "subtree_root": tree.subtree_root(HALF_LEVEL, i // 4).hex(),
                **_proof(receipt.half_proof(leaf_name)),
            }
            for i, leaf_name in enumerate(LEAF_NAMES)
        },
        "verification": verify_receipt_structure(receipt.envelope, receipt.leaves).to_content(),
        "disclosure": disclosure.to_content(),
        "disclosure_verification": verify_disclosure(disclosure, receipt.root).to_content(),
    }


def receipts(rng: random.Random) -> dict[str, Receipt]:
    return {
        "allow-settled": _allow_receipt(rng),
        "deny-not-submitted": _deny_receipt(rng),
        "escalated-approved-settled": _escalated_receipt(rng),
        "allow-settled-fake-rail": _fake_receipt(rng),
    }


def receipt_vectors(built: dict[str, Receipt]) -> JSONObject:
    described = {
        "allow-settled": (
            "A payment the policy allowed outright and the rail settled. All seven "
            "leaves are present; the observed anchor equals LEFT."
        ),
        "deny-not-submitted": (
            "A payment the policy denied. Nothing was submitted, so leaves 3 and 4 "
            "are null and the result is 'denied' — the receipt proves the refusal."
        ),
        "escalated-approved-settled": (
            "A payment over the per-transaction cap: the signer escalated, two "
            "approvers signed the challenge, and the payment then settled."
        ),
        "allow-settled-fake-rail": (
            "The same allow on the fake rail, produced by an unattested dev signer: "
            "leaf 3 is null and the receipt commits to its absence. Its settlement "
            "capture carries a path to the ledger's transaction root, which is what "
            "lets ledger inclusion reach proven-offline."
        ),
    }
    reveal = {
        "allow-settled": ["intent", "settlement"],
        "deny-not-submitted": ["policy_decision"],
        "escalated-approved-settled": ["intent", "policy_decision", "result"],
        "allow-settled-fake-rail": ["instruction", "settlement"],
    }
    return {
        "description": (
            "Complete merkl-receipt-v1 receipts. Leaves hash under "
            "merkl-receipt-leaf-v1, pad to eight by repeating leaf 6, fold into "
            "LEFT (0-3) and RIGHT (4-7), and ROOT = SHA-256(LEFT || RIGHT). "
            "envelope_hash = SHA-256(canonical_bytes(envelope))."
        ),
        "version": RECEIPT_VERSION,
        "spec": SPEC,
        "cases": [
            _receipt_case(name, described[name], receipt, reveal[name])
            for name, receipt in built.items()
        ],
    }


# --------------------------------------------------------------------------- #
# 5. Tampered cases
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# 6. Verdicts — the whole reading, with the material the verifier brought
# --------------------------------------------------------------------------- #


def _xrpl_proof(settlement: Settlement) -> JSONObject:
    """An XRPL capture shaped the way phase 2 captures one.

    Header, validated transaction, validations — and ``shamap_path`` in
    ``missing``, because rippled's ledger request does not hand back the path
    from a transaction to the ledger's transaction root. The header still hashes,
    which binds that root to the ledger identity; what is absent is the last hop,
    and the fixture says so instead of implying otherwise.
    """
    header: JSONObject = {
        "ledger_index": settlement.ledger_index,
        "total_coins": "99988877766655544",
        "parent_hash": digest(f"parent of {settlement.ledger_index}"),
        "transaction_hash": digest(f"transaction set of {settlement.ledger_index}"),
        "account_hash": digest(f"account state of {settlement.ledger_index}"),
        "parent_close_time": 792_000_000,
        "close_time": 792_000_010,
        "close_time_resolution": 10,
        "close_flags": 0,
    }
    return {
        "rail": "xrpl",
        "tx_hash": settlement.tx_hash,
        "ledger_index": settlement.ledger_index,
        "ledger_hash": xrpl_ledger_hash(header),
        "ledger_header": header,
        "transaction": {"hash": settlement.tx_hash, "validated": True},
        "validations": [
            {
                "validation_public_key": name,
                "ledger_index": settlement.ledger_index,
                "ledger_hash": xrpl_ledger_hash(header),
            }
            for name in ("nHUnvalidator1", "nHUnvalidator2", "nHUnvalidator3")
        ],
        "captured": [
            "ledger_header",
            "validated_transaction_with_metadata",
            "validator_validations",
            "signed_blob",
        ],
        "missing": ["shamap_path"],
    }


XRPL_TRUST: JSONObject = {
    "validators": {"nHUnvalidator1": "", "nHUnvalidator2": "", "nHUnvalidator3": ""},
    "quorum": 2,
}
"""Pinned XRPL validators with no checkable key: agreement is counted, not proved."""

FAKE_TRUST: JSONObject = {"validators": cast("JSONValue", VALIDATOR_KEYS), "quorum": 2}


def _bundle_action(
    index: int, session_id: str, input_hash: str, receipt_id: str | None
) -> JSONObject:
    """One bundle row, with the exact strings ``merkl-leaf-v1`` hashes."""
    action: JSONObject = {
        "action_id": f"01936b2e-4444-7000-8000-00000000000{index}",
        "session_id": session_id,
        "action_type": "transaction" if receipt_id else "tool_call",
        "tool_name": "xrpl_payment" if receipt_id else "read_file",
        "input_hash": input_hash,
        "output_hash": digest(f"output of action {index}"),
        "timestamp": f"2026-01-02T03:04:{index:02d}+00:00",
        "drift_score": 0,
        "drift_score_str": "0.0",
        "guardrail_result": "passed",
        "display_name": "",
        "depends_on": [],
        "status": "success",
        "category": "",
        "receipt_id": receipt_id,
    }
    action["leaf_hash"] = action_leaf(
        action_id=cast("str", action["action_id"]),
        session_id=session_id,
        action_type=cast("str", action["action_type"]),
        tool_name=cast("str", action["tool_name"]),
        input_hash=input_hash,
        output_hash=cast("str", action["output_hash"]),
        timestamp=cast("str", action["timestamp"]),
        drift_score="0.0",
        guardrail_result="passed",
    ).hex()
    return action


def _session_bundle(receipt: Receipt) -> JSONObject:
    """A session that actually commits this receipt's envelope, at the leaf it names.

    The receipt's ``session_locator`` says which action carries it, so the bundle
    is built out to that index: filler actions before it, then one whose
    ``input_hash`` *is* the envelope hash. Every leaf gets a real inclusion proof
    against a real tree, because the join is only meaningful if the action it
    lands on is itself provably in the session.

    No audit entry and no checkpoint — those are the notary's, and leaving them
    out is what makes this the *minimal* level-2 join: the log checks that need
    them report ``not_implemented`` by name while the join itself passes.
    """
    locator = receipt.envelope.session_locator
    assert locator is not None
    session_id = locator.session_id
    actions = [
        _bundle_action(i, session_id, digest(f"filler input {i}"), None)
        for i in range(locator.leaf_index)
    ]
    actions.append(
        _bundle_action(
            locator.leaf_index,
            session_id,
            receipt.envelope_hash().hex(),
            receipt.envelope.receipt_id,
        )
    )
    tree = MerkleTree.build(
        [SHA256Hash(bytes.fromhex(cast("str", a["leaf_hash"]))) for a in actions]
    )
    root = tree.root.hex()
    for i, action in enumerate(actions):
        action["proof"] = {**_proof(tree.get_proof(i)), "root": root, "leaf_index": i}
    return {
        "version": "1.2",
        "session": {
            "session_id": session_id,
            "agent_id": "agent-accounts-payable",
            "root_hash": root,
            "leaf_count": len(actions),
            "action_count": len(actions),
            "status": "closed",
        },
        "actions": cast("list[JSONValue]", actions),
        "receipts": [],
    }


def _material(name: str, receipt: Receipt) -> JSONObject:
    """What a verifier brings to each case, written down so the JS brings the same."""
    settlement = receipt.leaves.settlement
    proof: JSONValue = None
    trust: JSONValue = None
    if settlement is not None and settlement.rail == RAIL_FAKE:
        proof, trust = FAKE_PROOF, cast("JSONValue", FAKE_TRUST)
    elif settlement is not None:
        proof, trust = _xrpl_proof(settlement), cast("JSONValue", XRPL_TRUST)
    joined = name == "allow-settled"
    return {
        "settlement_proof": proof,
        "validator_trust": trust,
        "policy_document": SIGNED_POLICY.to_content(),
        "admin_public_key": ADMIN_KEY,
        "attestation_trust": None,
        "session_bundle": _session_bundle(receipt) if joined else None,
    }


def verdict_vectors(built: dict[str, Receipt]) -> JSONObject:
    """The full reading of each receipt: every check, both settlement lines, the level.

    ``material`` is the whole point. Nothing in it comes out of the receipt: the
    policy document is looked up by hash, the validator set and its quorum are the
    verifier's, and the attestation trust is deliberately null here so that check
    stays ``not_implemented`` rather than passing on a document nobody pinned
    measurements for. Both implementations must produce the recorded verdict from
    the recorded material and nothing else.
    """
    cases: list[JSONValue] = []
    for name, receipt in built.items():
        material = _material(name, receipt)
        cases.append(_verdict_case(name, name, receipt, material))
    cases.extend(_receipt_page_cases(built["allow-settled"]))
    return {
        "description": (
            "The complete verdict for each receipt in receipts.json, read with the "
            "material recorded beside it. Two settlement lines (plan D10) and one "
            "level (plan D9), never a single boolean. `receipt` names the case in "
            "receipts.json the leaves come from; it differs from `name` when two "
            "cases read the same receipt against different material."
        ),
        "spec": SPEC,
        "cases": cases,
    }


def _verdict_case(
    name: str, receipt_name: str, receipt: Receipt, material: JSONObject
) -> JSONObject:
    trust = cast("dict[str, Any] | None", material["validator_trust"])
    verdict = verify_receipt(
        receipt.envelope,
        receipt.leaves,
        settlement_proof=material["settlement_proof"],
        validator_trust=(
            ValidatorTrust(validators=trust["validators"], quorum=trust["quorum"])
            if trust
            else None
        ),
        policy_document=material["policy_document"],
        admin_public_key=cast("str", material["admin_public_key"]),
        session_bundle=cast("dict[str, Any] | None", material["session_bundle"]),
    )
    return {
        "name": name,
        "receipt": receipt_name,
        "material": material,
        "verdict": verdict.to_content(),
    }


def _receipt_page_cases(receipt: Receipt) -> list[JSONValue]:
    """The two bundles ``GET /v1/receipts/{id}/verify.html`` can hand a verifier.

    A receipt page has no reason to ship a whole session, so it ships the join
    *scoped* to this receipt: the one action whose ``input_hash`` is the envelope
    hash, its proof to the session root, and the log material around it
    (``merkl-api/docs/SPEC.md`` §9). Both implementations have to reach level 2
    from that, which means locating the action by the leaf its proof names rather
    than by its position — at position 0 in a one-row list, the position is a
    lie about which leaf it is.

    The second case is the same page before the session seals. It must say so:
    an open session is a stage of the session's life, not a defect in the
    receipt, and a bare level 1 with no explanation is what sent a reader asking.
    """
    locator = receipt.envelope.session_locator
    assert locator is not None
    full = _session_bundle(receipt)
    rows = cast("list[JSONObject]", full["actions"])
    scoped_actions = [
        a for a in rows if cast("JSONObject", a["proof"])["leaf_index"] == locator.leaf_index
    ]
    assert len(scoped_actions) == 1
    session = dict(cast("JSONObject", full["session"]))

    scoped: JSONObject = {
        **full,
        "session": {**session, "sealed": True},
        "actions": cast("list[JSONValue]", scoped_actions),
        "scope": {
            "kind": "receipt",
            "receipt_id": receipt.envelope.receipt_id,
            "session_id": locator.session_id,
            "leaf_index": locator.leaf_index,
            "actions_included": 1,
            "action_count": len(rows),
        },
    }
    # An open session as merkl-api actually renders one: no root to prove into,
    # so `root_hash` is null and there are no actions, no audit entry and no
    # checkpoint. The null matters — a verifier that stringified it would hold
    # every proof against the four characters "None" and report an honest open
    # session as contradicted.
    unsealed: JSONObject = {
        "version": scoped["version"],
        "session": {**session, "sealed": False, "status": "open", "root_hash": None},
        "actions": [],
        "receipts": [],
        "scope": {**cast("JSONObject", scoped["scope"]), "actions_included": 0},
    }
    base = _material("allow-settled", receipt)
    return [
        _verdict_case(
            "receipt-page-scoped-join",
            "allow-settled",
            receipt,
            {**base, "session_bundle": scoped},
        ),
        _verdict_case(
            "receipt-page-session-open",
            "allow-settled",
            receipt,
            {**base, "session_bundle": unsealed},
        ),
    ]


def _with(content: JSONValue, key: str, value: JSONValue) -> JSONValue:
    """A copy of an object content with one member replaced."""
    assert isinstance(content, dict)
    changed = copy.deepcopy(content)
    changed[key] = value
    return changed


def _flip_last_hex(value: str) -> str:
    """Change exactly one character of a hex-ish string."""
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def _receipt_tamper(
    name: str,
    description: str,
    base: str,
    receipt: Receipt,
    *,
    leaves: list[JSONValue] | None = None,
    envelope: JSONObject | None = None,
    expect: list[str],
) -> JSONObject:
    contents = leaves if leaves is not None else list(receipt.leaves.contents())
    envelope_content = envelope if envelope is not None else receipt.envelope.to_content()
    result = verify_receipt_structure(Envelope.from_content(envelope_content), contents)
    actual = sorted(c.name for c in result.failures)
    if actual != sorted(expect):
        raise AssertionError(
            f"{name}: expected failures {sorted(expect)}, verifier reported {actual}"
        )
    return {
        "name": name,
        "description": description,
        "kind": "receipt",
        "base": base,
        "envelope": envelope_content,
        "leaves": contents,
        "expected_ok": False,
        "expected_failing_checks": _strings(sorted(expect)),
    }


def _disclosure_tamper(
    name: str,
    description: str,
    base: str,
    disclosure: JSONObject,
    root: str,
    *,
    expect: list[str],
) -> JSONObject:
    result = verify_disclosure(
        Disclosure.from_content(disclosure), SHA256Hash(bytes.fromhex(root))
    )
    actual = sorted(c.name for c in result.failures)
    if actual != sorted(expect):
        raise AssertionError(
            f"{name}: expected failures {sorted(expect)}, verifier reported {actual}"
        )
    return {
        "name": name,
        "description": description,
        "kind": "disclosure",
        "base": base,
        "disclosure": disclosure,
        "root": root,
        "expected_ok": False,
        "expected_failing_checks": _strings(sorted(expect)),
    }


_ALSO_FAILS: dict[str, list[str]] = {
    "policy_decision": ["envelope.policy_hash"],
    "settlement": ["settlement.signed_blob"],
}

_TAMPER_FIELD: dict[str, str] = {
    "instruction": "content_hash",
    "intent": "nonce",
    "policy_decision": "policy_hash",
    "signer_attestation": "document",
    "settlement": "tx_hash",
    "result": "outcome_hash",
    "reasoning": "content_hash",
}


_UNBACKED_CASES: list[tuple[str, str, dict[str, Any], dict[str, Any], list[str]]] = [
    (
        "rebuilt-without-a-policy-signature",
        "A structurally perfect settled receipt that carries no policy signature. "
        "Nothing contradicts itself; it simply never proves that the policy key "
        "authorized the payment, and a settled receipt that cannot show that is a "
        "failure, not a gap.",
        {"policy_signature": None},
        {},
        ["policy.signature"],
    ),
    (
        "rebuilt-with-a-forged-policy-signature",
        "The signature bytes are altered. The payload still carries LEFT, so the "
        "binding survives and only the signature check fails.",
        {"forge_signature": True},
        {},
        ["policy.signature"],
    ),
    (
        "rebuilt-with-a-signature-over-another-payload",
        "A genuine signature by the policy key, over a payload that does not "
        "contain this receipt's LEFT. Replaying a real signature onto a different "
        "authorization is the attack this check exists for.",
        {"foreign_payload": True},
        {},
        ["policy.signature"],
    ),
    (
        "rebuilt-with-a-mismatched-signed-blob",
        "The transaction hash does not derive from the blob beside it, so at most "
        "one of the two describes what the ledger validated.",
        {"corrupt_blob": True},
        {},
        ["settlement.signed_blob"],
    ),
    (
        "rebuilt-with-an-anchor-that-is-not-left",
        "The rail carried some other digest. The payment settled, but not this authorization.",
        {"observed_anchor": digest("an anchor from another receipt")},
        {},
        ["settlement.anchor_equals_left"],
    ),
    (
        "rebuilt-with-an-amount-that-was-not-settled",
        "The intent asks for 250.00 and the balance deltas record 25.00 moving. "
        "Every hash agrees; the money does not.",
        {},
        {"scale": "25.00"},
        ["intent.matches_settled_fields"],
    ),
]


def _rebuild(
    base: Receipt, settlement_changes: dict[str, Any], result_changes: dict[str, Any]
) -> Receipt:
    """A fresh receipt over altered settlement leaves, with its own valid envelope."""
    settlement = base.leaves.settlement
    result = base.leaves.result
    assert settlement is not None and result is not None
    signature = settlement.policy_signature
    assert signature is not None

    changes: dict[str, Any] = dict(settlement_changes)
    if changes.pop("forge_signature", False):
        changes["policy_signature"] = dataclasses.replace(
            signature, signature=_flip_last_hex(signature.signature)
        )
    if changes.pop("foreign_payload", False):
        payload = b"a payload about some other payment entirely"
        changes["policy_signature"] = dataclasses.replace(
            signature,
            payload=payload.hex(),
            signature=SIGNER_PRIVATE.sign(payload).hex(),
        )
    if changes.pop("corrupt_blob", False):
        assert settlement.signed_tx_blob is not None
        changes["signed_tx_blob"] = _flip_last_hex(settlement.signed_tx_blob)

    scale = result_changes.pop("scale", None)
    if scale is not None:
        result = dataclasses.replace(
            result,
            balance_deltas=tuple(
                dataclasses.replace(d, value=("-" + scale) if d.value.startswith("-") else scale)
                for d in result.balance_deltas
            ),
        )
    result = dataclasses.replace(result, **result_changes) if result_changes else result

    leaves = dataclasses.replace(
        base.leaves,
        settlement=dataclasses.replace(settlement, **changes),
        result=result,
    )
    return Receipt.build(
        receipt_id=base.envelope.receipt_id,
        leaves=leaves,
        agent_id=base.envelope.agent_id,
        signer_public_key=base.envelope.signer_public_key,
        session_locator=base.envelope.session_locator,
    )


def tampered_vectors(built: dict[str, Receipt]) -> JSONObject:
    allow = built["allow-settled"]
    deny = built["deny-not-submitted"]
    cases: list[JSONValue] = []

    # One byte changed in each of the seven leaves.
    for i, leaf_name in enumerate(LEAF_NAMES):
        contents = list(allow.leaves.contents())
        original = contents[i]
        assert isinstance(original, dict)
        field = _TAMPER_FIELD[leaf_name]
        value = original[field]
        assert isinstance(value, str)
        contents[i] = _with(original, field, _flip_last_hex(value))
        half = "commitment.left" if i < 4 else "commitment.right"
        # policy_hash is repeated in the envelope, so tampering with it fails twice;
        # the transaction hash is derived from the blob, so tampering with it also
        # breaks the derivation.
        also = _ALSO_FAILS.get(leaf_name, [])
        cases.append(
            _receipt_tamper(
                f"leaf-{i}-{leaf_name}-one-byte-changed",
                f"One character of {leaf_name}.{field} changed; the envelope is untouched.",
                "allow-settled",
                allow,
                leaves=contents,
                expect=[f"leaf.{leaf_name}", half, *also],
            )
        )

    # Two leaves swapped between their names.
    swapped = list(allow.leaves.contents())
    swapped[1], swapped[2] = swapped[2], swapped[1]
    cases.append(
        _receipt_tamper(
            "swapped-leaf-names",
            "The intent and policy_decision contents are exchanged. The leaf name is "
            "inside the hash, so neither leaf verifies under the other's name.",
            "allow-settled",
            allow,
            leaves=swapped,
            expect=[
                "leaf.intent",
                "leaf.policy_decision",
                "commitment.left",
                "intent.matches_settled_fields",
                "envelope.rail",
                "envelope.treasury",
                "envelope.policy_hash",
            ],
        )
    )

    # Padding that does not repeat the last leaf.
    envelope = allow.envelope.to_content()
    hashes = envelope["leaf_hashes"]
    assert isinstance(hashes, list)
    bad_padding = list(hashes)
    bad_padding[7] = digest("a leaf that is not leaf 6")
    cases.append(
        _receipt_tamper(
            "wrong-padding",
            "Leaf 7 holds something other than a repeat of leaf 6, which is the only "
            "padding the format allows.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "leaf_hashes", bad_padding)),  # type: ignore[arg-type]
            expect=["leaves.padding", "commitment.right", "commitment.root"],
        )
    )

    cases.append(
        _receipt_tamper(
            "forged-root",
            "The envelope claims a root that is not SHA-256(LEFT || RIGHT).",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "root", digest("a root nobody computed"))),  # type: ignore[arg-type]
            expect=["commitment.root"],
        )
    )

    cases.append(
        _receipt_tamper(
            "forged-left",
            "The envelope claims a LEFT that the first four leaves do not produce; "
            "LEFT is the value the policy key signs, so this is the interesting forgery.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "left", digest("a left nobody computed"))),  # type: ignore[arg-type]
            expect=[
                "commitment.left",
                "policy.signature",
                "settlement.anchor_equals_left",
            ],
        )
    )

    cases.append(
        _receipt_tamper(
            "envelope-rail-mismatch",
            "The envelope names a different rail from the intent leaf.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "rail", "fake")),  # type: ignore[arg-type]
            expect=["envelope.rail"],
        )
    )

    cases.append(
        _receipt_tamper(
            "envelope-treasury-mismatch",
            "The envelope names a different treasury from the intent leaf.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "treasury", ATTACKER)),  # type: ignore[arg-type]
            expect=["envelope.treasury"],
        )
    )

    cases.append(
        _receipt_tamper(
            "envelope-policy-hash-mismatch",
            "The envelope points at a different policy document from the decision leaf.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "policy_hash", digest("some other policy"))),  # type: ignore[arg-type]
            expect=["envelope.policy_hash"],
        )
    )

    cases.append(
        _receipt_tamper(
            "unknown-version",
            "A verifier must refuse a version tag it does not know.",
            "allow-settled",
            allow,
            envelope=dict(_with(envelope, "version", "merkl-receipt-v2")),  # type: ignore[arg-type]
            expect=["receipt.version"],
        )
    )

    dropped = list(allow.leaves.contents())
    dropped[0] = None
    cases.append(
        _receipt_tamper(
            "instruction-leaf-dropped",
            "The instruction leaf is replaced with null, as if the payment had no "
            "origin. Every receipt carries leaves 0-2.",
            "allow-settled",
            allow,
            leaves=dropped,
            expect=["leaves.required_present", "leaf.instruction", "commitment.left"],
        )
    )

    truncated = list(allow.leaves.contents())[:6]
    cases.append(
        _receipt_tamper(
            "leaf-count-truncated",
            "Six leaf contents instead of seven.",
            "allow-settled",
            allow,
            leaves=truncated,
            expect=["leaves.count", "leaf.reasoning", "commitment.right"],
        )
    )

    grafted = list(deny.leaves.contents())
    grafted[4] = list(allow.leaves.contents())[4]
    cases.append(
        _receipt_tamper(
            "settlement-grafted-onto-a-denial",
            "A settlement leaf is grafted onto a denied receipt, which committed to "
            "having no settlement at all.",
            "deny-not-submitted",
            deny,
            leaves=grafted,
            expect=[
                "leaf.settlement",
                "commitment.right",
                "policy.signature",
                "settlement.anchor_equals_left",
            ],
        )
    )

    float_amount = list(allow.leaves.contents())
    intent_content = float_amount[1]
    assert isinstance(intent_content, dict)
    fractional = cast(JSONValue, {"value": 250.5, "currency": "RLUSD"})
    float_amount[1] = _with(intent_content, "amount", fractional)
    cases.append(
        _receipt_tamper(
            "fractional-amount",
            "The amount is a JSON number instead of a decimal string. Receipts hold "
            "no fractional numbers, so the leaf cannot even be hashed.",
            "allow-settled",
            allow,
            leaves=float_amount,
            expect=["leaf.intent", "commitment.left", "intent.matches_settled_fields"],
        )
    )

    # A forger who rebuilds the whole tree consistently still cannot produce the
    # signature, the anchor or the settled amounts. These four cases have a valid
    # envelope over their own leaves: every structural check passes, and the
    # receipt still proves nothing.
    for name, description, settlement_changes, result_changes, expect in _UNBACKED_CASES:
        rebuilt = _rebuild(allow, settlement_changes, result_changes)
        cases.append(
            _receipt_tamper(
                name,
                description,
                "allow-settled",
                rebuilt,
                leaves=list(rebuilt.leaves.contents()),
                envelope=rebuilt.envelope.to_content(),
                expect=expect,
            )
        )

    # Disclosure tampering.
    disclosure = allow.disclose(["intent", "settlement"]).to_content()
    root = allow.root.hex()

    changed_content = copy.deepcopy(disclosure)
    leaves_list = changed_content["leaves"]
    assert isinstance(leaves_list, list)
    first = leaves_list[0]
    assert isinstance(first, dict)
    first["content"] = _with(first["content"], "destination", ATTACKER)
    cases.append(
        _disclosure_tamper(
            "disclosure-destination-rewritten",
            "The disclosed intent names a different destination from the one the "
            "receipt committed to.",
            "allow-settled",
            changed_content,
            root,
            expect=["leaf.intent", "proof.intent"],
        )
    )

    changed_proof = copy.deepcopy(disclosure)
    leaves_list = changed_proof["leaves"]
    assert isinstance(leaves_list, list)
    second = leaves_list[1]
    assert isinstance(second, dict)
    proof = second["proof"]
    assert isinstance(proof, dict)
    siblings = proof["siblings"]
    assert isinstance(siblings, list) and isinstance(siblings[0], str)
    siblings[0] = _flip_last_hex(siblings[0])
    cases.append(
        _disclosure_tamper(
            "disclosure-sibling-changed",
            "One sibling hash in the settlement proof is altered, so the fold lands "
            "somewhere other than the root.",
            "allow-settled",
            changed_proof,
            root,
            expect=["proof.settlement"],
        )
    )

    wrong_root = copy.deepcopy(disclosure)
    cases.append(
        _disclosure_tamper(
            "disclosure-against-a-different-root",
            "A well-formed disclosure checked against a root the reader pinned "
            "elsewhere. The root is an input, never something the disclosure asserts.",
            "allow-settled",
            wrong_root,
            digest("a root from another receipt"),
            expect=[
                "disclosure.root",
                "proof.intent",
                "proof.settlement",
                "commitment.root",
            ],
        )
    )

    return {
        "description": (
            "Receipts and disclosures that must fail, each with the exact check names "
            "a conforming verifier reports. expected_failing_checks is the complete "
            "set of failures: no more, no fewer."
        ),
        "spec": SPEC,
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def build_all() -> dict[str, JSONObject]:
    """Every fixture file, keyed by filename. Pure: no I/O."""
    rng = random.Random(SEED)
    built = receipts(rng)
    files: dict[str, JSONObject] = {
        "merkle.json": merkle_vectors(),
        "action_leaf.json": action_leaf_vectors(),
        "receipt_leaf.json": receipt_leaf_vectors(),
        "approvals.json": approval_vectors(),
        "policies.json": policy_vectors(),
        "receipts.json": receipt_vectors(built),
        "verdicts.json": verdict_vectors(built),
        "tampered.json": tampered_vectors(built),
    }
    files["manifest.json"] = {
        "description": "Index of the Merkl receipt test vectors.",
        "spec": SPEC,
        "version": RECEIPT_VERSION,
        "seed": SEED,
        "generator": "python -m merkl.core.vectors.generate",
        "files": [
            {"file": name, "cases": len(_cases(content))} for name, content in files.items()
        ],
    }
    return files


def _cases(content: JSONObject) -> list[Any]:
    cases = content.get("cases", [])
    return cases if isinstance(cases, list) else []


def _serialize(content: JSONObject) -> str:
    return json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(out_dir: pathlib.Path) -> list[pathlib.Path]:
    written: list[pathlib.Path] = []
    for name, content in build_all().items():
        path = out_dir / name
        path.write_text(_serialize(content), encoding="utf-8")
        written.append(path)
    return written


def check(out_dir: pathlib.Path) -> list[str]:
    """Filenames whose committed contents differ from a fresh generation."""
    stale: list[str] = []
    for name, content in build_all().items():
        path = out_dir / name
        if not path.exists() or path.read_text(encoding="utf-8") != _serialize(content):
            stale.append(name)
    return stale


def main(argv: list[str]) -> int:
    if "--check" in argv:
        stale = check(VECTORS_DIR)
        if stale:
            print(f"stale vectors: {', '.join(stale)}", file=sys.stderr)
            print("regenerate with: python -m merkl.core.vectors.generate", file=sys.stderr)
            return 1
        print("vectors are up to date")
        return 0
    for path in write(VECTORS_DIR):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
