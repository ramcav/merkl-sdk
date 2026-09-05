"""``merkl.core`` — the pure core of Merkl's proof formats.

No HTTP, no database, no filesystem, no clock, no rail client, and no dependency
beyond the standard library and ``merkl.shared``. Everything here is a value
object or a function over value objects, so a verifier, a signer and a server can
all reach the same conclusion from the same bytes.

What lives here:

* :mod:`merkl.core.merkle` — the Merkle tree, inclusion proofs and subtree roots.
* :mod:`merkl.core.leaf` — the frozen ``merkl-leaf-v1`` action leaf and the
  ``merkl-receipt-leaf-v1`` receipt leaf.
* :mod:`merkl.core.intent` — Intent v1 and decimal-string money.
* :mod:`merkl.core.receipt` — the seven-leaf receipt, its envelope, selective
  disclosure and structural verification.
* :mod:`merkl.core.canonical` — the JSON subset receipt content may use.
* :mod:`merkl.core.policy` — the signed policy document, the deterministic engine
  and the rule state the signer keeps.
* :mod:`merkl.core.ports` — the Protocols adapters implement.
* :mod:`merkl.core.rail` — rail-facing value objects and the anchor placeholder.
* :mod:`merkl.core.crypto` — signature verification, the one place ``cryptography``
  is used inside core.

``docs/RECEIPT-SPEC.md`` is the normative description of every byte.
"""

from merkl.core.canonical import (
    ContentError,
    JSONObject,
    JSONValue,
    ensure_canonical_content,
    format_decimal,
    parse_decimal,
)
from merkl.core.intent import (
    NATIVE_XRP,
    Amount,
    CurrencyRef,
    Intent,
    IntentError,
    IssuedCurrency,
    Reference,
)
from merkl.core.leaf import (
    ACTION_LEAF_TAG,
    RECEIPT_LEAF_TAG,
    action_leaf,
    receipt_leaf,
)
from merkl.core.merkle import Direction, MerkleProof, MerkleTree
from merkl.core.receipt import (
    CHECK_ANCHOR_EQUALS_LEFT,
    CHECK_INTENT_MATCHES_SETTLED,
    CHECK_LEAF_COUNT,
    CHECK_LEFT,
    CHECK_PADDING,
    CHECK_POLICY_SIGNATURE,
    CHECK_REQUIRED_LEAVES,
    CHECK_RIGHT,
    CHECK_ROOT,
    CHECK_SIGNED_BLOB,
    CHECK_VERSION,
    DEFERRED_CHECKS,
    LEAF_NAMES,
    RECEIPT_VERSION,
    BalanceDelta,
    Check,
    CheckStatus,
    DisclosedLeaf,
    Disclosure,
    Envelope,
    Escalation,
    Instruction,
    InstructionSource,
    PolicyDecision,
    PolicyOutcome,
    PolicyRule,
    PolicySignature,
    Reasoning,
    Receipt,
    ReceiptError,
    ReceiptLeaves,
    Result,
    ResultOutcome,
    SessionLocator,
    Settlement,
    SignerAttestation,
    VerificationResult,
    authorization_commitment,
    build_left,
    build_right,
    build_root,
    build_tree,
    disclose,
    escalation_challenge,
    leaf_check,
    pad_leaf_hashes,
    proof_check,
    verify_disclosure,
    verify_receipt_structure,
)

__all__ = [
    "ACTION_LEAF_TAG",
    "Amount",
    "BalanceDelta",
    "CHECK_ANCHOR_EQUALS_LEFT",
    "CHECK_INTENT_MATCHES_SETTLED",
    "CHECK_LEAF_COUNT",
    "CHECK_LEFT",
    "CHECK_PADDING",
    "CHECK_POLICY_SIGNATURE",
    "CHECK_REQUIRED_LEAVES",
    "CHECK_RIGHT",
    "CHECK_ROOT",
    "CHECK_SIGNED_BLOB",
    "CHECK_VERSION",
    "Check",
    "CheckStatus",
    "ContentError",
    "CurrencyRef",
    "DEFERRED_CHECKS",
    "Direction",
    "DisclosedLeaf",
    "Disclosure",
    "Envelope",
    "Escalation",
    "Instruction",
    "InstructionSource",
    "Intent",
    "IntentError",
    "IssuedCurrency",
    "JSONObject",
    "JSONValue",
    "LEAF_NAMES",
    "MerkleProof",
    "MerkleTree",
    "NATIVE_XRP",
    "PolicyDecision",
    "PolicyOutcome",
    "PolicyRule",
    "PolicySignature",
    "RECEIPT_LEAF_TAG",
    "RECEIPT_VERSION",
    "Reasoning",
    "Receipt",
    "ReceiptError",
    "ReceiptLeaves",
    "Reference",
    "Result",
    "ResultOutcome",
    "SessionLocator",
    "Settlement",
    "SignerAttestation",
    "VerificationResult",
    "action_leaf",
    "authorization_commitment",
    "build_left",
    "build_right",
    "build_root",
    "build_tree",
    "disclose",
    "ensure_canonical_content",
    "escalation_challenge",
    "format_decimal",
    "leaf_check",
    "pad_leaf_hashes",
    "parse_decimal",
    "proof_check",
    "receipt_leaf",
    "verify_disclosure",
    "verify_receipt_structure",
]
