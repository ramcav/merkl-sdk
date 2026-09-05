"""``merkl.core.policy`` — the signed rules, the deterministic engine, the state.

Three things, kept apart on purpose:

* :mod:`~merkl.core.policy.document` — the policy as a signed, hashed document.
  Public, replayable, and holding no state.
* :mod:`~merkl.core.policy.engine` — ``evaluate``, a pure function from (intent,
  policy, state view, risk score, instant) to a decision that serializes as
  receipt leaf 2.
* :mod:`~merkl.core.policy.state` — reservations, sliding windows and replay
  nonces, as an immutable ledger a signer can seal and restore.

Plus :mod:`~merkl.core.policy.approvals`, which pins what a human approval of an
escalation looks like on the wire.
"""

from merkl.core.policy.approvals import (
    ApprovalAssertion,
    ApprovalError,
    AssertionCheck,
    QuorumResult,
    assertions_from_content,
    verify_assertion,
    verify_quorum,
)
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    CREDENTIAL_WEBAUTHN,
    POLICY_TAG,
    AgentSection,
    ApproverCredential,
    AssetLimit,
    EscalationTier,
    HumanTier,
    PolicyChange,
    PolicyDocument,
    PolicyError,
    ReferenceBinding,
    RiskRule,
    SignedPolicy,
    Tiers,
    WindowRule,
    asset_key,
    verify_policy_signature,
)
from merkl.core.policy.engine import (
    RULE_ORDER,
    Decision,
    EscalationRequest,
    ReservationRequest,
    RiskScore,
    RuleOutcome,
    evaluate,
)
from merkl.core.policy.state import (
    LedgerState,
    NonceEntry,
    Outflow,
    Reconciliation,
    SpendEntry,
    SpendStatus,
    StateError,
    StateStore,
    StateView,
    outflows_from_content,
    reconcile,
)

__all__ = [
    "CREDENTIAL_ED25519",
    "CREDENTIAL_WEBAUTHN",
    "POLICY_TAG",
    "RULE_ORDER",
    "AgentSection",
    "ApprovalAssertion",
    "ApprovalError",
    "ApproverCredential",
    "AssertionCheck",
    "AssetLimit",
    "Decision",
    "EscalationRequest",
    "EscalationTier",
    "HumanTier",
    "LedgerState",
    "NonceEntry",
    "Outflow",
    "PolicyChange",
    "PolicyDocument",
    "PolicyError",
    "QuorumResult",
    "Reconciliation",
    "ReferenceBinding",
    "ReservationRequest",
    "RiskRule",
    "RiskScore",
    "RuleOutcome",
    "SignedPolicy",
    "SpendEntry",
    "SpendStatus",
    "StateError",
    "StateStore",
    "StateView",
    "Tiers",
    "WindowRule",
    "assertions_from_content",
    "asset_key",
    "evaluate",
    "outflows_from_content",
    "reconcile",
    "verify_assertion",
    "verify_policy_signature",
    "verify_quorum",
]
