"""Domain enums for Merkl."""

from __future__ import annotations

import enum


class ActionStatus(enum.StrEnum):
    """Outcome status of an agent action."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    PENDING = "pending"



class ActionType(enum.StrEnum):
    """Type of agent action being recorded."""

    TOOL_CALL = "tool_call"
    DATA_ACCESS = "data_access"
    API_REQUEST = "api_request"
    TRANSACTION = "transaction"
    APPROVAL_REQUEST = "approval_request"
    REASONING = "reasoning"
    SUB_AGENT = "sub_agent"
    HUMAN_INPUT = "human_input"


class GuardrailResult(enum.StrEnum):
    """Outcome of a guardrail evaluation."""

    PASSED = "passed"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    NOT_EVALUATED = "not_evaluated"


class SessionStatus(enum.StrEnum):
    """Lifecycle status of a Merkl session."""

    OPEN = "open"
    CLOSED = "closed"
    ABORTED = "aborted"
    EXPIRED = "expired"


class ProvenanceLevel(enum.StrEnum):
    """Trust level for content source provenance."""

    SYSTEM = "system"
    USER = "user"
    INTERNAL = "internal"
    EXTERNAL_VERIFIED = "external_verified"
    EXTERNAL_UNVERIFIED = "external_unverified"
    UNTRUSTED = "untrusted"
