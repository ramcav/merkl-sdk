"""Shared kernel — cross-context value objects, enums, and base exceptions."""

from merkl.shared.enums import ActionType, GuardrailResult, ProvenanceLevel, SessionStatus
from merkl.shared.errors import (
    AnchorError,
    DomainError,
    EntityNotFoundError,
    InfrastructureError,
    RepositoryError,
    TransportError,
    ValidationError,
    MerklError,
)
from merkl.shared.events import DomainEvent
from merkl.shared.hashing import SHA256Hash
from merkl.shared.ids import ActionId, AgentId, SessionId
from merkl.shared.timestamps import Timestamp

__all__ = [
    "ActionId",
    "ActionType",
    "AgentId",
    "AnchorError",
    "DomainEvent",
    "DomainError",
    "EntityNotFoundError",
    "GuardrailResult",
    "InfrastructureError",
    "ProvenanceLevel",
    "RepositoryError",
    "SHA256Hash",
    "SessionId",
    "SessionStatus",
    "Timestamp",
    "TransportError",
    "ValidationError",
    "MerklError",
]
