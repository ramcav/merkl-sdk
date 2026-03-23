"""Identity value objects for Merkl."""

from __future__ import annotations

import dataclasses
import uuid

from uuid6 import uuid7

from merkl.shared.errors import ValidationError


@dataclasses.dataclass(frozen=True)
class AgentId:
    """Identifies a registered agent. Wraps a string identifier."""

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValidationError("AgentId cannot be empty")

    def __str__(self) -> str:
        return self.value


@dataclasses.dataclass(frozen=True)
class SessionId:
    """Identifies a Merkl session. Uses UUID v7 for time-sortable uniqueness."""

    value: uuid.UUID

    @classmethod
    def generate(cls) -> SessionId:
        """Generate a new time-sortable SessionId."""
        return cls(value=uuid7())

    @classmethod
    def from_str(cls, s: str) -> SessionId:
        """Construct from a UUID string."""
        return cls(value=uuid.UUID(s))

    def __str__(self) -> str:
        return str(self.value)


@dataclasses.dataclass(frozen=True)
class ActionId:
    """Identifies an individual action record. Uses UUID v7 for time-sortable uniqueness."""

    value: uuid.UUID

    @classmethod
    def generate(cls) -> ActionId:
        """Generate a new time-sortable ActionId."""
        return cls(value=uuid7())

    @classmethod
    def from_str(cls, s: str) -> ActionId:
        """Construct from a UUID string."""
        return cls(value=uuid.UUID(s))

    def __str__(self) -> str:
        return str(self.value)
