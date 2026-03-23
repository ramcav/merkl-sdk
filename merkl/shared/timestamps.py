"""Timestamp value object for Merkl."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime


@dataclasses.dataclass(frozen=True, order=True)
class Timestamp:
    """Immutable UTC timestamp value object."""

    value: datetime

    @classmethod
    def now(cls) -> Timestamp:
        """Create a Timestamp for the current UTC time."""
        return cls(value=datetime.now(UTC))

    @classmethod
    def from_datetime(cls, dt: datetime) -> Timestamp:
        """Create a Timestamp from an existing datetime (must be timezone-aware)."""
        if dt.tzinfo is None:
            raise ValueError("datetime must be timezone-aware (UTC)")
        return cls(value=dt.astimezone(UTC))

    @property
    def datetime(self) -> datetime:
        """Access the underlying datetime."""
        return self.value
