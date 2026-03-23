"""Base domain event protocol for Merkl."""

from __future__ import annotations

import typing

from merkl.shared.timestamps import Timestamp


@typing.runtime_checkable
class DomainEvent(typing.Protocol):
    """Protocol that all domain events must satisfy."""

    @property
    def event_id(self) -> str: ...

    @property
    def occurred_at(self) -> Timestamp: ...
