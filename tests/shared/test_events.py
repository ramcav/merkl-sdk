"""Tests for the DomainEvent protocol."""

from __future__ import annotations

import dataclasses

from merkl.shared.events import DomainEvent
from merkl.shared.timestamps import Timestamp


@dataclasses.dataclass(frozen=True)
class _FakeEvent:
    """A concrete event that satisfies the DomainEvent protocol."""

    payload: str
    event_id: str = "evt-123"
    occurred_at: Timestamp = dataclasses.field(default_factory=Timestamp.now)


@dataclasses.dataclass(frozen=True)
class _NonEvent:
    """Does not satisfy the DomainEvent protocol."""

    payload: str


class TestDomainEvent:
    def test_conforming_class_is_domain_event(self) -> None:
        event = _FakeEvent(payload="test")
        assert isinstance(event, DomainEvent)

    def test_non_conforming_class_is_not_domain_event(self) -> None:
        obj = _NonEvent(payload="test")
        assert not isinstance(obj, DomainEvent)
