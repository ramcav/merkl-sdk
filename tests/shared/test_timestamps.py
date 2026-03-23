"""Tests for the Timestamp value object."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from merkl.shared.timestamps import Timestamp


class TestTimestamp:
    def test_now_is_utc(self) -> None:
        ts = Timestamp.now()
        assert ts.datetime.tzinfo == UTC

    def test_immutable(self) -> None:
        ts = Timestamp.now()
        with __import__("pytest").raises(dataclasses.FrozenInstanceError):
            ts.value = datetime.now(UTC)  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        dt = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        ts1 = Timestamp.from_datetime(dt)
        ts2 = Timestamp.from_datetime(dt)
        assert ts1 == ts2

    def test_ordering(self) -> None:
        dt1 = datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC)
        dt2 = datetime(2026, 3, 16, 13, 0, 0, tzinfo=UTC)
        ts1 = Timestamp.from_datetime(dt1)
        ts2 = Timestamp.from_datetime(dt2)
        assert ts1 < ts2

    def test_from_datetime_rejects_naive(self) -> None:
        naive = datetime(2026, 3, 16, 12, 0, 0)
        with __import__("pytest").raises(ValueError, match="timezone-aware"):
            Timestamp.from_datetime(naive)
