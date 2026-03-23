"""Tests for AgentId, SessionId, and ActionId value objects."""

from __future__ import annotations

import dataclasses
import time
import uuid

import pytest

from merkl.shared.errors import ValidationError
from merkl.shared.ids import ActionId, AgentId, SessionId


class TestAgentId:
    def test_stores_string(self) -> None:
        agent = AgentId("agent-customer-support-v2")
        assert agent.value == "agent-customer-support-v2"

    def test_immutable(self) -> None:
        agent = AgentId("agent-foo")
        with pytest.raises(dataclasses.FrozenInstanceError):
            agent.value = "agent-bar"  # type: ignore[misc]

    def test_equality(self) -> None:
        a1 = AgentId("agent-foo")
        a2 = AgentId("agent-foo")
        a3 = AgentId("agent-bar")
        assert a1 == a2
        assert a1 != a3

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValidationError, match="cannot be empty"):
            AgentId("")

    def test_str_representation(self) -> None:
        agent = AgentId("agent-test")
        assert str(agent) == "agent-test"


class TestSessionId:
    def test_generates_uuid7(self) -> None:
        sid = SessionId.generate()
        assert isinstance(sid.value, uuid.UUID)
        assert sid.value.version == 7

    def test_time_sortable(self) -> None:
        s1 = SessionId.generate()
        time.sleep(0.002)
        s2 = SessionId.generate()
        assert str(s1) < str(s2)

    def test_immutable(self) -> None:
        sid = SessionId.generate()
        with pytest.raises(dataclasses.FrozenInstanceError):
            sid.value = uuid.uuid4()  # type: ignore[misc]

    def test_from_str(self) -> None:
        sid = SessionId.generate()
        restored = SessionId.from_str(str(sid))
        assert restored == sid

    def test_str_representation(self) -> None:
        sid = SessionId.generate()
        assert str(sid) == str(sid.value)


class TestActionId:
    def test_generates_uuid7(self) -> None:
        aid = ActionId.generate()
        assert isinstance(aid.value, uuid.UUID)
        assert aid.value.version == 7

    def test_time_sortable(self) -> None:
        a1 = ActionId.generate()
        time.sleep(0.002)
        a2 = ActionId.generate()
        assert str(a1) < str(a2)

    def test_immutable(self) -> None:
        aid = ActionId.generate()
        with pytest.raises(dataclasses.FrozenInstanceError):
            aid.value = uuid.uuid4()  # type: ignore[misc]

    def test_from_str(self) -> None:
        aid = ActionId.generate()
        restored = ActionId.from_str(str(aid))
        assert restored == aid

    def test_equality(self) -> None:
        uid = uuid.uuid4()
        a1 = ActionId(value=uid)
        a2 = ActionId(value=uid)
        assert a1 == a2
