"""Shared test fixtures for merkl-sdk tests."""

from __future__ import annotations

import pytest

from merkl.shared.ids import ActionId, AgentId, SessionId
from merkl.shared.timestamps import Timestamp


@pytest.fixture
def sample_agent_id() -> AgentId:
    """A sample agent identifier for testing."""
    return AgentId(value="agent-customer-support-v2")


@pytest.fixture
def sample_session_id() -> SessionId:
    """A freshly generated session identifier for testing."""
    return SessionId.generate()


@pytest.fixture
def sample_action_id() -> ActionId:
    """A freshly generated action identifier for testing."""
    return ActionId.generate()


@pytest.fixture
def sample_timestamp() -> Timestamp:
    """A current-time timestamp for testing."""
    return Timestamp.now()
