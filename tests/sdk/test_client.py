"""Tests for MerklClient."""

from __future__ import annotations

from merkl.sdk.client import MerklClient
from merkl.sdk.session_context import SessionContext


class TestMerklClient:
    def test_creates_with_config(self) -> None:
        client = MerklClient(
            endpoint="http://localhost:8000",
            agent_id="agent-1",
            api_key="mk_test",
        )
        assert client._agent_id == "agent-1"
        assert client._endpoint == "http://localhost:8000"

    def test_session_returns_context(self) -> None:
        client = MerklClient(
            endpoint="http://localhost:8000",
            agent_id="agent-1",
            api_key="mk_test",
        )
        ctx = client.session(
            goal="Test",
            allowed_tools=["tool_a"],
            data_scope=["data"],
            policy="p1",
        )
        assert isinstance(ctx, SessionContext)

    def test_session_defaults(self) -> None:
        client = MerklClient(
            endpoint="http://localhost:8000",
            agent_id="agent-1",
            api_key="mk_test",
        )
        ctx = client.session(goal="Test")
        assert ctx._allowed_tools == []
        assert ctx._data_scope == []
        assert ctx._policy_reference == "default"
