"""Tests for SessionContext — integration with real notary via test app."""

from __future__ import annotations

import pytest

from merkl.sdk.session_context import SessionContext


class MockTransport:
    """Mock transport that captures requests."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, object]]] = []
        self._session_counter = 0

    async def post(self, path: str, json: dict[str, object]) -> dict[str, object]:
        self.requests.append((path, json))
        if path == "/v1/sessions":
            self._session_counter += 1
            return {
                "session_id": f"sess-{self._session_counter}",
                "commitment_hash": "a" * 64,
            }
        if "close" in path:
            return {"session_id": "sess-1", "status": "closed"}
        if "actions" in path:
            return {"action_id": "act-1", "session_id": "sess-1"}
        return {}

    async def get(self, path: str) -> dict[str, object]:
        return {}


class TestSessionContext:
    @pytest.mark.asyncio
    async def test_opens_and_closes_session(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1",
            goal="Test",
            allowed_tools=["tool"],
            data_scope=["data"],
            policy_reference="p1",
        )
        async with ctx:
            assert ctx.session_id == "sess-1"
        # Should have POST /sessions and POST /sessions/{id}/close
        paths = [r[0] for r in transport.requests]
        assert paths[0] == "/v1/sessions"
        assert "close" in paths[-1]

    @pytest.mark.asyncio
    async def test_record_action_in_session(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1",
            goal="Test",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p1",
        )
        async with ctx:
            result = await ctx.record_action(
                tool_name="query_db",
                input_data="SELECT *",
                output_data=[{"id": 1}],
            )
            assert result["action_id"] == "act-1"
        assert ctx.action_count == 1

    @pytest.mark.asyncio
    async def test_record_action_without_session_raises(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="a",
            goal="g",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p",
        )
        with pytest.raises(RuntimeError, match="not opened"):
            await ctx.record_action(tool_name="t", input_data="", output_data="")

    @pytest.mark.asyncio
    async def test_action_count_increments(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="a",
            goal="g",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p",
        )
        async with ctx:
            for _ in range(5):
                await ctx.record_action(
                    tool_name="t", input_data="", output_data=""
                )
        assert ctx.action_count == 5

    @pytest.mark.asyncio
    async def test_session_id_before_open_is_none(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="a",
            goal="g",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p",
        )
        assert ctx.session_id is None
