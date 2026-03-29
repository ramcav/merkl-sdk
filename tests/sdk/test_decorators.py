"""Tests for @trace decorator."""

from __future__ import annotations

import pytest

from merkl.sdk.decorators import set_current_session, trace


class MockSession:
    """Mock session that captures recorded actions."""

    def __init__(self) -> None:
        self.actions: list[dict[str, object]] = []

    async def record_action(self, **kwargs: object) -> dict[str, object]:
        self.actions.append(kwargs)
        return {"action_id": "mock-id"}


class TestTrace:
    @pytest.mark.asyncio
    async def test_trace_captures_call(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @trace
            async def my_tool(x: int) -> str:
                return f"result-{x}"

            result = await my_tool(42)
            assert result == "result-42"
            assert len(mock.actions) == 1
            assert mock.actions[0]["tool_name"] == "my_tool"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_trace_captures_timing(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @trace
            async def slow_tool() -> str:
                return "done"

            await slow_tool()
            assert "duration_ms" in mock.actions[0]
            assert isinstance(mock.actions[0]["duration_ms"], int)
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_trace_no_session_still_works(self) -> None:
        set_current_session(None)

        @trace
        async def my_tool() -> str:
            return "ok"

        result = await my_tool()
        assert result == "ok"

    def test_trace_sync_returns_unchanged(self) -> None:
        @trace
        def my_sync_tool(x: int) -> int:
            return x * 2

        result = my_sync_tool(5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_trace_preserves_name(self) -> None:
        @trace
        async def my_named_function() -> None:
            pass

        assert my_named_function.__name__ == "my_named_function"

    @pytest.mark.asyncio
    async def test_trace_captures_output(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @trace
            async def get_data() -> list[int]:
                return [1, 2, 3]

            result = await get_data()
            assert result == [1, 2, 3]
            assert mock.actions[0]["output_data"] == "[1, 2, 3]"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_trace_passes_display_name(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @trace
            async def lookup_order(order_id: int) -> str:
                return "found"

            await lookup_order(42)
            assert mock.actions[0]["display_name"] == "lookup_order"
        finally:
            set_current_session(None)
