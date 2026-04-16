"""Tests for @trace and @guardrail decorators."""

from __future__ import annotations

import pytest

from merkl.sdk.decorators import (
    GuardrailBlocked,
    guardrail,
    set_current_session,
    trace,
)


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


class TestGuardrail:
    @pytest.mark.asyncio
    async def test_allowed_tool_passes_through(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @guardrail(allowed_tools=["do_thing"])
            async def do_thing() -> str:
                return "ok"

            result = await do_thing()
            assert result == "ok"
            assert len(mock.actions) == 1
            assert mock.actions[0]["guardrail_result"] == "passed"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_tool_not_in_allowed_blocks(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @guardrail(allowed_tools=["only_this"])
            async def dangerous_tool() -> str:
                return "should not run"

            with pytest.raises(GuardrailBlocked) as exc:
                await dangerous_tool()
            assert exc.value.tool_name == "dangerous_tool"
            assert "not in allowed_tools" in exc.value.reason
            assert len(mock.actions) == 1
            assert mock.actions[0]["status"] == "blocked"
            assert mock.actions[0]["guardrail_result"] == "blocked"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_check_callable_false_blocks(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @guardrail(check=lambda amount: amount <= 1000)
            async def transfer(amount: int) -> str:
                return "sent"

            with pytest.raises(GuardrailBlocked):
                await transfer(5000)
            assert mock.actions[0]["status"] == "blocked"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_check_returns_reason_string_blocks(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            def policy(amount: int) -> str:
                return "exceeds daily limit" if amount > 1000 else ""

            @guardrail(check=policy)
            async def transfer(amount: int) -> str:
                return "sent"

            with pytest.raises(GuardrailBlocked) as exc:
                await transfer(5000)
            assert exc.value.reason == "exceeds daily limit"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_on_block_skip_returns_none(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            @guardrail(check=lambda: False, on_block="skip")
            async def do_thing() -> str:
                return "ran"

            result = await do_thing()
            assert result is None
            assert mock.actions[0]["status"] == "blocked"
        finally:
            set_current_session(None)

    @pytest.mark.asyncio
    async def test_async_check_supported(self) -> None:
        mock = MockSession()
        set_current_session(mock)
        try:
            async def async_policy(x: int) -> bool:
                return x > 0

            @guardrail(check=async_policy)
            async def do_thing(x: int) -> int:
                return x

            assert await do_thing(5) == 5
            with pytest.raises(GuardrailBlocked):
                await do_thing(-1)
        finally:
            set_current_session(None)

    def test_sync_function_returned_unchanged(self) -> None:
        @guardrail(check=lambda: True)
        def sync_tool(x: int) -> int:
            return x * 2

        assert sync_tool(3) == 6
