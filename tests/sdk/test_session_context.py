"""Tests for SessionContext — integration with real merkl-api via test app."""

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
    async def test_record_action_auto_resumes_after_seal(self) -> None:
        """If the server reports the session is already sealed (e.g. a
        dashboard force-seal or the idle timeout fired), the SDK starts a
        fresh session with the same params and retries once. Caller sees
        success; the new session_id is reflected on the context."""

        class _SealAfterFirstAction:
            def __init__(self) -> None:
                self.requests: list[tuple[str, dict[str, object]]] = []
                self._session_counter = 0
                self._first_record_done = False

            async def post(self, path: str, json: dict[str, object]) -> dict[str, object]:
                self.requests.append((path, json))
                if path == "/v1/sessions":
                    self._session_counter += 1
                    return {
                        "session_id": f"sess-{self._session_counter}",
                        "commitment_hash": "a" * 64,
                    }
                if "close" in path:
                    return {"session_id": path.split("/")[3], "status": "closed"}
                if "actions" in path:
                    # First action succeeds on sess-1; second action on sess-1
                    # triggers a seal error; retry on sess-2 succeeds.
                    if not self._first_record_done:
                        self._first_record_done = True
                        return {"action_id": "act-1", "session_id": "sess-1", "leaf_index": 0}
                    session_in_path = path.split("/")[3]
                    if session_in_path == "sess-1":
                        from merkl.sdk.transport import ApiError
                        raise ApiError(
                            status=422,
                            error_code="session_sealed",
                            detail="Session sess-1 is already sealed.",
                        )
                    return {"action_id": "act-2", "session_id": session_in_path, "leaf_index": 0}
                return {}

            async def get(self, path: str) -> dict[str, object]:
                return {}

        transport = _SealAfterFirstAction()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1",
            goal="T",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p1",
        )
        async with ctx:
            assert ctx.session_id == "sess-1"
            r1 = await ctx.record_action(
                tool_name="t", input_data="i1", output_data="o1",
            )
            assert r1["session_id"] == "sess-1"

            r2 = await ctx.record_action(
                tool_name="t", input_data="i2", output_data="o2",
            )
            # Auto-resumed onto a new session
            assert r2["session_id"] == "sess-2"
            assert ctx.session_id == "sess-2"
            assert ctx.action_count == 2

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


class TestSessionContextV2:
    @pytest.mark.asyncio
    async def test_record_action_sends_v2_fields(self) -> None:
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
            await ctx.record_action(
                tool_name="query_db",
                input_data="SELECT *",
                output_data="result",
                display_name="Looked up order",
                depends_on=["dep-1"],
                status="success",
                category="payment",
                input_preview="SELECT *",
                output_preview="1 row",
            )
        # Find the action request
        action_req = [r for r in transport.requests if "actions" in r[0]][0]
        payload = action_req[1]
        assert payload["display_name"] == "Looked up order"
        assert payload["depends_on"] == ["dep-1"]
        assert payload["status"] == "success"
        assert payload["category"] == "payment"
        assert payload["input_preview"] == "SELECT *"
        assert payload["output_preview"] == "1 row"

    @pytest.mark.asyncio
    async def test_record_action_backward_compat(self) -> None:
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
            await ctx.record_action(
                tool_name="query_db",
                input_data="x",
                output_data="y",
            )
        action_req = [r for r in transport.requests if "actions" in r[0]][0]
        payload = action_req[1]
        assert payload["display_name"] == ""
        assert payload["depends_on"] == []
        assert payload["status"] == "success"
        assert payload["category"] == "data_access"

    @pytest.mark.asyncio
    async def test_close_sends_summary(self) -> None:
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
            await ctx.close(summary="All done")
        close_req = [r for r in transport.requests if "close" in r[0]][0]
        assert close_req[1]["summary"] == "All done"

    @pytest.mark.asyncio
    async def test_close_without_summary(self) -> None:
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
            pass
        close_req = [r for r in transport.requests if "close" in r[0]][0]
        assert close_req[1].get("summary") is None


class TestWorkspaceExternalId:
    @pytest.mark.asyncio
    async def test_workspace_external_id_sent_when_provided(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1",
            goal="g",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p",
            workspace_external_id="hospital-sf",
        )
        async with ctx:
            pass
        create_req = [r for r in transport.requests if r[0] == "/v1/sessions"][0]
        assert create_req[1]["workspace_external_id"] == "hospital-sf"

    @pytest.mark.asyncio
    async def test_workspace_external_id_omitted_when_not_provided(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1",
            goal="g",
            allowed_tools=[],
            data_scope=[],
            policy_reference="p",
        )
        async with ctx:
            pass
        create_req = [r for r in transport.requests if r[0] == "/v1/sessions"][0]
        assert "workspace_external_id" not in create_req[1]
