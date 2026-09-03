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
    async def test_syncs_session_id_when_server_routes_to_successor(self) -> None:
        """Server-driven continuation: when an action POST to a sealed
        session auto-routes to a successor, the action response carries
        the successor's session_id. The SDK syncs its ctx.session_id to
        match, so subsequent calls go to the right place."""

        class _ServerDrivenSuccessor:
            def __init__(self) -> None:
                self._first_action_done = False

            async def post(self, path: str, json: dict[str, object]) -> dict[str, object]:
                if path == "/v1/sessions":
                    return {"session_id": "sess-1", "commitment_hash": "a" * 64}
                if "close" in path:
                    return {"session_id": path.split("/")[3], "status": "closed"}
                if "actions" in path:
                    if not self._first_action_done:
                        self._first_action_done = True
                        return {"action_id": "act-1", "session_id": "sess-1", "leaf_index": 0}
                    # Server routed to successor: response carries new id
                    return {"action_id": "act-2", "session_id": "sess-2", "leaf_index": 1}
                return {}

            async def get(self, path: str) -> dict[str, object]:
                return {}

        transport = _ServerDrivenSuccessor()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="agent-1", goal="T", allowed_tools=[],
            data_scope=[], policy_reference="p1",
        )
        async with ctx:
            assert ctx.session_id == "sess-1"
            r1 = await ctx.record_action(
                tool_name="t", input_data="i1", output_data="o1",
            )
            assert r1["session_id"] == "sess-1"
            assert ctx.session_id == "sess-1"

            r2 = await ctx.record_action(
                tool_name="t", input_data="i2", output_data="o2",
            )
            assert r2["session_id"] == "sess-2"
            # SDK followed the server's route
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
            include_previews=True,
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


class TestPrivacyKnobs:
    @pytest.mark.asyncio
    async def test_include_previews_false_blanks_previews(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="a", goal="g", allowed_tools=[], data_scope=[], policy_reference="p",
            include_previews=False,
        )
        async with ctx:
            await ctx.record_action(
                tool_name="t", input_data="secret", output_data="reply",
                input_preview="secret", output_preview="reply",
            )
        action_req = [r for r in transport.requests if "actions" in r[0]][0]
        assert action_req[1]["input_preview"] == ""
        assert action_req[1]["output_preview"] == ""

    @pytest.mark.asyncio
    async def test_include_previews_true_sends_previews(self) -> None:
        transport = MockTransport()
        ctx = SessionContext(
            transport=transport,  # type: ignore[arg-type]
            agent_id="a", goal="g", allowed_tools=[], data_scope=[], policy_reference="p",
            include_previews=True,
        )
        async with ctx:
            await ctx.record_action(
                tool_name="t", input_data="x", output_data="y",
                input_preview="in", output_preview="out",
            )
        action_req = [r for r in transport.requests if "actions" in r[0]][0]
        assert action_req[1]["input_preview"] == "in"
        assert action_req[1]["output_preview"] == "out"
