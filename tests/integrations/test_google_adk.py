"""Tests for the Google ADK integration helpers.

The real ``google.adk`` package is a heavy optional dep; these tests only
exercise the surface our integration touches: an object with a
``after_tool_callback`` attribute, a tool with a ``name``, and an async
Merkl session exposing ``record_action``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from merkl.integrations.google_adk import instrument
from merkl.sdk.decorators import reset_current_session, set_current_session


@dataclass
class FakeAgent:
    """Minimal stand-in for an ADK ``LlmAgent``."""

    before_tool_callback: Any = None
    after_tool_callback: Any = None
    before_agent_callback: Any = None
    after_agent_callback: Any = None
    tools: list = field(default_factory=list)


@dataclass
class FakeTool:
    name: str


@dataclass
class FakeSession:
    recorded: list[dict] = field(default_factory=list)

    async def record_action(self, **kwargs: Any) -> dict[str, Any]:
        self.recorded.append(kwargs)
        return {"action_id": f"a-{len(self.recorded)}", "leaf_index": len(self.recorded) - 1}


def test_instrument_attaches_callback_when_none():
    agent = FakeAgent(after_tool_callback=None)
    instrument(agent)
    assert isinstance(agent.after_tool_callback, list)
    assert len(agent.after_tool_callback) == 1


def test_instrument_appends_after_existing_list():
    """Merkl records last, so an earlier callback that mutates the response
    is committed as the tool's final output."""
    def other_cb(tool, args, ctx, resp):  # noqa: ANN001
        return None

    agent = FakeAgent(after_tool_callback=[other_cb])
    instrument(agent)
    assert len(agent.after_tool_callback) == 2
    assert agent.after_tool_callback[0] is other_cb


def test_instrument_wraps_single_callback():
    def other_cb(tool, args, ctx, resp):  # noqa: ANN001
        return None

    agent = FakeAgent(after_tool_callback=other_cb)
    instrument(agent)
    assert isinstance(agent.after_tool_callback, list)
    assert other_cb in agent.after_tool_callback


def test_instrument_is_idempotent():
    agent = FakeAgent()
    instrument(agent)
    instrument(agent)
    instrument(agent)
    assert len(agent.after_tool_callback) == 1


def test_callback_records_to_active_session():
    """Happy path: callback fires, reads the contextvar, writes to session."""
    agent = FakeAgent()
    instrument(agent)
    callback = agent.after_tool_callback[0]

    session = FakeSession()
    token = set_current_session(session)
    try:
        result = asyncio.run(
            callback(FakeTool(name="get_door_code"), {"booking_id": "abc"}, None, {"code": "1234"})
        )
    finally:
        reset_current_session(token)

    assert result is None  # must not short-circuit the tool
    assert len(session.recorded) == 1
    assert session.recorded[0]["tool_name"] == "get_door_code"
    assert session.recorded[0]["input_data"] == {"booking_id": "abc"}
    # output_hash commits to the REAL response, not a placeholder
    assert session.recorded[0]["output_data"] == {"code": "1234"}


def test_callback_noop_without_session():
    agent = FakeAgent()
    instrument(agent)
    callback = agent.after_tool_callback[0]

    # No active session — callback should silently do nothing and return None.
    result = asyncio.run(callback(FakeTool(name="local_search"), {"q": "pizza"}, None, "results"))
    assert result is None


def test_callback_swallows_record_errors():
    """Tracing must never break the agent even if the transport explodes."""

    class BoomSession:
        async def record_action(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("transport broke")

    agent = FakeAgent()
    instrument(agent)
    callback = agent.after_tool_callback[0]

    token = set_current_session(BoomSession())
    try:
        result = asyncio.run(callback(FakeTool(name="x"), {}, None, "out"))
    finally:
        reset_current_session(token)

    assert result is None  # boom was swallowed


def test_instrument_returns_same_agent_for_decorator_use():
    agent = FakeAgent()
    returned = instrument(agent, auto_session=False)
    assert returned is agent


# ---------------------------------------------------------------------------
# Auto-session lifecycle
# ---------------------------------------------------------------------------


class FakeSessionCM:
    """Mimics ``SessionContext`` as an async context manager."""

    def __init__(self, session: FakeSession):
        self._session = session
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> FakeSession:
        self.entered = True
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.exited = True


@dataclass
class FakeClient:
    session_obj: FakeSession = field(default_factory=FakeSession)
    opened_cms: list[FakeSessionCM] = field(default_factory=list)
    last_kwargs: dict = field(default_factory=dict)

    def session(self, **kwargs: Any) -> FakeSessionCM:
        self.last_kwargs = kwargs
        cm = FakeSessionCM(self.session_obj)
        self.opened_cms.append(cm)
        return cm


@dataclass
class FakeCallbackContext:
    state: dict = field(default_factory=dict)
    user_content: Any = None


@dataclass
class _FakePart:
    text: str | None = None


@dataclass
class _FakeUserContent:
    parts: list[_FakePart] = field(default_factory=list)


def _agent_with_tools(tool_names: list[str]) -> FakeAgent:
    agent = FakeAgent()
    agent.tools = [FakeTool(name=n) for n in tool_names]
    return agent


def test_auto_session_opens_and_closes_around_agent_run():
    """Callbacks must share one event loop (contextvars don't cross loops)."""
    client = FakeClient()
    agent = _agent_with_tools(["get_door_code", "local_search"])
    instrument(agent, client=client, goal="Help the guest")

    before = agent.before_agent_callback
    after = agent.after_agent_callback
    tool_cb = agent.after_tool_callback[0]

    ctx = FakeCallbackContext()

    async def _run_lifecycle():
        await before(ctx)
        assert len(client.opened_cms) == 1 and client.opened_cms[0].entered
        await tool_cb(FakeTool(name="get_door_code"), {"bid": "abc"}, None, "4321")
        await after(ctx)
        assert client.opened_cms[0].exited
        # After close, contextvar reset — recording is a no-op.
        await tool_cb(FakeTool(name="get_door_code"), {"bid": "xyz"}, None, "0000")

    asyncio.run(_run_lifecycle())
    assert len(client.session_obj.recorded) == 1
    assert client.session_obj.recorded[0]["tool_name"] == "get_door_code"


def test_instrument_infers_allowed_tools_from_agent():
    client = FakeClient()
    agent = _agent_with_tools(["a", "b", "c"])
    instrument(agent, client=client)

    asyncio.run(agent.before_agent_callback(FakeCallbackContext()))
    assert client.last_kwargs["allowed_tools"] == ["a", "b", "c"]


def test_instrument_noop_when_no_client_available(monkeypatch):
    monkeypatch.delenv("MERKL_ENDPOINT", raising=False)

    agent = _agent_with_tools(["t"])
    instrument(agent)  # no client, no env

    # Lifecycle callbacks installed but no session opens.
    asyncio.run(agent.before_agent_callback(FakeCallbackContext()))
    # Tool recording is a safe no-op.
    asyncio.run(
        agent.after_tool_callback[0](FakeTool(name="t"), {}, None, "out")
    )
    asyncio.run(agent.after_agent_callback(FakeCallbackContext()))


def test_goal_callable_receives_callback_context():
    client = FakeClient()
    seen = {}

    def goal_fn(ctx):
        seen["ctx"] = ctx
        return "resolved goal"

    agent = _agent_with_tools(["t"])
    instrument(agent, client=client, goal=goal_fn)

    ctx = FakeCallbackContext()
    asyncio.run(agent.before_agent_callback(ctx))
    assert seen["ctx"] is ctx
    assert client.last_kwargs["goal"] == "resolved goal"


def test_goal_falls_back_to_first_user_message_text():
    client = FakeClient()
    agent = _agent_with_tools(["t"])
    instrument(agent, client=client)

    ctx = FakeCallbackContext(
        user_content=_FakeUserContent(parts=[_FakePart(text="Can I have my code?")])
    )
    asyncio.run(agent.before_agent_callback(ctx))
    assert client.last_kwargs["goal"] == "Can I have my code?"


def test_auto_session_false_skips_lifecycle_callbacks():
    agent = _agent_with_tools(["t"])
    instrument(agent, auto_session=False)
    assert agent.before_agent_callback is None
    assert agent.after_agent_callback is None
    # Tool callback is still present.
    assert callable(agent.after_tool_callback[0])
