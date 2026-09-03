"""Google ADK integration — auto-record tool calls.

One-liner:

    from merkl.integrations.google_adk import instrument

    agent = instrument(LlmAgent(name="phillip", tools=[...]))
    await run_agent(agent=agent, ...)   # session opens, tool calls recorded, session seals

``instrument()`` wires three ADK callbacks:

* ``before_agent_callback``  → opens a Merkl session and binds it to a
  contextvar for the duration of the agent run. Client comes from the
  ``client`` arg or from ``MERKL_ENDPOINT`` / ``MERKL_API_KEY`` env vars.
* ``after_tool_callback``    → records every tool invocation against the
  active session, committing to the tool's real response.
* ``after_agent_callback``   → closes + seals the session.

If no client is available (env not set, explicit ``client=None``), the
callbacks no-op — safe to leave on in production.

If you already own the session lifecycle (opened via ``client.session(...)``
before the agent runs), pass ``auto_session=False``; the tool callback
still records to whatever session is bound to the contextvar.

Runner wrapper is still available for callers that don't own the agent:

    from merkl.integrations.google_adk import MerklADKRunner

    async with client.session(...) as session:
        async for event in MerklADKRunner(session, runner).run(...):
            ...
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import AsyncIterator, Callable
from typing import Any

from merkl.integrations._common import record_tool_call
from merkl.sdk.decorators import (
    get_current_session,
    reset_current_session,
    set_current_session,
)
from merkl.sdk.session_context import SessionContext

logger = logging.getLogger("merkl.adk")


def _debug(msg: str) -> None:
    """Dev-only stderr echo so diagnostic lines can't be swallowed by loguru
    or other logging replacements. Off unless MERKL_DEBUG=1."""
    if os.environ.get("MERKL_DEBUG", "0") != "0":
        print(f"[merkl] {msg}", file=sys.stderr, flush=True)
    logger.info(msg)

_INSTRUMENTED_ATTR = "_merkl_instrumented"

# Module-level registry: invocation_id → (session_cm, contextvar_token). ADK's
# ``callback_context.state`` is delta-tracked and rejects non-JSON objects,
# so we can't stash the open context manager there.
_active_invocations: dict[str, tuple[Any, Any]] = {}


def _invocation_key(callback_context: Any) -> str:
    """Best-effort stable key for one agent invocation."""
    return (
        getattr(callback_context, "invocation_id", None)
        or getattr(callback_context, "agent_name", "")
        or f"anon-{id(callback_context)}"
    )


def _default_client() -> Any | None:
    """Build a MerklClient from env vars, or return None if not configured."""
    endpoint = os.environ.get("MERKL_ENDPOINT")
    if not endpoint:
        return None
    # Import here so merkl.integrations.google_adk stays importable even
    # when the SDK client module has optional deps.
    from merkl.sdk import MerklClient

    return MerklClient(
        endpoint=endpoint,
        api_key=os.environ.get("MERKL_API_KEY", "mk_dev"),
        agent_id=os.environ.get("MERKL_AGENT_ID", "adk-agent"),
    )


def _resolve_goal(goal: Any, callback_context: Any) -> str:
    """Resolve the session goal — either static or via a callable(callback_context)."""
    if callable(goal):
        try:
            resolved = goal(callback_context)
        except Exception:
            resolved = ""
        return str(resolved) if resolved else "ADK agent run"
    if goal:
        return str(goal)
    # Try to pull the last user turn as the goal.
    user_content = getattr(callback_context, "user_content", None)
    if user_content is not None:
        parts = getattr(user_content, "parts", None) or []
        for part in parts:
            text = getattr(part, "text", None)
            if text:
                return str(text)[:200]
    return "ADK agent run"


def instrument(
    agent: Any,
    *,
    client: Any | None = None,
    goal: str | Callable[[Any], str] = "",
    allowed_tools: list[str] | None = None,
    data_scope: list[str] | None = None,
    policy: str = "adk-agent",
    auto_session: bool = True,
    drift_score: float = 0.0,
    guardrail_result: str = "not_evaluated",
    category: str = "",
) -> Any:
    """Wire Merkl recording into an ADK agent. One call, no boilerplate.

    By default (``auto_session=True``), a Merkl session opens at the start
    of each agent run and seals at the end. Tool calls during the run are
    recorded automatically. If ``MERKL_ENDPOINT`` is unset and no ``client``
    is passed, the callbacks no-op and the agent runs unchanged.

    Args:
        agent: Any ADK agent (``LlmAgent``, ``Agent``, ...).
        client: Optional explicit ``MerklClient``. Falls back to one built
            from ``MERKL_ENDPOINT`` / ``MERKL_API_KEY`` / ``MERKL_AGENT_ID``.
        goal: Session goal — either a string, or a callable that receives
            the ADK ``CallbackContext`` and returns a string. When omitted,
            the first user-message text block is used.
        allowed_tools: Declared tool allowlist on the session commitment.
            Defaults to the names of tools wired on the agent.
        data_scope: Passed through to the session commitment.
        policy: Passed through to the session commitment.
        auto_session: If False, skip session open/close — the tool callback
            still records into whatever session is active on the contextvar.
        drift_score, guardrail_result, category: Applied to every recorded
            tool call.

    Returns:
        The same agent, mutated in place.
    """
    if getattr(agent, _INSTRUMENTED_ATTR, False):
        return agent

    # ---------- tool recording ----------
    # Recording happens AFTER the tool runs so output_hash commits to the
    # real response. Recording before execution would hash a placeholder,
    # making the output commitment — and any later evidence match — meaningless.
    async def _merkl_after_tool(tool, args, tool_context, tool_response):  # type: ignore[no-untyped-def]
        session = get_current_session()
        if session is None:
            logger.debug("[merkl] after_tool %s: no active session", tool.name)
            return None
        try:
            await record_tool_call(
                session,
                tool_name=tool.name,
                input_data=dict(args) if args else {},
                output_data=tool_response,
                drift_score=drift_score,
                guardrail_result=guardrail_result,
                category=category,
            )
            _debug(f"recorded {tool.name}")
        except Exception:
            logger.exception("[merkl] record_tool_call failed for %s", tool.name)
        return None

    existing_tool_cb = getattr(agent, "after_tool_callback", None)
    if existing_tool_cb is None:
        agent.after_tool_callback = [_merkl_after_tool]
    elif isinstance(existing_tool_cb, list):
        agent.after_tool_callback = [*existing_tool_cb, _merkl_after_tool]
    else:
        agent.after_tool_callback = [existing_tool_cb, _merkl_after_tool]

    # ---------- session lifecycle (optional) ----------
    if auto_session:
        resolved_client = client if client is not None else _default_client()
        inferred_tools = allowed_tools or [
            getattr(t, "name", None) or getattr(t, "__name__", "tool")
            for t in (getattr(agent, "tools", None) or [])
        ]

        async def _merkl_before_agent(callback_context):  # type: ignore[no-untyped-def]
            agent_name = getattr(callback_context, "agent_name", "?")
            _debug(f"before_agent_callback fired (agent={agent_name})")
            if resolved_client is None:
                _debug("no client (MERKL_ENDPOINT unset) — skipping")
                return None
            try:
                session_cm = resolved_client.session(
                    goal=_resolve_goal(goal, callback_context),
                    allowed_tools=inferred_tools,
                    data_scope=data_scope or [],
                    policy=policy,
                )
                session = await session_cm.__aenter__()
                token = set_current_session(session)
                _active_invocations[_invocation_key(callback_context)] = (session_cm, token)
                _debug(f"session opened {session.session_id}")
            except Exception as e:
                logger.exception("[merkl] session open failed")
                _debug(f"session open failed: {e}")
            return None

        async def _merkl_after_agent(callback_context):  # type: ignore[no-untyped-def]
            key = _invocation_key(callback_context)
            entry = _active_invocations.pop(key, None)
            if entry is None:
                _debug(f"no active session for {key}")
                return None
            session_cm, token = entry
            try:
                await session_cm.__aexit__(None, None, None)
                _debug("session sealed")
            except Exception as e:
                logger.exception("[merkl] session close failed")
                _debug(f"session close failed: {e}")
            with contextlib.suppress(Exception):
                reset_current_session(token)
            return None

        existing_before = getattr(agent, "before_agent_callback", None)
        if existing_before is None:
            agent.before_agent_callback = _merkl_before_agent
        elif isinstance(existing_before, list):
            agent.before_agent_callback = [_merkl_before_agent, *existing_before]
        else:
            agent.before_agent_callback = [_merkl_before_agent, existing_before]

        existing_after = getattr(agent, "after_agent_callback", None)
        if existing_after is None:
            agent.after_agent_callback = _merkl_after_agent
        elif isinstance(existing_after, list):
            agent.after_agent_callback = [*existing_after, _merkl_after_agent]
        else:
            agent.after_agent_callback = [existing_after, _merkl_after_agent]

    setattr(agent, _INSTRUMENTED_ATTR, True)
    return agent


class MerklADKRunner:
    """Wraps a Google ADK Runner to auto-record tool calls in Merkl.

    Intercepts function call events from the ADK runner and records them
    as actions in the Merkl session.

    Usage:
        from google.adk import Agent
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService

        agent = Agent(name="analyst", model="gemini-2.5-flash", tools=[...])
        session_service = InMemorySessionService()
        runner = Runner(agent=agent, app_name="demo", session_service=session_service)

        client = MerklClient(endpoint="http://localhost:8000", agent_id="adk-agent", api_key="key")

        async with client.session(goal="...", ...) as session:
            merkl_runner = MerklADKRunner(session, runner)
            adk_session = await session_service.create_session(app_name="demo", user_id="user")

            async for event in merkl_runner.run(
                user_id="user", session_id=adk_session.id, message=user_msg
            ):
                # Events pass through — final text, etc.
                pass
    """

    def __init__(
        self,
        session: SessionContext,
        runner: Any,
        drift_score: float = 0.0,
        guardrail_result: str = "passed",
    ) -> None:
        self._session = session
        self._runner = runner
        self._drift_score = drift_score
        self._guardrail_result = guardrail_result

    async def run(
        self,
        user_id: str,
        session_id: str,
        message: Any,
    ) -> AsyncIterator[Any]:
        """Run the ADK agent and auto-record tool calls.

        Yields all events from the underlying runner.
        """
        async for event in self._runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=message,
        ):
            # Check for function calls
            function_calls = event.get_function_calls()
            if function_calls:
                for fc in function_calls:
                    tool_name = fc.name
                    tool_input = dict(fc.args) if fc.args else {}
                    await record_tool_call(
                        self._session,
                        tool_name=tool_name,
                        input_data=tool_input,
                        output_data="(pending)",
                        drift_score=self._drift_score,
                        guardrail_result=self._guardrail_result,
                    )

            yield event
