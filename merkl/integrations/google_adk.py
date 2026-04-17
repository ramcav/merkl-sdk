"""Google ADK integration — wrapper for auto-recording tool calls.

Usage:
    from merkl.integrations.google_adk import MerklADKRunner

    async with witness.session(...) as session:
        runner = MerklADKRunner(session, agent=agent, app_name="my_app", session_service=svc)
        async for event in runner.run(user_id="u1", session_id="s1", message=msg):
            print(event)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from merkl.integrations._common import record_tool_call
from merkl.sdk.session_context import SessionContext


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
            witness_runner = MerklADKRunner(session, runner)
            adk_session = await session_service.create_session(app_name="demo", user_id="user")

            async for event in witness_runner.run(
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
