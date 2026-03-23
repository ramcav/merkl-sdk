"""CrewAI integration — step callback for auto-recording in Merkl.

Usage:
    from merkl.integrations.crewai import MerklStepCallback

    async with witness.session(...) as session:
        callback = MerklStepCallback(session)
        task = Task(..., callback=callback)
"""

from __future__ import annotations

import asyncio
from typing import Any

from merkl.sdk.session_context import SessionContext


class MerklStepCallback:
    """CrewAI step callback that records tool usage in a Merkl session.

    Pass this as the `step_callback` parameter to a CrewAI Task or Agent.
    It intercepts each step and records tool calls in the Merkl audit trail.

    Usage:
        witness = MerklClient(endpoint="...", agent_id="crew-agent", api_key="key")

        async with witness.session(goal="Research task", ...) as session:
            callback = MerklStepCallback(session)
            task = Task(
                description="...",
                agent=agent,
                callback=callback,
            )
            crew = Crew(agents=[agent], tasks=[task])
            result = crew.kickoff()
    """

    def __init__(
        self,
        session: SessionContext,
        drift_score: float = 0.0,
        guardrail_result: str = "passed",
    ) -> None:
        self._session = session
        self._drift_score = drift_score
        self._guardrail_result = guardrail_result

    def __call__(self, step_output: Any) -> None:
        """Called by CrewAI after each agent step."""
        # CrewAI step_output has .tool, .tool_input, .result attributes
        tool_name = getattr(step_output, "tool", None)
        if not tool_name:
            return

        tool_input = getattr(step_output, "tool_input", "")
        result = getattr(step_output, "result", "")

        # CrewAI runs synchronously, so we need to bridge to async
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self._session.record_action(
                    tool_name=str(tool_name),
                    input_data=tool_input,
                    output_data=result,
                    drift_score=self._drift_score,
                    guardrail_result=self._guardrail_result,
                )
            )
        except RuntimeError:
            # No running event loop — run synchronously
            asyncio.run(
                self._session.record_action(
                    tool_name=str(tool_name),
                    input_data=tool_input,
                    output_data=result,
                    drift_score=self._drift_score,
                    guardrail_result=self._guardrail_result,
                )
            )
