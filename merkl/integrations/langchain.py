"""LangChain integration — auto-record tool calls via callback handler.

Usage:
    from merkl.integrations.langchain import MerklCallbackHandler

    async with witness.session(goal="...", ...) as session:
        handler = MerklCallbackHandler(session)
        result = await chain.ainvoke(input, config={"callbacks": [handler]})
"""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks import AsyncCallbackHandler
except ImportError as e:
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it with: pip install langchain-core"
    ) from e

from merkl.sdk.session_context import SessionContext


class MerklCallbackHandler(AsyncCallbackHandler):
    """LangChain async callback handler that records tool calls in a Merkl session.

    Automatically captures tool invocations (name, input, output, duration)
    and records them as actions in the Merkl audit trail.

    Usage:
        witness = MerklClient(endpoint="http://localhost:8000", agent_id="my-agent", api_key="key")

        async with witness.session(goal="Answer question", allowed_tools=["search"]) as session:
            handler = MerklCallbackHandler(session)
            result = await chain.ainvoke({"input": "..."}, config={"callbacks": [handler]})
            # All tool calls are now recorded in the Merkl session
    """

    def __init__(
        self,
        session: SessionContext,
        drift_score: float = 0.0,
        guardrail_result: str = "passed",
    ) -> None:
        super().__init__()
        self._session = session
        self._drift_score = drift_score
        self._guardrail_result = guardrail_result
        self._tool_starts: dict[str, tuple[float, str, Any]] = {}

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        self._tool_starts[str(run_id)] = (time.monotonic(), tool_name, input_str)

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id)
        start_time, tool_name, input_str = self._tool_starts.pop(
            run_key, (time.monotonic(), "unknown", "")
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)

        await self._session.record_action(
            tool_name=tool_name,
            input_data=input_str,
            output_data=str(output),
            duration_ms=duration_ms,
            drift_score=self._drift_score,
            guardrail_result=self._guardrail_result,
        )

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id)
        start_time, tool_name, input_str = self._tool_starts.pop(
            run_key, (time.monotonic(), "unknown", "")
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)

        await self._session.record_action(
            tool_name=tool_name,
            input_data=input_str,
            output_data=f"ERROR: {error}",
            duration_ms=duration_ms,
            drift_score=self._drift_score,
            guardrail_result="blocked",
        )
