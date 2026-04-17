"""Shared helper for framework integrations.

Every framework adapter (LangChain, OpenAI, CrewAI, Google ADK) eventually
calls ``session.record_action(...)`` with the same shape. Centralizing the
call here means new action fields only need to be plumbed through one
place — adapters stay thin translators from framework-specific events to
the normalized payload.
"""

from __future__ import annotations

from typing import Any

from merkl.sdk.session_context import SessionContext


async def record_tool_call(
    session: SessionContext,
    *,
    tool_name: str,
    input_data: Any,
    output_data: Any,
    duration_ms: int = 0,
    drift_score: float = 0.0,
    guardrail_result: str = "passed",
    status: str = "success",
    display_name: str = "",
    category: str = "data_access",
    input_preview: str = "",
    output_preview: str = "",
    depends_on: list[str] | None = None,
) -> dict[str, Any]:
    """Record a tool invocation inside ``session``.

    Wraps ``SessionContext.record_action`` so framework adapters share a
    single call site. ``display_name`` falls back to ``tool_name`` when
    not explicitly supplied.
    """
    return await session.record_action(
        tool_name=tool_name,
        input_data=input_data,
        output_data=output_data,
        duration_ms=duration_ms,
        drift_score=drift_score,
        guardrail_result=guardrail_result,
        status=status,
        display_name=display_name or tool_name,
        category=category,
        input_preview=input_preview,
        output_preview=output_preview,
        depends_on=depends_on,
    )
