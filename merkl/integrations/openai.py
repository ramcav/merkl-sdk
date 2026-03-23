"""OpenAI Agents SDK integration — wrap tools to auto-record in Merkl.

Usage:
    from merkl.integrations.openai import merkl_tool

    @merkl_tool(session)
    async def search(query: str) -> str:
        ...
"""

from __future__ import annotations

import functools
import time
from typing import Any, Callable, TypeVar

from merkl.sdk.session_context import SessionContext

F = TypeVar("F", bound=Callable[..., Any])


def merkl_tool(session: SessionContext, **record_kwargs: Any) -> Callable[[F], F]:
    """Decorator that wraps an async tool function to record calls in Merkl.

    Args:
        session: Active Merkl session context.
        **record_kwargs: Extra kwargs passed to record_action (e.g. drift_score).

    Usage:
        async with witness.session(...) as session:
            @merkl_tool(session)
            async def my_tool(query: str) -> str:
                return await do_search(query)

            # Or wrap existing tools:
            wrapped = merkl_tool(session)(original_tool)
    """
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            try:
                result = await fn(*args, **kwargs)
                duration_ms = int((time.monotonic() - start) * 1000)
                await session.record_action(
                    tool_name=fn.__name__,
                    input_data={"args": args, "kwargs": kwargs},
                    output_data=result,
                    duration_ms=duration_ms,
                    guardrail_result=record_kwargs.get("guardrail_result", "passed"),
                    drift_score=record_kwargs.get("drift_score", 0.0),
                )
                return result
            except Exception as e:
                duration_ms = int((time.monotonic() - start) * 1000)
                await session.record_action(
                    tool_name=fn.__name__,
                    input_data={"args": args, "kwargs": kwargs},
                    output_data=f"ERROR: {e}",
                    duration_ms=duration_ms,
                    guardrail_result="blocked",
                    drift_score=record_kwargs.get("drift_score", 0.0),
                )
                raise
        return wrapper  # type: ignore[return-value]
    return decorator


def merkl_tools(
    session: SessionContext,
    tools: list[Callable[..., Any]],
    **record_kwargs: Any,
) -> list[Callable[..., Any]]:
    """Wrap a list of tool functions to auto-record in Merkl.

    Args:
        session: Active Merkl session context.
        tools: List of async tool functions.
        **record_kwargs: Extra kwargs passed to record_action.

    Returns:
        List of wrapped tool functions.

    Usage:
        tools = merkl_tools(session, [search, calculator, get_date])
        agent = Agent(tools=tools, ...)
    """
    return [merkl_tool(session, **record_kwargs)(t) for t in tools]
