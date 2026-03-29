"""@trace decorator for automatic action recording."""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

_current_session: Any = None


def set_current_session(session: Any) -> None:
    """Set the global session reference (called by SessionContext.__aenter__)."""
    global _current_session  # noqa: PLW0603
    _current_session = session


def get_current_session() -> Any:
    """Get the current active session."""
    return _current_session


def trace(fn: F) -> F:
    """Decorator that traces async function calls, capturing input/output/timing.

    The traced data is sent as an ActionRecord to the current session.
    If no session is active, the function executes normally without tracing.
    Only works with async functions — sync functions are returned unchanged.
    """
    if not inspect.iscoroutinefunction(fn):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        session = get_current_session()
        start = time.monotonic()
        result = await fn(*args, **kwargs)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        if session is not None:
            await session.record_action(
                tool_name=fn.__name__,
                input_data={"args": str(args), "kwargs": str(kwargs)},
                output_data=str(result),
                duration_ms=elapsed_ms,
                display_name=fn.__name__,
            )
        return result

    return wrapper  # type: ignore[return-value]
