"""@trace and @guardrail decorators for automatic action recording."""

from __future__ import annotations

import contextvars
import functools
import inspect
import time
from collections.abc import Callable
from typing import Any, Literal, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# ContextVar so concurrent asyncio tasks and sub-agents each see their own
# active session instead of racing over a module-level global.
_current_session_var: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "merkl_current_session", default=None,
)


def set_current_session(session: Any) -> contextvars.Token[Any]:
    """Set the active session used by @trace and @guardrail.

    Returns a token that can be passed to :func:`reset_current_session` to
    restore the previous value. ``SessionContext`` does this automatically
    inside ``async with``.
    """
    return _current_session_var.set(session)


def reset_current_session(token: contextvars.Token[Any]) -> None:
    """Restore the prior session bound before the matching ``set_current_session``."""
    _current_session_var.reset(token)


def get_current_session() -> Any:
    """Get the current active session (contextvar-scoped)."""
    return _current_session_var.get()


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


class GuardrailBlocked(RuntimeError):
    """Raised when a @guardrail-wrapped call is denied by policy."""

    def __init__(self, tool_name: str, reason: str) -> None:
        super().__init__(f"Guardrail blocked {tool_name}: {reason}")
        self.tool_name = tool_name
        self.reason = reason


def guardrail(
    check: Callable[..., Any] | None = None,
    *,
    allowed_tools: list[str] | None = None,
    on_block: Literal["raise", "skip"] = "raise",
    policy_reference: str = "",
) -> Callable[[F], F]:
    """Decorator that gates a tool call through a policy check.

    Evaluation order: if `allowed_tools` is set and the function name is not
    in the list, the call is blocked. Otherwise `check(*args, **kwargs)` is
    invoked (async or sync); a falsy return or a non-empty string is treated
    as a block, with the string used as the reason.

    Blocks are recorded as an Action with `status="blocked"` and
    `guardrail_result="blocked"` — the audit trail captures guardrails
    working, not just what the agent did. On block, behavior depends on
    `on_block`: "raise" (default) throws `GuardrailBlocked`; "skip" returns
    None without running the function.

    Async-only for the wrapped fn; sync functions are returned unchanged.
    """

    def decorator(fn: F) -> F:
        if not inspect.iscoroutinefunction(fn):
            return fn

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            session = get_current_session()
            reason = await _evaluate_guardrail(
                fn.__name__, check, allowed_tools, args, kwargs
            )
            if reason is not None:
                if session is not None:
                    await session.record_action(
                        tool_name=fn.__name__,
                        input_data={"args": str(args), "kwargs": str(kwargs)},
                        output_data={"blocked": reason},
                        status="blocked",
                        guardrail_result="blocked",
                        display_name=fn.__name__,
                    )
                if on_block == "raise":
                    raise GuardrailBlocked(fn.__name__, reason)
                return None

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
                    guardrail_result="passed",
                )
            return result

        return wrapper  # type: ignore[return-value]

    # policy_reference is reserved for future use (e.g. linking blocks
    # to a policy doc); keep in signature but unused to avoid breaking
    # callers when it becomes wired through.
    _ = policy_reference
    return decorator


async def _evaluate_guardrail(
    tool_name: str,
    check: Callable[..., Any] | None,
    allowed_tools: list[str] | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str | None:
    """Run policy checks; return block reason string, or None when allowed."""
    if allowed_tools is not None and tool_name not in allowed_tools:
        return f"tool '{tool_name}' not in allowed_tools"
    if check is None:
        return None
    verdict = check(*args, **kwargs)
    if inspect.isawaitable(verdict):
        verdict = await verdict
    if isinstance(verdict, str):
        return verdict if verdict else None
    return None if verdict else "policy check returned False"
