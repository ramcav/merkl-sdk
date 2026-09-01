"""Session context manager — async with client.session(...) as session."""

from __future__ import annotations

import contextvars
from typing import Any

from merkl.sdk.transport import AsyncTransport
from merkl.shared.hashing import canonical_hash


class SessionContext:
    """Context manager wrapping a Merkl session lifecycle.

    Usage:
        async with client.session(goal=..., ...) as session:
            result = await session.record_action(...)
    """

    def __init__(
        self,
        transport: AsyncTransport,
        agent_id: str,
        goal: str,
        allowed_tools: list[str],
        data_scope: list[str],
        policy_reference: str,
        workspace_external_id: str | None = None,
        include_previews: bool = True,
    ) -> None:
        self._transport = transport
        self._agent_id = agent_id
        self._goal = goal
        self._allowed_tools = allowed_tools
        self._data_scope = data_scope
        self._policy_reference = policy_reference
        self._workspace_external_id = workspace_external_id
        self._include_previews = include_previews
        self._session_id: str | None = None
        self._action_count = 0
        self._session_token: contextvars.Token[Any] | None = None

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def action_count(self) -> int:
        return self._action_count

    def _create_session_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": self._agent_id,
            "goal": self._goal,
            "allowed_tools": self._allowed_tools,
            "data_scope": self._data_scope,
            "policy_reference": self._policy_reference,
        }
        if self._workspace_external_id is not None:
            payload["workspace_external_id"] = self._workspace_external_id
        return payload

    async def __aenter__(self) -> SessionContext:
        resp = await self._transport.post(
            "/v1/sessions", json=self._create_session_payload()
        )
        self._session_id = resp["session_id"]
        # Bind this session to the contextvar so @trace/@guardrail inside
        # the `async with` block see it automatically. Inner contexts
        # shadow outer ones; __aexit__ restores.
        from merkl.sdk.decorators import set_current_session

        self._session_token = set_current_session(self)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        # Restore the previous session binding first — even if close() fails.
        if self._session_token is not None:
            from merkl.sdk.decorators import reset_current_session

            reset_current_session(self._session_token)
            self._session_token = None
        if not self._session_id:
            return
        try:
            await self._transport.post(
                f"/v1/sessions/{self._session_id}/close",
                json={},
            )
        except Exception:
            # Session may already be closed (force-seal, idle timeout).
            # __aexit__ is best-effort cleanup — don't raise inside it.
            pass

    async def record_action(
        self,
        tool_name: str,
        input_data: Any,
        output_data: Any,
        action_type: str = "tool_call",
        drift_score: float = 0.0,
        guardrail_result: str = "passed",
        duration_ms: int = 0,
        display_name: str = "",
        depends_on: list[str] | None = None,
        status: str = "success",
        category: str = "data_access",
        input_preview: str = "",
        output_preview: str = "",
    ) -> dict[str, Any]:
        """Record an action in this session."""
        if self._session_id is None:
            msg = "Session not opened. Use 'async with' context manager."
            raise RuntimeError(msg)

        input_hash = canonical_hash(input_data).hex()
        output_hash = canonical_hash(output_data).hex()

        action_payload = {
            "agent_id": self._agent_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "drift_score": drift_score,
            "guardrail_result": guardrail_result,
            "policy_reference": self._policy_reference,
            "duration_ms": duration_ms,
            "display_name": display_name,
            "depends_on": depends_on or [],
            "status": status,
            "category": category,
            "input_preview": input_preview if self._include_previews else "",
            "output_preview": output_preview if self._include_previews else "",
        }

        result: dict[str, Any] = await self._transport.post(
            f"/v1/sessions/{self._session_id}/actions",
            json=action_payload,
        )
        # Server may have routed the action to a continuation session if
        # ours was sealed (force-seal or idle timeout). Sync our state to
        # the session the server actually recorded on.
        returned_id = result.get("session_id")
        if returned_id and returned_id != self._session_id:
            self._session_id = returned_id
        self._action_count += 1
        return result
