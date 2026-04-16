"""Session context manager — async with client.session(...) as session."""

from __future__ import annotations

from typing import Any

from merkl.sdk.transport import AsyncTransport
from merkl.shared.hashing import SHA256Hash


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
    ) -> None:
        self._transport = transport
        self._agent_id = agent_id
        self._goal = goal
        self._allowed_tools = allowed_tools
        self._data_scope = data_scope
        self._policy_reference = policy_reference
        self._workspace_external_id = workspace_external_id
        self._session_id: str | None = None
        self._action_count = 0
        self._summary: str | None = None

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
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if not self._session_id:
            return
        payload: dict[str, Any] = {}
        if self._summary is not None:
            payload["summary"] = self._summary
        try:
            await self._transport.post(
                f"/v1/sessions/{self._session_id}/close",
                json=payload,
            )
        except Exception:
            # Session may already be closed (force-seal, idle timeout).
            # __aexit__ is best-effort cleanup — don't raise inside it.
            pass

    async def close(self, summary: str | None = None) -> None:
        """Set an optional summary; sent to the API when the session exits."""
        self._summary = summary

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

        input_hash = SHA256Hash.from_bytes(
            str(input_data).encode()
        ).hex()
        output_hash = SHA256Hash.from_bytes(
            str(output_data).encode()
        ).hex()

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
            "input_preview": input_preview,
            "output_preview": output_preview,
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
