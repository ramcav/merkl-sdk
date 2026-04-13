"""MerklClient — main entry point for the Merkl SDK."""

from __future__ import annotations

from merkl.sdk.session_context import SessionContext
from merkl.sdk.transport import AsyncTransport


class MerklClient:
    """Client for Merkl — cryptographic accountability for AI agents.

    Usage:
        client = MerklClient(
            endpoint="https://api.merkl.ai",
            agent_id="agent-customer-support-v2",
            api_key="mk_...",
        )
        async with client.session(
            goal="Process refunds",
            allowed_tools=["query_db"],
        ) as session:
            result = await session.record_action(
                tool_name="query_db",
                input_data="SELECT ...",
                output_data={"rows": 42},
            )
            # result includes batch_id and leaf_index
    """

    def __init__(
        self,
        endpoint: str,
        agent_id: str,
        api_key: str,
        max_retries: int = 3,
        timeout: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._agent_id = agent_id
        self._api_key = api_key
        self._transport = AsyncTransport(
            base_url=endpoint,
            api_key=api_key,
            max_retries=max_retries,
            timeout=timeout,
        )

    def session(
        self,
        goal: str,
        allowed_tools: list[str] | None = None,
        data_scope: list[str] | None = None,
        policy: str = "default",
        workspace_external_id: str | None = None,
    ) -> SessionContext:
        """Create a session context manager.

        If workspace_external_id is omitted, the server resolves to the org's
        default workspace.
        """
        return SessionContext(
            transport=self._transport,
            agent_id=self._agent_id,
            goal=goal,
            allowed_tools=allowed_tools or [],
            data_scope=data_scope or [],
            policy_reference=policy,
            workspace_external_id=workspace_external_id,
        )

    async def close(self) -> None:
        """Close the underlying transport."""
        await self._transport.close()
