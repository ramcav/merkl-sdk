#!/usr/bin/env python3
"""Basic Merkl integration — raw Python agent example.

Demonstrates how to use the Merkl SDK to create a session, record
actions with @trace, and verify the audit trail.

Usage:
    # Start the notary first (merkl-api repo):
    #   AUTH_DISABLED=true uvicorn app.docker_entry:factory --factory --port 8000

    python examples/basic_agent.py
"""

from __future__ import annotations

import asyncio

from merkl.sdk import MerklClient, guardrail, trace


async def main() -> None:
    # Initialize the Merkl client
    client = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="basic-agent-001",
        api_key="mk_dev_key",
    )

    # Open a recorded session
    async with client.session(
        goal="Process customer data export request",
        allowed_tools=["query_db", "write_file", "send_email"],
        data_scope=["customer_data", "export_logs"],
        policy="default-policy",
    ) as session:
        print(f"Session opened: {session.session_id}")

        # Record tool calls — each becomes a leaf in the Merkle tree
        result = await session.record_action(
            tool_name="query_db",
            input_data="SELECT * FROM customers WHERE region = 'EU'",
            output_data={"row_count": 1247, "columns": ["id", "name", "email"]},
        )
        print(f"  Action 1 (query_db): {result['action_id']}")

        result = await session.record_action(
            tool_name="write_file",
            input_data="/exports/eu_customers_2024.csv",
            output_data={"bytes_written": 524288, "path": "/exports/eu_customers_2024.csv"},
        )
        print(f"  Action 2 (write_file): {result['action_id']}")

        result = await session.record_action(
            tool_name="send_email",
            input_data="compliance@example.com",
            output_data={"status": "sent", "message_id": "msg-abc123"},
        )
        print(f"  Action 3 (send_email): {result['action_id']}")

    print(f"Session closed. Total actions: {session.action_count}")
    print("All actions are now in the Merkle tree and can be verified on-chain.")


if __name__ == "__main__":
    asyncio.run(main())
