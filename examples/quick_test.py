#!/usr/bin/env python3
"""Quick test — record a few actions via the SDK and see them in the dashboard.

Usage:
    source .venv/bin/activate
    python examples/quick_test.py
"""

import asyncio
import os

from merkl.sdk import MerklClient


async def main() -> None:
    api_key = os.environ.get("MERKL_API_KEY", "")
    if not api_key:
        print("Set MERKL_API_KEY env var first (from dashboard Settings > API Keys)")
        return

    client = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="test-agent",
        api_key=api_key,
    )

    async with client.session(
        goal="Process customer refund #1234",
        allowed_tools=["query_db", "send_email", "process_payment"],
        policy="refund_policy_v2",
    ) as session:
        print(f"Session opened: {session.session_id}")

        # Simulate a few tool calls
        r1 = await session.record_action(
            tool_name="query_db",
            action_type="tool_call",
            input_data="SELECT * FROM orders WHERE id = 1234",
            output_data='{"id": 1234, "amount": 59.99, "status": "delivered"}',
            drift_score=0.05,
        )
        print(f"  Action 1 recorded: query_db (batch={r1.get('batch_id')})")

        r2 = await session.record_action(
            tool_name="process_payment",
            action_type="tool_call",
            input_data='{"order_id": 1234, "refund_amount": 59.99}',
            output_data='{"status": "refunded", "transaction_id": "tx_abc123"}',
            drift_score=0.08,
        )
        print(f"  Action 2 recorded: process_payment")

        r3 = await session.record_action(
            tool_name="send_email",
            action_type="tool_call",
            input_data='{"to": "customer@example.com", "subject": "Refund processed"}',
            output_data='{"sent": true, "message_id": "msg_xyz"}',
            drift_score=0.12,
        )
        print(f"  Action 3 recorded: send_email")

    print("\nSession closed. Open the dashboard to see your agent activity!")


if __name__ == "__main__":
    asyncio.run(main())
