#!/usr/bin/env python3
"""Traced agent example — using @trace and @guardrail decorators.

The @trace decorator automatically captures input/output/timing for each
tool call and records it as a Merkl action. The @guardrail decorator
blocks disallowed tools before execution.

``async with client.session(...)`` binds the active session to a
``contextvars.ContextVar`` automatically, so the decorators pick it up
without any manual plumbing — and concurrent asyncio tasks each see
their own session.

Usage:
    python examples/traced_agent.py
"""

from __future__ import annotations

import asyncio

from merkl.sdk import MerklClient, guardrail, trace


# Define traced tools — @trace captures input/output/timing automatically
@trace
async def query_database(sql: str) -> dict:
    """Simulated database query."""
    return {"rows": [{"id": 1, "name": "Alice"}], "count": 1}


@trace
async def write_report(path: str, content: str) -> dict:
    """Simulated file write."""
    return {"bytes_written": len(content), "path": path}


# Guardrailed tool — only allowed if the tool name is in the allowed list
@guardrail(allowed_tools=["send_notification"])
async def send_notification(recipient: str, message: str) -> dict:
    """Simulated notification — guardrail-protected."""
    return {"status": "sent", "recipient": recipient}


async def main() -> None:
    client = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="traced-agent-001",
        api_key="mk_dev_key",
    )

    async with client.session(
        goal="Generate weekly analytics report",
        allowed_tools=["query_database", "write_report", "send_notification"],
        data_scope=["analytics"],
        policy="analytics-policy",
    ) as session:
        print(f"Session: {session.session_id}")

        # These calls are automatically traced — the active session is
        # bound to a contextvar on __aenter__ and restored on __aexit__.
        db_result = await query_database("SELECT COUNT(*) FROM events")
        print(f"  DB result: {db_result}")

        report_result = await write_report(
            "/reports/weekly.md", "# Weekly Report\n\nTotal events: 42"
        )
        print(f"  Report: {report_result}")

        # Guardrail-protected — blocks go through the audit trail too.
        notify_result = await send_notification(
            "team@example.com", "Weekly report ready"
        )
        print(f"  Notification: {notify_result}")

    print(f"Done. {session.action_count} actions traced and recorded.")


if __name__ == "__main__":
    asyncio.run(main())
