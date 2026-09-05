#!/usr/bin/env python3
"""OpenAI function calling with Merkl accountability.

Usage:
    pip install openai
    export OPENAI_API_KEY=...
    python examples/openai_agent.py
"""

from __future__ import annotations

import asyncio
import json
import os

from openai import AsyncOpenAI

from merkl.sdk import MerklClient
from merkl.integrations.openai import merkl_tool


async def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for company information."""
    data = {
        "revenue": "Acme Corp reported $150M revenue in 2024.",
        "employees": "Acme Corp has 1,200 employees.",
    }
    for key, value in data.items():
        if key in query.lower():
            return value
    return f"No results found for: {query}"


async def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    try:
        return str(eval(expression, {"__builtins__": {}}))
    except Exception as e:
        return f"Error: {e}"


TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "search_knowledge_base",
            "description": "Search the internal knowledge base",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculator",
            "description": "Evaluate a math expression",
            "parameters": {
                "type": "object",
                "properties": {"expression": {"type": "string"}},
                "required": ["expression"],
            },
        },
    },
]


async def main() -> None:
    merkl = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="openai-agent",
        api_key="mk_dev_key",
    )

    async with merkl.session(
        goal="Answer questions about Acme Corp",
        allowed_tools=["search_knowledge_base", "calculator"],
        data_scope=["company_data"],
        policy="default",
    ) as session:
        # Wrap tools with Merkl recording
        tool_fns = {
            "search_knowledge_base": merkl_tool(session)(search_knowledge_base),
            "calculator": merkl_tool(session)(calculator),
        }

        client = AsyncOpenAI()

        print(f"Merkl Session: {session.session_id}")
        print("Asking about Acme Corp...\n")

        messages = [{"role": "user", "content": "What is Acme Corp's revenue? Calculate 150M / 1200 employees."}]

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=TOOLS_SCHEMA,
        )

        # Handle tool calls
        while response.choices[0].message.tool_calls:
            messages.append(response.choices[0].message)
            for tc in response.choices[0].message.tool_calls:
                fn = tool_fns[tc.function.name]
                args = json.loads(tc.function.arguments)
                print(f"  Tool: {tc.function.name}({args})")
                result = await fn(**args)
                print(f"  Result: {result}")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
                })
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                tools=TOOLS_SCHEMA,
            )

        print(f"\nFinal: {response.choices[0].message.content}")
        print(f"Recorded {session.action_count} tool calls in Merkl")

    await merkl.close()


if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: Set OPENAI_API_KEY")
        exit(1)
    asyncio.run(main())
