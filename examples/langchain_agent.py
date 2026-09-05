#!/usr/bin/env python3
"""LangChain agent with Merkl accountability.

Usage:
    pip install langchain-core langchain-openai
    export OPENAI_API_KEY=...
    python examples/langchain_agent.py
"""

from __future__ import annotations

import asyncio
import os

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from merkl.sdk import MerklClient
from merkl.integrations.langchain import MerklCallbackHandler


@tool
def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for company information."""
    data = {
        "revenue": "Acme Corp reported $150M revenue in 2024.",
        "employees": "Acme Corp has 1,200 employees.",
    }
    for key, value in data.items():
        if key in query.lower():
            return value
    return f"No results found for: {query}"


@tool
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    try:
        return str(eval(expression, {"__builtins__": {}}))
    except Exception as e:
        return f"Error: {e}"


async def main() -> None:
    merkl = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="langchain-agent",
        api_key="mk_dev_key",
    )

    tools = [search_knowledge_base, calculator]

    async with merkl.session(
        goal="Answer questions about Acme Corp",
        allowed_tools=[t.name for t in tools],
        data_scope=["company_data"],
        policy="default",
    ) as session:
        handler = MerklCallbackHandler(session)

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        llm_with_tools = llm.bind_tools(tools)

        print(f"Merkl Session: {session.session_id}")
        print("Asking about Acme Corp revenue...\n")

        result = await llm_with_tools.ainvoke(
            [HumanMessage(content="What is Acme Corp's revenue?")],
            config={"callbacks": [handler]},
        )

        print(f"Response: {result.content}")
        print(f"\nRecorded {session.action_count} tool calls in Merkl")

    await merkl.close()


if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: Set OPENAI_API_KEY environment variable")
        exit(1)
    asyncio.run(main())
