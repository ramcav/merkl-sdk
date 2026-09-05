#!/usr/bin/env python3
"""Real AI agent with Merkl accountability using Google ADK.

Uses Gemini via the Google Agent Development Kit to answer a question
using tools, with every tool call recorded in the Merkl audit trail.

Usage:
    # Make sure the notary is running (docker-compose up -d)
    # Make sure GOOGLE_API_KEY is set

    pip install google-adk
    python examples/claude_agent.py
"""

from __future__ import annotations

import asyncio
import math
import os
import time

from dotenv import load_dotenv

load_dotenv()
from datetime import datetime, timezone

from google.adk import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from merkl.sdk import MerklClient


# --- Tool implementations ---

def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for company information.

    Args:
        query: The search query about company data.

    Returns:
        Search results from the knowledge base.
    """
    data = {
        "company revenue": "Acme Corp reported $150M revenue in 2024, up from $120M in 2023.",
        "employee count": "Acme Corp has 1,200 employees across 5 offices globally.",
        "product launches": "Acme Corp launched 3 new products in Q4 2024: AcmeAI, AcmeCloud, AcmeSecure.",
        "customer satisfaction": "NPS score is 72. Customer retention rate is 94%.",
    }
    for key, value in data.items():
        if key in query.lower():
            return value
    return f"No results found for: {query}"


def calculator(expression: str) -> str:
    """Evaluate a mathematical expression safely. Supports +, -, *, /, parentheses.

    Args:
        expression: The math expression to evaluate, e.g. '(150000000 - 120000000) / 120000000 * 100'.

    Returns:
        The result of the calculation as a string.
    """
    allowed = set("0123456789+-*/.() _,")
    clean = expression.replace(",", "").replace("_", "")
    if not all(c in allowed for c in clean):
        return "Error: unsafe expression"
    try:
        result = eval(clean, {"__builtins__": {}}, {"math": math})
        return str(result)
    except Exception as e:
        return f"Error: {e}"


def get_current_date() -> str:
    """Get the current date and time in UTC.

    Returns:
        Current datetime in ISO format.
    """
    return datetime.now(timezone.utc).isoformat()


TOOLS_MAP = {
    "search_knowledge_base": search_knowledge_base,
    "calculator": calculator,
    "get_current_date": get_current_date,
}


async def run_agent(question: str) -> None:
    """Run a Gemini-powered agent with Merkl accountability."""

    # Set up Merkl
    merkl = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="gemini-agent-001",
        api_key="mk_dev_key",
    )

    tool_names = list(TOOLS_MAP.keys())

    async with merkl.session(
        goal=f"Answer user question: {question}",
        allowed_tools=tool_names,
        data_scope=["company_data"],
        policy="research-policy",
    ) as merkl_session:
        print(f"\n{'='*60}")
        print(f"Merkl Session: {merkl_session.session_id}")
        print(f"Question: {question}")
        print(f"{'='*60}\n")

        # Set up Google ADK agent
        agent = Agent(
            name="analyst",
            model="gemini-2.5-flash",
            instruction="You are a helpful analyst with access to a company knowledge base and calculator. Use the tools to answer questions accurately. Always use the tools rather than guessing.",
            tools=[search_knowledge_base, calculator, get_current_date],
        )

        session_service = InMemorySessionService()
        runner = Runner(agent=agent, app_name="merkl_demo", session_service=session_service)

        adk_session = await session_service.create_session(
            app_name="merkl_demo", user_id="user-1"
        )

        user_message = types.Content(
            role="user",
            parts=[types.Part.from_text(text=question)],
        )

        final_text = ""
        async for event in runner.run_async(
            user_id="user-1",
            session_id=adk_session.id,
            new_message=user_message,
        ):
            # Capture tool calls and record them in Merkl
            function_calls = event.get_function_calls()
            if function_calls:
                for fc in function_calls:
                    tool_name = fc.name
                    tool_input = dict(fc.args) if fc.args else {}
                    print(f"  Tool call: {tool_name}({tool_input})")

                    # Record in Merkl
                    await merkl_session.record_action(
                        tool_name=tool_name,
                        input_data=tool_input,
                        output_data="(executed by ADK)",
                        duration_ms=0,
                    )
                    print(f"  -> Recorded in Merkl\n")

            function_responses = event.get_function_responses()
            if function_responses:
                for fr in function_responses:
                    print(f"  Tool result ({fr.name}): {fr.response}")

            # Capture final text
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        final_text = part.text

        if final_text:
            print(f"\nAgent answer:\n{final_text}")

        print(f"\n{'='*60}")
        print(f"Session complete: {merkl_session.action_count} tool calls recorded")
        print(f"Session ID: {merkl_session.session_id}")
        print(f"All actions are in the Merkle tree and verifiable.")
        print(f"{'='*60}")

    await merkl.close()


if __name__ == "__main__":
    if not os.environ.get("GOOGLE_API_KEY"):
        print("Error: Set GOOGLE_API_KEY environment variable")
        exit(1)

    question = (
        "What was Acme Corp's revenue growth rate from 2023 to 2024, "
        "and how does that compare to their employee count?"
    )
    asyncio.run(run_agent(question))
