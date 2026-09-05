#!/usr/bin/env python3
"""Interactive Gemini agent with Merkl accountability.

Chat with a Gemini-powered research analyst. Every tool call is recorded
in a Merkl session, hashed into a per-session Merkle tree, and committed
to the workspace's append-only transparency log.

Usage:
    docker-compose up -d
    pip install google-adk python-dotenv
    python examples/interactive_demo.py
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from google.adk import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from merkl.sdk import MerklClient


# ---------------------------------------------------------------------------
# Tools — the agent can use these during conversation
# ---------------------------------------------------------------------------

def search_knowledge_base(query: str) -> str:
    """Search the internal knowledge base for company information.

    Args:
        query: The search query about company data.

    Returns:
        Search results from the knowledge base.
    """
    data = {
        "revenue": "Acme Corp reported $150M revenue in 2024, up from $120M in 2023. Q4 was the strongest quarter at $45M.",
        "employee": "Acme Corp has 1,200 employees across 5 offices (SF, NYC, London, Berlin, Tokyo). Engineering is 40% of headcount.",
        "product": "Acme Corp launched 3 products in Q4 2024: AcmeAI (LLM platform), AcmeCloud (managed infra), AcmeSecure (zero-trust auth).",
        "customer": "NPS score is 72. Customer retention rate is 94%. Enterprise segment grew 35% YoY. 12 Fortune 500 clients added in 2024.",
        "funding": "Acme Corp raised $80M Series C in March 2024 at a $900M valuation. Total funding: $145M.",
        "competitor": "Main competitors: WidgetCo ($200M rev), DataSphere ($90M rev), NovaTech ($75M rev). Acme is #2 in market share.",
        "roadmap": "2025 roadmap: AcmeAI v2 with multi-agent support (Q1), FedRAMP certification (Q2), APAC expansion (Q3).",
        "security": "SOC 2 Type II certified. Zero breaches in 2024. Bug bounty program paid out $120K across 47 reports.",
    }
    query_lower = query.lower()
    results = []
    for key, value in data.items():
        if key in query_lower or any(word in query_lower for word in key.split()):
            results.append(value)
    return "\n".join(results) if results else f"No results found for: {query}"


def calculator(expression: str) -> str:
    """Evaluate a mathematical expression. Supports +, -, *, /, parentheses, percentages.

    Args:
        expression: The math expression to evaluate, e.g. '(150 - 120) / 120 * 100'.

    Returns:
        The result of the calculation as a string.
    """
    allowed = set("0123456789+-*/.() _,")
    clean = expression.replace(",", "").replace("_", "").replace("%", "/100")
    if not all(c in allowed for c in clean.replace("/100", "")):
        return "Error: unsafe expression"
    try:
        result = eval(clean, {"__builtins__": {}}, {"math": math})
        if isinstance(result, float):
            return f"{result:.4f}" if result != int(result) else str(int(result))
        return str(result)
    except Exception as e:
        return f"Error: {e}"


def get_current_date() -> str:
    """Get the current date and time in UTC.

    Returns:
        Current datetime in ISO format.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def web_search(query: str) -> str:
    """Search the web for current information.

    Args:
        query: The search query.

    Returns:
        Simulated web search results.
    """
    results = {
        "ai market": "The global AI market is projected to reach $1.8T by 2030 (Grand View Research, 2024). Enterprise AI adoption is at 72%.",
        "saas growth": "Average SaaS growth rate in 2024 was 22% YoY. Top quartile companies grew at 40%+.",
        "cybersecurity": "Global cybersecurity spending reached $215B in 2024. Zero-trust adoption increased 60% YoY.",
        "cloud market": "AWS holds 31% cloud market share, Azure 25%, GCP 11%. Multi-cloud adoption is at 89% among enterprises.",
    }
    query_lower = query.lower()
    for key, value in results.items():
        if any(word in query_lower for word in key.split()):
            return value
    return f"Web results for '{query}': No specific data available. Try a more targeted query."


TOOLS = [search_knowledge_base, calculator, get_current_date, web_search]
TOOL_NAMES = [t.__name__ for t in TOOLS]


# ---------------------------------------------------------------------------
# Colors for terminal output
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def print_header():
    print(f"\n{C.RED}{'─' * 60}{C.RESET}")
    print(f"{C.BOLD}  Merkl — Interactive Demo{C.RESET}")
    print(f"{C.DIM}  Every tool call is recorded, hashed, and sealed into a transparency log{C.RESET}")
    print(f"{C.RED}{'─' * 60}{C.RESET}\n")


def print_merkl_event(label: str, detail: str):
    print(f"  {C.RED}│{C.RESET} {C.DIM}{label}:{C.RESET} {detail}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def main():
    print_header()

    merkl = MerklClient(
        endpoint="http://localhost:8000",
        agent_id="gemini-analyst",
        api_key="mk_dev_key",
    )

    session_service = InMemorySessionService()

    agent = Agent(
        name="analyst",
        model="gemini-2.5-flash",
        instruction=(
            "You are a sharp research analyst at Acme Corp. You have access to the "
            "company knowledge base, a calculator, web search, and current date. "
            "Always use tools to ground your answers in data — never guess. "
            "Be concise but insightful. When asked to analyze, show your work."
        ),
        tools=TOOLS,
    )

    runner = Runner(agent=agent, app_name="merkl_demo", session_service=session_service)
    adk_session = await session_service.create_session(app_name="merkl_demo", user_id="user-1")

    print(f"{C.DIM}  Tools: {', '.join(TOOL_NAMES)}{C.RESET}")
    print(f"{C.DIM}  Type 'quit' to end the session and seal the Merkle tree.{C.RESET}")
    print(f"{C.DIM}  Type 'verify' to verify the last action's proof.{C.RESET}\n")

    async with merkl.session(
        goal="Interactive research analyst session",
        allowed_tools=TOOL_NAMES,
        data_scope=["company_data", "web"],
        policy="analyst-policy",
    ) as ws:
        print(f"{C.RED}  ┌ Merkl Session{C.RESET}")
        print_merkl_event("Session ID", ws.session_id)
        print_merkl_event("Batching", "cross-session (auto-assigned)")
        print(f"{C.RED}  └{'─' * 40}{C.RESET}\n")

        while True:
            try:
                user_input = input(f"{C.BOLD}You:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not user_input:
                continue

            if user_input.lower() == "quit":
                break

            if user_input.lower() == "verify":
                print(f"{C.YELLOW}  Verification requires sealing the batch first.{C.RESET}")
                print(f"{C.YELLOW}  Batches seal automatically at threshold or time interval.{C.RESET}\n")
                continue

            # Send to Gemini via ADK
            user_message = types.Content(
                role="user",
                parts=[types.Part.from_text(text=user_input)],
            )

            tool_calls_this_turn = 0
            final_text = ""

            async for event in runner.run_async(
                user_id="user-1",
                session_id=adk_session.id,
                new_message=user_message,
            ):
                # Record tool calls in Merkl
                function_calls = event.get_function_calls()
                if function_calls:
                    for fc in function_calls:
                        tool_name = fc.name
                        tool_input = dict(fc.args) if fc.args else {}
                        tool_calls_this_turn += 1

                        start = time.time()
                        # ADK executes the tool automatically — we just record it
                        duration_ms = int((time.time() - start) * 1000)

                        await ws.record_action(
                            tool_name=tool_name,
                            input_data=tool_input,
                            output_data="(executed by ADK)",
                            duration_ms=duration_ms,
                        )

                        print(f"\n{C.RED}  ┌ Merkl: action #{ws.action_count}{C.RESET}")
                        print_merkl_event("Tool", tool_name)
                        print_merkl_event("Input", json.dumps(tool_input, default=str)[:80])
                        print_merkl_event("Leaf hash", "computed (SHA-256)")
                        print(f"{C.RED}  └{'─' * 40}{C.RESET}")

                # Capture final response
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            final_text = part.text

            if final_text:
                print(f"\n{C.CYAN}Agent:{C.RESET} {final_text}\n")

        # Session closes here (auto-seal)
        print(f"\n{C.RED}{'─' * 60}{C.RESET}")
        print(f"{C.BOLD}  Session sealed{C.RESET}")
        print(f"{C.DIM}  Actions recorded: {ws.action_count}{C.RESET}")
        print(f"{C.DIM}  Session ID: {ws.session_id}{C.RESET}")
        print(f"{C.DIM}  Session root appended to workspace transparency log{C.RESET}")
        print(f"{C.RED}{'─' * 60}{C.RESET}\n")

    await merkl.close()


if __name__ == "__main__":
    if not os.environ.get("GOOGLE_API_KEY"):
        print("Error: Set GOOGLE_API_KEY in .env")
        exit(1)

    asyncio.run(main())
