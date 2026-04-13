"""Claude Code PostToolUse hook — records every tool call in Merkl.

This script is a side-channel: it receives the hook payload from Claude Code
via stdin, hashes the tool input/output, and posts to the Merkl API.
The agent is never aware this is running.

Usage (automatic via Claude Code hooks):
    python -m merkl.hooks.claude_code

Required env vars:
    MERKL_API_KEY    Your Merkl API key (mk_...)
    MERKL_ENDPOINT   Merkl API base URL (default: http://localhost:8000)

Optional env vars:
    MERKL_SESSION_ID   Pin all events to a specific Merkl session
    MERKL_AGENT_ID     Agent label shown in dashboard (default: claude-code)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


def _sha256(data: object) -> str:
    """SHA-256 of the canonical JSON representation."""
    serialized = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialized).hexdigest()


def _session_cache(claude_session_id: str) -> Path:
    """Temp file path that maps a Claude session → Merkl session_id."""
    tag = claude_session_id[:16].replace("/", "_")
    return Path(tempfile.gettempdir()) / f"merkl_session_{tag}"


def _display_name(tool_name: str, tool_input: object) -> str:
    """Generate a human-readable action label from the tool call."""
    if not isinstance(tool_input, dict):
        return tool_name

    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        label = cmd.split("\n")[0][:72]
        return f"$ {label}" if label else "Bash"

    for field in ("file_path", "path", "pattern", "query"):
        if val := tool_input.get(field):
            return f"{tool_name} {str(val)[:60]}"

    return tool_name


def _get_or_create_session(
    endpoint: str,
    api_key: str,
    agent_id: str,
    claude_session_id: str,
) -> str:
    """Return the Merkl session_id to record into.

    Priority:
    1. MERKL_SESSION_ID env var (explicit override)
    2. Temp-file cache keyed by Claude's session_id (auto-created per session)
    """
    import httpx  # local import — only needed at call time

    if pinned := os.environ.get("MERKL_SESSION_ID"):
        return pinned

    cache = _session_cache(claude_session_id)
    if cache.exists():
        return cache.read_text().strip()

    # Auto-create a Merkl session for this Claude Code run
    resp = httpx.post(
        f"{endpoint}/v1/sessions",
        json={
            "agent_id": agent_id,
            "goal": f"Claude Code — {claude_session_id[:8]}",
            "allowed_tools": [],
            "data_scope": [],
            "policy_reference": "claude-code",
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )
    resp.raise_for_status()
    session_id = resp.json()["session_id"]
    cache.write_text(session_id)
    return session_id


def main() -> None:
    raw = sys.stdin.read()
    if not raw.strip():
        return

    payload: dict = json.loads(raw)

    endpoint = os.environ.get("MERKL_ENDPOINT", "http://localhost:8000").rstrip("/")
    api_key = os.environ.get("MERKL_API_KEY", "")
    agent_id = os.environ.get("MERKL_AGENT_ID", "claude-code")

    if not api_key:
        # Not configured — exit silently so Claude Code is never blocked
        return

    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: object = payload.get("tool_input", {})
    # Claude Code uses "tool_response" in PostToolUse payloads
    tool_response: object = payload.get("tool_response", payload.get("tool_result", ""))
    claude_session_id: str = payload.get("session_id", "unknown")

    import httpx

    session_id = _get_or_create_session(endpoint, api_key, agent_id, claude_session_id)

    httpx.post(
        f"{endpoint}/v1/sessions/{session_id}/actions",
        json={
            "agent_id": agent_id,
            "action_type": "tool_call",
            "tool_name": tool_name,
            "display_name": _display_name(tool_name, tool_input),
            "input_hash": _sha256(tool_input),
            "output_hash": _sha256(tool_response),
            "drift_score": 0.0,
            "guardrail_result": "not_evaluated",
            "policy_reference": "claude-code",
            "status": "success",
            "category": "data_access",
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Hooks must NEVER block or crash Claude Code
        sys.exit(0)
