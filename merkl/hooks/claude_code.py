"""Claude Code PostToolUse hook — records every tool call in Merkl.

This script is a side-channel: it receives the hook payload from Claude Code
via stdin, hashes the tool input/output, and posts to the Merkl API.
The agent is never aware this is running.

Usage (automatic via Claude Code hooks):
    python -m merkl.hooks.claude_code

Required env vars:
    MERKL_API_KEY    Your Merkl API key (mk_...)

Optional env vars:
    MERKL_ENDPOINT     Merkl API base URL (default: https://api.merkl.ai)
    MERKL_SESSION_ID   Pin all events to a specific Merkl session
    MERKL_AGENT_ID     Agent label shown in dashboard (default: claude-code)

DAG grouping
------------
Claude Code can call multiple tools in a single turn (one assistant message).
We read the transcript to detect which tools belong to the same turn, then
record them as siblings (same depends_on) rather than a chain. This produces
a fan-out / fan-in graph instead of a straight line.

  Turn 1: ToolSearch                       depends_on=[]
  Turn 2: WebFetch(A), WebFetch(B)         both depend on ToolSearch
  Turn 3: Write                            depends on WebFetch(A) + WebFetch(B)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: object) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialized).hexdigest()


def _tag(claude_session_id: str) -> str:
    return claude_session_id[:16].replace("/", "_")


def _session_cache(claude_session_id: str) -> Path:
    return Path(tempfile.gettempdir()) / f"merkl_session_{_tag(claude_session_id)}"


def _turn_state_cache(claude_session_id: str) -> Path:
    """JSON file tracking current/prev turn action IDs for DAG grouping."""
    return Path(tempfile.gettempdir()) / f"merkl_turn_{_tag(claude_session_id)}.json"


def _display_name(tool_name: str, tool_input: object) -> str:
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


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _get_or_create_session(
    endpoint: str,
    api_key: str,
    agent_id: str,
    claude_session_id: str,
) -> str:
    import httpx

    if pinned := os.environ.get("MERKL_SESSION_ID"):
        return pinned

    cache = _session_cache(claude_session_id)
    if cache.exists():
        return cache.read_text().strip()

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


# ---------------------------------------------------------------------------
# DAG turn grouping
# ---------------------------------------------------------------------------

def _current_turn_id(transcript_path: str | None) -> str | None:
    """Read the transcript and return a fingerprint of the last assistant turn.

    Claude Code writes the full assistant message (including all tool_use
    blocks) before executing any tool in that turn. So when the first hook
    fires for turn N, the transcript already contains the complete turn-N
    assistant message — letting us identify all siblings.
    """
    if not transcript_path:
        return None
    try:
        path = Path(transcript_path)
        if not path.exists():
            return None
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        for raw in reversed(lines):
            msg = json.loads(raw)
            # Handle both plain messages and wrapped Claude Code transcript entries
            content = msg.get("content") or msg.get("message", {}).get("content")
            role = msg.get("role") or msg.get("message", {}).get("role")
            if role == "assistant" and isinstance(content, list):
                ids = [
                    blk.get("id", "")
                    for blk in content
                    if blk.get("type") == "tool_use"
                ]
                if ids:
                    return "|".join(ids)
    except Exception:
        pass
    return None


def _load_turn_state(claude_session_id: str) -> dict:
    path = _turn_state_cache(claude_session_id)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {"turn_id": None, "current_actions": [], "prev_actions": []}


def _save_turn_state(claude_session_id: str, state: dict) -> None:
    _turn_state_cache(claude_session_id).write_text(json.dumps(state))


def _resolve_depends_on(
    transcript_path: str | None,
    claude_session_id: str,
) -> tuple[list[str], dict]:
    """Return (depends_on, state) for the current tool call.

    depends_on points to last turn's action IDs (siblings share the same
    depends_on, producing a fan-out from the previous turn's outputs).

    Falls back to simple linear chaining if transcript is unreadable.
    """
    state = _load_turn_state(claude_session_id)
    new_turn_id = _current_turn_id(transcript_path)

    if new_turn_id and new_turn_id != state.get("turn_id"):
        # New turn detected — rotate current → prev
        state["prev_actions"] = state["current_actions"]
        state["current_actions"] = []
        state["turn_id"] = new_turn_id
    elif not new_turn_id:
        # Transcript unreadable — fall back to linear chain
        last = state["current_actions"][-1:] if state["current_actions"] else state["prev_actions"][-1:]
        return last, state

    depends_on = state["prev_actions"]
    return depends_on, state


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    raw = sys.stdin.read()
    if not raw.strip():
        return

    payload: dict = json.loads(raw)

    endpoint = os.environ.get("MERKL_ENDPOINT", "https://api.merkl.ai").rstrip("/")
    api_key = os.environ.get("MERKL_API_KEY", "")
    agent_id = os.environ.get("MERKL_AGENT_ID", "claude-code")

    if not api_key:
        return

    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: object = payload.get("tool_input", {})
    tool_response: object = payload.get("tool_response", payload.get("tool_result", ""))
    claude_session_id: str = payload.get("session_id", "unknown")
    transcript_path: str | None = payload.get("transcript_path")

    import httpx

    session_id = _get_or_create_session(endpoint, api_key, agent_id, claude_session_id)
    depends_on, turn_state = _resolve_depends_on(transcript_path, claude_session_id)

    resp = httpx.post(
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
            "depends_on": depends_on,
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )

    if resp.is_success:
        action_id = resp.json().get("action_id", "")
        if action_id:
            turn_state["current_actions"].append(action_id)
            _save_turn_state(claude_session_id, turn_state)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Hooks must NEVER block or crash Claude Code
        sys.exit(0)
