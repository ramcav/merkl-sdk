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

DAG grouping — two layers
-------------------------
Layer 1 (structural): Read transcript_path to detect which tools belong to
the same assistant turn. Tools in the same turn become siblings (same
depends_on), producing fan-out / fan-in.

Layer 2 (semantic / data-flow): After each tool, store a snippet of its
output. Before recording the next tool, scan the incoming tool_input for
content from previous outputs. If Write's input contains text that came from
WebFetch's output, we infer a data-flow dependency automatically — no agent
cooperation needed. This is how data lineage tools work.

Combined result for a weather research session:

  Turn 1: ToolSearch                       depends_on=[]
  Turn 2: WebFetch(Madrid)                 depends_on=[ToolSearch]   ← structural
          WebFetch(Bogotá)                 depends_on=[ToolSearch]   ← structural (sibling)
  Turn 3: Write(report)                    depends_on=[WebFetch(Madrid), WebFetch(Bogotá)]
                                           ← data-flow: report text contains weather data
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


def _dataflow_cache(claude_session_id: str) -> Path:
    """JSON file storing output snippets keyed by action_id for data-flow matching."""
    return Path(tempfile.gettempdir()) / f"merkl_dataflow_{_tag(claude_session_id)}.json"


# Minimum token length to avoid spurious matches on short/common strings
_MIN_SNIPPET_LEN = 12


def _extract_snippets(data: object, max_snippets: int = 16) -> list[str]:
    """Pull meaningful string fragments from tool output for data-flow matching.

    Walks the data structure recursively to extract string leaf values.
    These are the actual content tokens that a downstream tool might reuse
    (e.g. "21°C" from a weather fetch appearing verbatim in a written report).
    """
    snippets: list[str] = []

    def _walk(obj: object) -> None:
        if isinstance(obj, str):
            s = obj.strip()
            if len(s) >= _MIN_SNIPPET_LEN:
                snippets.append(s)
            # Also take sub-phrases split by sentence/line boundaries
            import re
            for part in re.split(r'[.\n;]+', s):
                part = part.strip()
                if len(part) >= _MIN_SNIPPET_LEN and part not in snippets:
                    snippets.append(part)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    # If data is a raw string (e.g. HTTP response body), parse JSON if possible
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            pass

    _walk(data)

    # Deduplicate, sort longest first (longer = less likely to be spurious)
    seen: set[str] = set()
    result: list[str] = []
    for s in sorted(snippets, key=len, reverse=True):
        if s not in seen:
            seen.add(s)
            result.append(s)
        if len(result) >= max_snippets:
            break
    return result


def _dataflow_depends_on(tool_input: object, claude_session_id: str) -> list[str]:
    """Return action_ids whose output data appears in tool_input (data lineage)."""
    cache_path = _dataflow_cache(claude_session_id)
    if not cache_path.exists():
        return []
    try:
        store: dict[str, list[str]] = json.loads(cache_path.read_text())
    except Exception:
        return []

    input_text = json.dumps(tool_input, default=str)
    matched: list[str] = []
    for action_id, snippets in store.items():
        if any(len(s) >= _MIN_SNIPPET_LEN and s in input_text for s in snippets):
            matched.append(action_id)
    return matched


def _store_dataflow(action_id: str, tool_response: object, claude_session_id: str) -> None:
    """Save output snippets for this action so future tools can reference it."""
    cache_path = _dataflow_cache(claude_session_id)
    try:
        store: dict[str, list[str]] = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    except Exception:
        store = {}
    snippets = _extract_snippets(tool_response)
    if snippets:
        store[action_id] = snippets
    # Keep store bounded — drop oldest entries beyond 50
    if len(store) > 50:
        oldest = list(store.keys())[:-50]
        for k in oldest:
            del store[k]
    cache_path.write_text(json.dumps(store))


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


def _input_preview(tool_name: str, tool_input: object) -> str:
    """Truncated plaintext describing what the tool was asked to do."""
    if not isinstance(tool_input, dict):
        return str(tool_input)[:200]
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))[:200]
    if tool_name == "WebFetch":
        return str(tool_input.get("url", ""))[:200]
    if tool_name in ("Read", "Write", "Edit", "NotebookEdit"):
        path = str(tool_input.get("file_path", ""))
        extra = tool_input.get("content") or tool_input.get("new_string") or tool_input.get("old_string") or ""
        return f"{path}: {str(extra)[:140]}".strip(": ") if extra else path
    if tool_name in ("Glob", "Grep"):
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", "")
        return f"{pattern} in {path}" if path else str(pattern)
    # Generic fallback
    return " | ".join(f"{k}={str(v)[:40]}" for k, v in list(tool_input.items())[:4])[:200]


def _output_preview(tool_response: object) -> str:
    """Truncated plaintext of what the tool returned."""
    if isinstance(tool_response, str):
        return tool_response.strip()[:200]
    if isinstance(tool_response, dict):
        for field in ("content", "text", "output", "stdout", "result", "data"):
            if val := tool_response.get(field):
                return str(val).strip()[:200]
        return json.dumps(tool_response, default=str)[:200]
    if isinstance(tool_response, list):
        return json.dumps(tool_response[:5], default=str)[:200]
    return str(tool_response)[:200]


def _infer_goal(transcript_path: str | None) -> str:
    """Read the first human message from the transcript as the session goal."""
    if not transcript_path:
        return "Claude Code session"
    try:
        path = Path(transcript_path)
        if not path.exists():
            return "Claude Code session"
        for raw in path.read_text().splitlines():
            if not raw.strip():
                continue
            msg = json.loads(raw)
            role = msg.get("role") or msg.get("message", {}).get("role")
            content = msg.get("content") or msg.get("message", {}).get("content")
            if role == "user":
                if isinstance(content, str) and content.strip():
                    return content.strip()[:200]
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block.get("text", "").strip()
                            if text:
                                return text[:200]
    except Exception:
        pass
    return "Claude Code session"


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _get_or_create_session(
    endpoint: str,
    api_key: str,
    agent_id: str,
    claude_session_id: str,
    transcript_path: str | None = None,
) -> str:
    import httpx

    if pinned := os.environ.get("MERKL_SESSION_ID"):
        return pinned

    cache = _session_cache(claude_session_id)
    if cache.exists():
        return cache.read_text().strip()

    goal = _infer_goal(transcript_path)
    resp = httpx.post(
        f"{endpoint}/v1/sessions",
        json={
            "agent_id": agent_id,
            "goal": goal,
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

def _seal_session_on_exit(
    endpoint: str, api_key: str, claude_session_id: str
) -> None:
    """On SessionEnd, seal the Merkl session so the dashboard flips it out
    of Live. If we never opened one for this conversation (user quit
    before any tool call), there's nothing to seal.
    """
    import httpx

    cache = _session_cache(claude_session_id)
    if not cache.exists():
        return
    merkl_session_id = cache.read_text().strip()
    if not merkl_session_id:
        return
    try:
        httpx.post(
            f"{endpoint}/v1/sessions/{merkl_session_id}/seal",
            headers={"X-Merkl-API-Key": api_key},
            timeout=5.0,
        )
    except Exception:
        # Hook must never block Claude Code's exit flow.
        return
    # Cleanup per-conversation caches; a fresh conversation will recreate.
    for path in (
        _session_cache(claude_session_id),
        _turn_state_cache(claude_session_id),
        _dataflow_cache(claude_session_id),
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


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

    event = payload.get("hook_event_name", "PostToolUse")
    claude_session_id: str = payload.get("session_id", "unknown")

    # SessionEnd: user ran /exit, /clear, or closed the window. Seal the
    # Merkl session immediately instead of waiting for the idle timeout.
    if event == "SessionEnd":
        _seal_session_on_exit(endpoint, api_key, claude_session_id)
        return

    # Everything below is the PostToolUse path — unchanged behavior.
    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: object = payload.get("tool_input", {})
    tool_response: object = payload.get("tool_response", payload.get("tool_result", ""))
    transcript_path: str | None = payload.get("transcript_path")

    import httpx

    session_id = _get_or_create_session(endpoint, api_key, agent_id, claude_session_id, transcript_path)

    # Layer 1: structural grouping via transcript (siblings share a turn)
    structural_deps, turn_state = _resolve_depends_on(transcript_path, claude_session_id)

    # Layer 2: data-flow deps — which previous outputs does this input reference?
    dataflow_deps = _dataflow_depends_on(tool_input, claude_session_id)

    # Merge: prefer data-flow when available (more precise), else use structural
    if dataflow_deps:
        depends_on = list(dict.fromkeys(dataflow_deps + structural_deps))
    else:
        depends_on = structural_deps

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
            "input_preview": _input_preview(tool_name, tool_input),
            "output_preview": _output_preview(tool_response),
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )

    if resp.is_success:
        action_id = resp.json().get("action_id", "")
        if action_id:
            turn_state["current_actions"].append(action_id)
            _save_turn_state(claude_session_id, turn_state)
            # Store this action's output for future data-flow matching
            _store_dataflow(action_id, tool_response, claude_session_id)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Hooks must NEVER block or crash Claude Code
        sys.exit(0)
