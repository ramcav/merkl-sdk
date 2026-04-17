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

All per-Claude-session state is held in one ``HookState`` JSON file
(``merkl_hookstate_{tag}.json``) so reads and writes are atomic.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

from merkl.shared.hashing import canonical_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: object) -> str:
    return canonical_hash(data).hex()


def _tag(claude_session_id: str) -> str:
    return claude_session_id[:16].replace("/", "_")


# Minimum token length to avoid spurious matches on short/common strings
_MIN_SNIPPET_LEN = 40
_MAX_DEPS_PER_ACTION = 5
_MAX_DATAFLOW_ENTRIES = 50


# ---------------------------------------------------------------------------
# HookState — single JSON file per Claude Code session
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class HookState:
    """All per-Claude-session scratch state the hook needs.

    One ``merkl_hookstate_{tag}.json`` file owns: the Merkl session_id,
    turn-rotation tracking, output snippets for data-flow matching, and
    the last Task action_id used for sub-agent linkage.
    """

    claude_session_id: str
    session_id: str | None = None
    turn_id: str | None = None
    current_actions: list[str] = dataclasses.field(default_factory=list)
    prev_actions: list[str] = dataclasses.field(default_factory=list)
    dataflow: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    last_task_action_id: str | None = None

    @staticmethod
    def _path(claude_session_id: str) -> Path:
        return Path(tempfile.gettempdir()) / f"merkl_hookstate_{_tag(claude_session_id)}.json"

    @classmethod
    def load(cls, claude_session_id: str) -> HookState:
        path = cls._path(claude_session_id)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                return cls(
                    claude_session_id=claude_session_id,
                    session_id=data.get("session_id"),
                    turn_id=data.get("turn_id"),
                    current_actions=list(data.get("current_actions", [])),
                    prev_actions=list(data.get("prev_actions", [])),
                    dataflow=dict(data.get("dataflow", {})),
                    last_task_action_id=data.get("last_task_action_id"),
                )
            except Exception:
                pass
        return cls(claude_session_id=claude_session_id)

    def save(self) -> None:
        path = self._path(self.claude_session_id)
        path.write_text(json.dumps({
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "current_actions": self.current_actions,
            "prev_actions": self.prev_actions,
            "dataflow": self.dataflow,
            "last_task_action_id": self.last_task_action_id,
        }))

    def delete(self) -> None:
        try:
            self._path(self.claude_session_id).unlink()
        except FileNotFoundError:
            pass

    def rotate_turn(self, new_turn_id: str) -> None:
        if new_turn_id != self.turn_id:
            self.prev_actions = self.current_actions
            self.current_actions = []
            self.turn_id = new_turn_id

    def depends_on_prev_turn(self) -> list[str]:
        return list(self.prev_actions)

    def last_linear(self) -> list[str]:
        """Fallback when the transcript is unreadable."""
        if self.current_actions:
            return self.current_actions[-1:]
        return self.prev_actions[-1:]

    def record_action(
        self,
        action_id: str,
        tool_response: object,
        is_task: bool,
    ) -> None:
        self.current_actions.append(action_id)
        snippets = _extract_snippets(tool_response)
        if snippets:
            self.dataflow[action_id] = snippets
        if len(self.dataflow) > _MAX_DATAFLOW_ENTRIES:
            # drop oldest entries beyond the cap
            for k in list(self.dataflow.keys())[:-_MAX_DATAFLOW_ENTRIES]:
                del self.dataflow[k]
        if is_task:
            self.last_task_action_id = action_id

    def dataflow_depends_on(self, tool_input: object) -> list[str]:
        """Return action_ids whose output snippets appear in this input.

        Scored by longest matching snippet (longer = less likely spurious).
        Capped at ``_MAX_DEPS_PER_ACTION`` so a shared prefix can't explode
        the DAG fan-in.
        """
        if not self.dataflow:
            return []
        input_text = _strip_common_prefixes(json.dumps(tool_input, default=str))
        scored: list[tuple[int, str]] = []
        for action_id, snippets in self.dataflow.items():
            best = 0
            for s in snippets:
                if len(s) >= _MIN_SNIPPET_LEN and s in input_text and len(s) > best:
                    best = len(s)
            if best > 0:
                scored.append((best, action_id))
        scored.sort(reverse=True)
        return [aid for _, aid in scored[:_MAX_DEPS_PER_ACTION]]


def _strip_common_prefixes(s: str) -> str:
    """Strip tokens shared across a session's working environment (cwd, home).

    A path like `/Users/.../witness/foo.py` gets trimmed to `foo.py`.
    Without this, every Read/Edit of a file in the same repo shares a long
    prefix that spuriously links every action to every other.
    """
    for prefix in (os.getcwd(), str(Path.home())):
        if prefix and prefix in s:
            s = s.replace(prefix, "")
    return s


def _extract_snippets(data: object, max_snippets: int = 16) -> list[str]:
    """Pull meaningful string fragments from tool output for data-flow matching.

    Walks the structure recursively; collects string leaves plus sentence /
    line fragments that exceed ``_MIN_SNIPPET_LEN``.
    """
    snippets: list[str] = []

    def _walk(obj: object) -> None:
        if isinstance(obj, str):
            s = _strip_common_prefixes(obj.strip())
            if len(s) >= _MIN_SNIPPET_LEN:
                snippets.append(s)
            for part in re.split(r"[.\n;]+", s):
                part = part.strip()
                if len(part) >= _MIN_SNIPPET_LEN and part not in snippets:
                    snippets.append(part)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            pass

    _walk(data)

    seen: set[str] = set()
    result: list[str] = []
    for s in sorted(snippets, key=len, reverse=True):
        if s not in seen:
            seen.add(s)
            result.append(s)
        if len(result) >= max_snippets:
            break
    return result


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


def _current_turn_id(transcript_path: str | None) -> str | None:
    """Fingerprint of the last assistant turn (tool_use IDs joined).

    Claude Code writes the full assistant message (including all tool_use
    blocks) before executing any tool in that turn, so when the first hook
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


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _resolve_parent_task_action_id(parent_claude_session_id: str | None) -> str | None:
    """Look up the parent's last Task action_id from their HookState."""
    if not parent_claude_session_id:
        return None
    parent_state = HookState.load(parent_claude_session_id)
    return parent_state.last_task_action_id


def _ensure_session(
    endpoint: str,
    api_key: str,
    agent_id: str,
    state: HookState,
    transcript_path: str | None,
    parent_claude_session_id: str | None,
) -> str | None:
    """Return an existing merkl session_id or create one. Returns None on failure."""
    if pinned := os.environ.get("MERKL_SESSION_ID"):
        return pinned
    if state.session_id:
        return state.session_id

    parent_action_id = _resolve_parent_task_action_id(parent_claude_session_id)

    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "goal": _infer_goal(transcript_path),
        "allowed_tools": [],
        "data_scope": [],
        "policy_reference": "claude-code",
    }
    if parent_action_id:
        payload["parent_action_id"] = parent_action_id

    resp = httpx.post(
        f"{endpoint}/v1/sessions",
        json=payload,
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )
    resp.raise_for_status()
    state.session_id = resp.json()["session_id"]
    return state.session_id


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _seal_session_on_exit(
    endpoint: str, api_key: str, claude_session_id: str,
) -> None:
    """On SessionEnd, seal the Merkl session so the dashboard flips it out of Live.

    If the user quit before any tool call, there's no session to seal.
    """
    state = HookState.load(claude_session_id)
    if not state.session_id:
        return
    try:
        httpx.post(
            f"{endpoint}/v1/sessions/{state.session_id}/seal",
            headers={"X-Merkl-API-Key": api_key},
            timeout=5.0,
        )
    except Exception:
        # Hook must never block Claude Code's exit flow.
        return
    state.delete()


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

    if event == "SessionEnd":
        _seal_session_on_exit(endpoint, api_key, claude_session_id)
        return

    # PostToolUse path
    tool_name: str = payload.get("tool_name", "unknown")
    tool_input: object = payload.get("tool_input", {})
    tool_response: object = payload.get("tool_response", payload.get("tool_result", ""))
    transcript_path: str | None = payload.get("transcript_path")
    parent_claude_session_id: str | None = payload.get("parent_session_id")

    state = HookState.load(claude_session_id)

    session_id = _ensure_session(
        endpoint, api_key, agent_id, state, transcript_path, parent_claude_session_id,
    )
    if not session_id:
        return

    # Layer 1 — structural grouping via transcript turn rotation
    new_turn_id = _current_turn_id(transcript_path)
    if new_turn_id is not None:
        state.rotate_turn(new_turn_id)
        structural_deps = state.depends_on_prev_turn()
    else:
        structural_deps = state.last_linear()

    # Layer 2 — data-flow deps from previous outputs
    dataflow_deps = state.dataflow_depends_on(tool_input)

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
            state.record_action(action_id, tool_response, is_task=(tool_name == "Task"))

    # One atomic write captures session_id, turn state, dataflow cache,
    # and last_task_action_id for the next hook invocation.
    state.save()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Hooks must NEVER block or crash Claude Code
        sys.exit(0)
