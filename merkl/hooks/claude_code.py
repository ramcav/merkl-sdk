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
from datetime import datetime, timezone
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


_FILE_TOOLS = {"Read", "Write", "Edit", "NotebookEdit"}
_SEARCH_TOOLS = {"Glob", "Grep"}


def _previews_enabled() -> bool:
    """Whether plaintext (previews + rich display names) leaves this machine.

    Default OFF: the notary is a notarization layer, not a data warehouse.
    display_name is hashed into the Merkle leaf, so anything placed there is
    stored server-side forever to keep proofs verifiable — with previews
    disabled we send only the tool name. Opt in with MERKL_INCLUDE_PREVIEWS=1.
    """
    return os.environ.get("MERKL_INCLUDE_PREVIEWS", "").lower() in ("1", "true", "yes")


def _display_name(tool_name: str, tool_input: object) -> str:
    """Short human-readable label for a tool call.

    File tools show the basename (not the full path) — otherwise every
    Read/Edit in the same repo renders identically after truncation.
    """
    if not isinstance(tool_input, dict):
        return tool_name
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", "")).strip()
        label = cmd.split("\n")[0][:72]
        return f"$ {label}" if label else "Bash"
    if tool_name in _FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if path:
            return f"{tool_name} {Path(str(path)).name}"
        return tool_name
    if tool_name in _SEARCH_TOOLS:
        pattern = tool_input.get("pattern") or tool_input.get("query", "")
        path = tool_input.get("path", "")
        scope = f" in {Path(str(path)).name}" if path else ""
        return f"{tool_name} {str(pattern)[:48]}{scope}".strip()
    if tool_name == "WebFetch":
        url = str(tool_input.get("url", "")).replace("https://", "").replace("http://", "")
        return f"Fetched {url[:60]}" if url else "WebFetch"
    if tool_name == "WebSearch":
        q = tool_input.get("query", "")
        return f"Searched {str(q)[:60]}" if q else "WebSearch"
    if tool_name == "Task":
        desc = tool_input.get("description") or tool_input.get("prompt", "")
        return f"Sub-agent: {str(desc)[:50]}" if desc else "Sub-agent"
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


_CATEGORY_BY_TOOL: dict[str, str] = {
    "Read": "data_access",
    "Glob": "data_access",
    "Grep": "data_access",
    "Write": "modification",
    "Edit": "modification",
    "NotebookEdit": "modification",
    "Bash": "execution",
    "WebFetch": "external",
    "WebSearch": "external",
    "Task": "sub_agent",
}


def _category(tool_name: str) -> str:
    return _CATEGORY_BY_TOOL.get(tool_name, "reasoning")


def _status(tool_response: object) -> str:
    """Detect tool failure from the PostToolUse payload.

    Claude Code marks failed tool calls with ``is_error: true`` on the
    response block; some adapters instead return a dict with ``error``
    or prefix plaintext with ``"Error: "``. Treat any of these as failed.
    """
    if isinstance(tool_response, dict):
        if tool_response.get("is_error") or tool_response.get("error"):
            return "failed"
        # Nested content blocks (Claude Code standard shape).
        content = tool_response.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("is_error"):
                    return "failed"
    elif isinstance(tool_response, str):
        if tool_response.lstrip().startswith("Error:"):
            return "failed"
    return "success"


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


def _evidence_dir() -> Path:
    """Where raw action payloads are kept — the operator's machine, never the notary.

    The notary stores only hashes; this local append-only log holds the
    preimages. At audit time the operator discloses selected entries and the
    auditor re-hashes them against the signed Merkle leaves. Override with
    MERKL_EVIDENCE_DIR; set MERKL_EVIDENCE_DIR=off to disable capture.
    """
    return Path(os.environ.get("MERKL_EVIDENCE_DIR") or Path.home() / ".merkl" / "evidence")


def _append_evidence(
    *,
    session_id: str,
    action_id: str,
    tool_name: str,
    tool_input: object,
    tool_response: object,
    input_hash: str,
    output_hash: str,
) -> None:
    """Append this action's raw payloads to the local evidence log (JSONL).

    One file per Merkl session. Hashes are stored alongside so an entry is
    self-checking: canonical_hash(input) must equal input_hash, which must
    equal the field committed in the Merkle leaf. Failures are swallowed —
    evidence capture must never break the agent.
    """
    if os.environ.get("MERKL_EVIDENCE_DIR", "").lower() == "off":
        return
    try:
        directory = _evidence_dir()
        directory.mkdir(parents=True, exist_ok=True)
        entry = {
            "action_id": action_id,
            "session_id": session_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "input": tool_input,
            "output": tool_response,
            "input_hash": input_hash,
            "output_hash": output_hash,
        }
        with open(directory / f"{session_id}.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass


_SHELL_PROMPT_RE = re.compile(r"^\s*[\(\[][^\]\)]*[\)\]].*?[❯>\$%#]\s*", re.MULTILINE)


def _clean_goal(text: str) -> str:
    """Strip common noise so pasted terminal output doesn't become the goal.

    Drops shell prompt prefixes like `(base) [user@host] ~/path ❯ cmd...`,
    collapses whitespace, removes leading code fences, truncates to one
    sentence or 160 chars — whichever comes first.
    """
    text = text.strip()
    # Strip leading code fences
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else text
        text = text.rstrip("`").strip()
    # Drop shell prompt lines at the start of a paste.
    lines = text.split("\n")
    while lines and _SHELL_PROMPT_RE.match(lines[0]):
        lines = lines[1:]
    text = "\n".join(lines).strip()
    # First sentence (period, question, newline).
    for sep in ("\n\n", "\n", ". ", "? "):
        if sep in text:
            first = text.split(sep, 1)[0]
            if len(first) >= 10:
                text = first
                break
    # Collapse internal whitespace.
    text = re.sub(r"\s+", " ", text).strip()
    return text[:160] if text else "Claude Code session"


# Harness-generated "user" messages that are not the human's prompt. The
# transcript wraps local-command output, slash-command expansions, and
# system notes as user-role messages; a goal built from one of these reads
# as garbage in the dashboard ("<local-command-caveat>Caveat: ...").
_SYNTHETIC_PREFIXES = (
    "<local-command-caveat>",
    "<command-name>",
    "<command-message>",
    "<command-args>",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
    "<system-reminder>",
    "<task-notification>",
    "[Request interrupted",
)


def _is_synthetic_user_text(text: str) -> bool:
    return text.lstrip().startswith(_SYNTHETIC_PREFIXES)


def _infer_goal(transcript_path: str | None) -> str:
    """Read the first REAL human message from the transcript as the goal.

    Skips harness-synthesized user messages (caveat wrappers, slash-command
    expansions, meta lines) and keeps scanning until actual prompt text.
    """
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
            if msg.get("isMeta"):
                continue
            role = msg.get("role") or msg.get("message", {}).get("role")
            content = msg.get("content") or msg.get("message", {}).get("content")
            if role != "user":
                continue
            if isinstance(content, str) and content.strip():
                if _is_synthetic_user_text(content):
                    continue
                return _clean_goal(content)
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "").strip()
                        if text and not _is_synthetic_user_text(text):
                            return _clean_goal(text)
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

def _record_event_action(
    *,
    endpoint: str,
    api_key: str,
    agent_id: str,
    state: HookState,
    session_id: str,
    action_type: str,
    tool_name: str,
    display_name: str,
    input_data: object,
    output_data: object,
    guardrail_result: str = "not_evaluated",
    status: str = "success",
    category: str,
    input_preview: str = "",
    output_preview: str = "",
) -> str | None:
    """Record a non-tool session event (user prompt, permission decision,
    transcript commitment) as an action. Same hashing + evidence path as
    tool calls so the event is a first-class Merkle leaf."""
    input_hash = _sha256(input_data)
    output_hash = _sha256(output_data)
    resp = httpx.post(
        f"{endpoint}/v1/sessions/{session_id}/actions",
        json={
            "agent_id": agent_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "display_name": display_name,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "drift_score": 0.0,
            "guardrail_result": guardrail_result,
            "policy_reference": "claude-code",
            "status": status,
            "category": category,
            "depends_on": state.last_linear(),
            "input_preview": input_preview,
            "output_preview": output_preview,
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )
    if not resp.is_success:
        return None
    action_id = resp.json().get("action_id", "")
    if action_id:
        state.record_action(action_id, output_data, is_task=False)
        _append_evidence(
            session_id=session_id,
            action_id=action_id,
            tool_name=tool_name,
            tool_input=input_data,
            tool_response=output_data,
            input_hash=input_hash,
            output_hash=output_hash,
        )
    return action_id or None


def _record_user_prompt(
    endpoint: str, api_key: str, agent_id: str, payload: dict,
) -> None:
    """UserPromptSubmit → human_input leaf. The instruction becomes part of
    the committed record, so 'the agent did this unprompted' vs 'the user
    told it to' is decidable from the proof chain."""
    prompt = str(payload.get("prompt", ""))
    if not prompt.strip() or _is_synthetic_user_text(prompt):
        return
    claude_session_id: str = payload.get("session_id", "unknown")
    state = HookState.load(claude_session_id)
    session_id = _ensure_session(
        endpoint, api_key, agent_id, state,
        payload.get("transcript_path"), payload.get("parent_session_id"),
    )
    if not session_id:
        return
    verbose = _previews_enabled()
    _record_event_action(
        endpoint=endpoint, api_key=api_key, agent_id=agent_id,
        state=state, session_id=session_id,
        action_type="human_input",
        tool_name="user_prompt",
        display_name=prompt.split("\n")[0][:72] if verbose else "User prompt",
        input_data={"prompt": prompt},
        output_data="",
        category="human",
        input_preview=prompt[:200] if verbose else "",
    )
    state.save()


def _record_permission_event(
    endpoint: str, api_key: str, agent_id: str, event: str, payload: dict,
) -> None:
    """PermissionRequest / PermissionDenied → approval_request leaf.

    A denial is the audit jackpot: the agent provably attempted something
    and a human provably said no. Tool name only — arguments stay hashed.
    """
    claude_session_id: str = payload.get("session_id", "unknown")
    state = HookState.load(claude_session_id)
    if not state.session_id:
        # No session yet: a permission prompt before any recorded activity
        # would create a session just to hold it; skip instead.
        return
    tool = str(payload.get("tool_name", "unknown"))
    denied = event == "PermissionDenied"
    _record_event_action(
        endpoint=endpoint, api_key=api_key, agent_id=agent_id,
        state=state, session_id=state.session_id,
        action_type="approval_request",
        tool_name=tool,
        display_name=(
            f"Permission denied: {tool}" if denied else f"Permission requested: {tool}"
        ),
        input_data={"tool_name": tool, "tool_input": payload.get("tool_input", {})},
        output_data={"decision": "denied" if denied else "requested"},
        guardrail_result="blocked" if denied else "pending_approval",
        status="blocked" if denied else "pending",
        category="approval",
    )
    state.save()


def _seal_session_on_exit(
    endpoint: str, api_key: str, claude_session_id: str,
    transcript_path: str | None = None,
) -> None:
    """On SessionEnd, commit the full transcript and seal the session.

    The transcript leaf is the completeness proof: one SHA-256 over the
    whole conversation file. Any later dispute about anything said in the
    session resolves by re-hashing the operator's transcript copy. If the
    user quit before any tool call, there's no session to seal.
    """
    state = HookState.load(claude_session_id)
    if not state.session_id:
        return
    agent_id = os.environ.get("MERKL_AGENT_ID", "claude-code")
    try:
        if transcript_path and Path(transcript_path).exists():
            digest = _sha256_file(Path(transcript_path))
            _record_event_action(
                endpoint=endpoint, api_key=api_key, agent_id=agent_id,
                state=state, session_id=state.session_id,
                action_type="transcript",
                tool_name="session_transcript",
                display_name="Session transcript",
                input_data={"transcript_sha256": digest},
                output_data={"transcript_path": str(transcript_path)},
                category="transcript",
            )
        httpx.post(
            f"{endpoint}/v1/sessions/{state.session_id}/seal",
            headers={"X-Merkl-API-Key": api_key},
            timeout=5.0,
        )
    except Exception:
        # Hook must never block Claude Code's exit flow.
        return
    state.delete()


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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
        _seal_session_on_exit(
            endpoint, api_key, claude_session_id, payload.get("transcript_path")
        )
        return

    if event == "UserPromptSubmit":
        _record_user_prompt(endpoint, api_key, agent_id, payload)
        return

    if event in ("PermissionRequest", "PermissionDenied"):
        _record_permission_event(endpoint, api_key, agent_id, event, payload)
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

    # Privacy default: only the tool name and typed metadata leave this
    # machine. Payload text (rich display names, previews) is opt-in.
    verbose = _previews_enabled()
    input_hash = _sha256(tool_input)
    output_hash = _sha256(tool_response)
    resp = httpx.post(
        f"{endpoint}/v1/sessions/{session_id}/actions",
        json={
            "agent_id": agent_id,
            "action_type": "tool_call",
            "tool_name": tool_name,
            "display_name": _display_name(tool_name, tool_input) if verbose else tool_name,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "drift_score": 0.0,
            "guardrail_result": "not_evaluated",
            "policy_reference": "claude-code",
            "status": _status(tool_response),
            "category": _category(tool_name),
            "depends_on": depends_on,
            "input_preview": _input_preview(tool_name, tool_input) if verbose else "",
            "output_preview": _output_preview(tool_response) if verbose else "",
        },
        headers={"X-Merkl-API-Key": api_key},
        timeout=5.0,
    )

    if resp.is_success:
        action_id = resp.json().get("action_id", "")
        if action_id:
            state.record_action(action_id, tool_response, is_task=(tool_name == "Task"))
            _append_evidence(
                session_id=session_id,
                action_id=action_id,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_response=tool_response,
                input_hash=input_hash,
                output_hash=output_hash,
            )

    # One atomic write captures session_id, turn state, dataflow cache,
    # and last_task_action_id for the next hook invocation.
    state.save()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Hooks must NEVER block or crash Claude Code
        sys.exit(0)
