"""Tests for the Claude Code hook — event routing + seal-on-exit."""

from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def merkl_env(monkeypatch, tmp_path: Path):
    """Minimum env the hook needs to run."""
    monkeypatch.setenv("MERKL_ENDPOINT", "https://test.merkl.local")
    monkeypatch.setenv("MERKL_API_KEY", "mk_test")
    monkeypatch.setenv("MERKL_AGENT_ID", "claude-code-test")
    # Redirect the hook's /tmp caches into a pytest tmp_path so tests don't
    # collide with each other or with real Claude Code sessions.
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    yield


@pytest.fixture
def capture_httpx(monkeypatch):
    """Capture every httpx.post call the hook makes; short-circuit the network."""
    import httpx

    calls: list[dict] = []

    class _FakeResponse:
        is_success = True
        status_code = 200
        text = ""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"session_id": "019d9999-0000-7000-8000-000000000001", "action_id": "a-1"}

    def fake_post(url, **kw):
        calls.append({"url": url, "json": kw.get("json"), "headers": kw.get("headers")})
        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    yield calls


def _run_hook_with(payload: dict) -> None:
    """Run the hook's main() with a JSON payload on stdin."""
    from merkl.hooks import claude_code

    sys.stdin = io.StringIO(json.dumps(payload))
    try:
        claude_code.main()
    finally:
        sys.stdin = sys.__stdin__


def test_session_end_seals_the_session(merkl_env, tmp_path, capture_httpx):  # noqa: ANN001
    """When Claude Code fires SessionEnd (user /exit, /clear, or window
    close), the hook seals the Merkl session so the dashboard no longer
    shows it as Live."""
    # Seed the session cache as if a prior PostToolUse had created one.
    claude_sid = "claude-sess-abc123"
    merkl_sid = "019d9999-0000-7000-8000-000000000042"
    cache = tmp_path / f"merkl_session_{claude_sid[:16].replace('/', '_')}"
    cache.write_text(merkl_sid)

    _run_hook_with({
        "hook_event_name": "SessionEnd",
        "session_id": claude_sid,
    })

    seal_calls = [c for c in capture_httpx if "/seal" in c["url"]]
    assert len(seal_calls) == 1, f"expected one /seal call, got {capture_httpx}"
    assert seal_calls[0]["url"].endswith(f"/v1/sessions/{merkl_sid}/seal")


def test_session_end_without_known_session_is_a_noop(merkl_env, capture_httpx):  # noqa: ANN001
    """If we don't have a Merkl session_id for this Claude Code session
    (e.g. the user never ran a tool), SessionEnd does nothing — no spurious
    create + immediate seal."""
    _run_hook_with({
        "hook_event_name": "SessionEnd",
        "session_id": "claude-sess-unknown",
    })
    assert capture_httpx == []


def test_post_tool_use_still_records_actions(merkl_env, capture_httpx, tmp_path):  # noqa: ANN001
    """Regression: adding event routing must not break the default
    PostToolUse path. A payload with no hook_event_name, or
    hook_event_name=PostToolUse, still POSTs /actions."""
    payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sess-xyz",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_response": "file.txt\n",
    }
    _run_hook_with(payload)
    action_calls = [c for c in capture_httpx if "/actions" in c["url"]]
    assert len(action_calls) == 1
