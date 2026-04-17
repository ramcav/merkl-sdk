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
    # Seed HookState as if a prior PostToolUse had created one.
    from merkl.hooks.claude_code import HookState

    claude_sid = "claude-sess-abc123"
    merkl_sid = "019d9999-0000-7000-8000-000000000042"
    state = HookState(claude_session_id=claude_sid, session_id=merkl_sid)
    state.save()

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


def test_hook_state_rotates_turns(merkl_env, tmp_path):  # noqa: ANN001
    from merkl.hooks.claude_code import HookState

    state = HookState(claude_session_id="s1")
    state.rotate_turn("turn-a")
    state.current_actions.append("a1")
    state.current_actions.append("a2")

    state.rotate_turn("turn-b")
    assert state.turn_id == "turn-b"
    assert state.prev_actions == ["a1", "a2"]
    assert state.current_actions == []
    assert state.depends_on_prev_turn() == ["a1", "a2"]


def test_hook_state_dataflow_links_matching_snippet(merkl_env, tmp_path):  # noqa: ANN001
    from merkl.hooks.claude_code import HookState

    state = HookState(claude_session_id="s2")
    state.record_action(
        action_id="a1",
        tool_response="the quick brown fox jumps over the lazy dog by the river",
        is_task=False,
    )
    deps = state.dataflow_depends_on(
        {"content": "Report: the quick brown fox jumps over the lazy dog by the river"}
    )
    assert deps == ["a1"]


def test_hook_state_dataflow_caps_fanin(merkl_env, tmp_path):  # noqa: ANN001
    """Cap ``_MAX_DEPS_PER_ACTION`` prevents spurious fan-in explosions."""
    from merkl.hooks.claude_code import _MAX_DEPS_PER_ACTION, HookState

    state = HookState(claude_session_id="s3")
    shared = "X" * 60
    for i in range(_MAX_DEPS_PER_ACTION * 3):
        state.record_action(action_id=f"a{i}", tool_response=shared, is_task=False)
    deps = state.dataflow_depends_on({"content": shared})
    assert len(deps) == _MAX_DEPS_PER_ACTION


def test_hook_state_task_link_sets_last_task_action_id(merkl_env, tmp_path):  # noqa: ANN001
    from merkl.hooks.claude_code import HookState

    state = HookState(claude_session_id="parent")
    state.record_action(action_id="task-77", tool_response="spawned", is_task=True)
    state.save()

    reloaded = HookState.load("parent")
    assert reloaded.last_task_action_id == "task-77"


def test_hook_state_round_trip(merkl_env, tmp_path):  # noqa: ANN001
    from merkl.hooks.claude_code import HookState

    original = HookState(
        claude_session_id="round",
        session_id="sid-1",
        turn_id="t-2",
        current_actions=["c1"],
        prev_actions=["p1", "p2"],
        dataflow={"c1": ["long snippet value that exceeds min"]},
        last_task_action_id="task-1",
    )
    original.save()
    reloaded = HookState.load("round")
    assert reloaded == original
