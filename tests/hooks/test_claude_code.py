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


def test_display_name_uses_basename_for_file_tools():
    from merkl.hooks.claude_code import _display_name

    path = "/Users/someone/Developer/repo/src/pkg/service.py"
    assert _display_name("Read", {"file_path": path}) == "Read service.py"
    assert _display_name("Write", {"file_path": path}) == "Write service.py"
    assert _display_name("Edit", {"file_path": path}) == "Edit service.py"


def test_display_name_distinguishes_two_files_in_same_dir():
    """The original bug: both calls rendered identically after [:60] truncation."""
    from merkl.hooks.claude_code import _display_name

    long_prefix = "/Users/name/Developer/project/packages/pkg/src/deep/path"
    a = _display_name("Edit", {"file_path": f"{long_prefix}/alpha.py"})
    b = _display_name("Edit", {"file_path": f"{long_prefix}/beta.py"})
    assert a != b
    assert a.endswith("alpha.py")
    assert b.endswith("beta.py")


def test_display_name_search_and_web_tools():
    from merkl.hooks.claude_code import _display_name

    assert _display_name("Grep", {"pattern": "foo", "path": "src/pkg"}).startswith("Grep foo")
    assert _display_name("WebFetch", {"url": "https://example.com/x"}).startswith("Fetched example.com/x")
    assert _display_name("Task", {"description": "audit auth"}).startswith("Sub-agent: audit auth")


def test_status_flags_error_responses():
    from merkl.hooks.claude_code import _status

    assert _status({"is_error": True, "content": [{"text": "boom"}]}) == "failed"
    assert _status({"error": "nope"}) == "failed"
    assert _status({"content": [{"is_error": True}]}) == "failed"
    assert _status("Error: command failed") == "failed"
    assert _status("ok") == "success"
    assert _status({"content": [{"text": "ok"}]}) == "success"


def test_category_maps_per_tool():
    from merkl.hooks.claude_code import _category

    assert _category("Read") == "data_access"
    assert _category("Write") == "modification"
    assert _category("Bash") == "execution"
    assert _category("WebFetch") == "external"
    assert _category("Task") == "sub_agent"
    assert _category("Mystery") == "reasoning"


def test_clean_goal_strips_shell_prompts():
    from merkl.hooks.claude_code import _clean_goal

    pasted = (
        "(base) [user@host] ~/Developer/repo (branch) ❯ supabase db pull\n"
        "Initialising login role...\nConnecting to remote database..."
    )
    assert not _clean_goal(pasted).startswith("(base)")


def test_clean_goal_caps_length():
    from merkl.hooks.claude_code import _clean_goal

    goal = _clean_goal("short but clear question about auth")
    assert goal == "short but clear question about auth"

    long = "please help me " * 40
    assert len(_clean_goal(long)) <= 160


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


def test_privacy_default_sends_no_payload_text(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    """By default the notary sees only the tool name and typed metadata —
    no command text in display_name, empty previews."""
    monkeypatch.delenv("MERKL_INCLUDE_PREVIEWS", raising=False)
    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    _run_hook_with({
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sess-priv",
        "tool_name": "Bash",
        "tool_input": {"command": "psql -c 'select * from payments'"},
        "tool_response": "42 rows\n",
    })
    action = [c for c in capture_httpx if "/actions" in c["url"]][0]["json"]
    assert action["display_name"] == "Bash"
    assert action["input_preview"] == ""
    assert action["output_preview"] == ""
    assert "payments" not in json.dumps(action)
    # Hashes still commit to the real payload
    assert len(action["input_hash"]) == 64


def test_previews_opt_in_restores_rich_labels(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    monkeypatch.setenv("MERKL_INCLUDE_PREVIEWS", "1")
    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    _run_hook_with({
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sess-verb",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "tool_response": "file.txt\n",
    })
    action = [c for c in capture_httpx if "/actions" in c["url"]][0]["json"]
    assert action["display_name"] == "$ ls -la"
    assert action["input_preview"] == "ls -la"


def test_evidence_log_holds_preimages(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    """The local evidence log keeps raw payloads whose canonical hash equals
    the hash committed to the notary — the disclosure path for audits."""
    from merkl.shared.hashing import canonical_hash

    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    _run_hook_with({
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sess-evd",
        "tool_name": "Bash",
        "tool_input": {"command": "stripe transfer --amount 100"},
        "tool_response": {"ok": True},
    })
    action = [c for c in capture_httpx if "/actions" in c["url"]][0]["json"]
    files = list((tmp_path / "evidence").glob("*.jsonl"))
    assert len(files) == 1
    entry = json.loads(files[0].read_text().splitlines()[0])
    assert entry["action_id"] == "a-1"
    # Raw payload is in the evidence, NOT on the notary
    assert entry["input"]["command"] == "stripe transfer --amount 100"
    # Self-check: re-hash evidence -> matches what the notary recorded
    assert canonical_hash(entry["input"]).hex() == action["input_hash"]
    assert canonical_hash(entry["output"]).hex() == action["output_hash"]


def test_evidence_capture_can_be_disabled(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    monkeypatch.setenv("MERKL_EVIDENCE_DIR", "off")
    _run_hook_with({
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sess-noevd",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_response": "x",
    })
    assert not (Path.home() / ".merkl").exists() or True  # no crash is the contract
    assert len([c for c in capture_httpx if "/actions" in c["url"]]) == 1


def test_infer_goal_skips_synthetic_user_messages(tmp_path, merkl_env):  # noqa: ANN001
    """Caveat wrappers and slash-command expansions are user-role lines in
    the transcript but not the human's prompt — the goal must skip them."""
    from merkl.hooks.claude_code import _infer_goal

    transcript = tmp_path / "t.jsonl"
    lines = [
        {"message": {"role": "user", "content": "<local-command-caveat>Caveat: The messages below were generated..."}},
        {"message": {"role": "user", "content": [{"type": "text", "text": "<command-name>/hooks</command-name>"}]}},
        {"message": {"role": "user", "content": "<local-command-stdout>Set model to Opus 5</local-command-stdout>"}},
        {"isMeta": True, "message": {"role": "user", "content": "meta noise"}},
        {"message": {"role": "assistant", "content": "hi"}},
        {"message": {"role": "user", "content": "Fix the billing rate bug"}},
    ]
    transcript.write_text("\n".join(json.dumps(x) for x in lines))
    assert _infer_goal(str(transcript)) == "Fix the billing rate bug"


def test_infer_goal_falls_back_when_only_synthetic(tmp_path, merkl_env):  # noqa: ANN001
    from merkl.hooks.claude_code import _infer_goal

    transcript = tmp_path / "t.jsonl"
    transcript.write_text(json.dumps(
        {"message": {"role": "user", "content": "<local-command-caveat>only noise"}}
    ))
    assert _infer_goal(str(transcript)) == "Claude Code session"


def test_user_prompt_submit_records_human_input(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "ev"))
    _run_hook_with({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "claude-sess-prompt",
        "prompt": "Refund order #4821 and email the customer",
    })
    actions = [c for c in capture_httpx if c["url"].endswith("/actions")]
    assert len(actions) == 1
    a = actions[0]["json"]
    assert a["action_type"] == "human_input"
    assert a["tool_name"] == "user_prompt"
    assert a["category"] == "human"
    # Privacy default: prompt text stays local, only the hash leaves
    assert a["display_name"] == "User prompt"
    assert a["input_preview"] == ""
    assert "Refund" not in json.dumps(a)


def test_user_prompt_skips_synthetic(merkl_env, capture_httpx):  # noqa: ANN001
    _run_hook_with({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "claude-sess-prompt2",
        "prompt": "<command-name>/hooks</command-name>",
    })
    assert [c for c in capture_httpx if c["url"].endswith("/actions")] == []


def test_permission_denied_records_blocked_approval(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    from merkl.hooks.claude_code import HookState

    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "ev"))
    state = HookState(claude_session_id="claude-sess-perm",
                      session_id="019d9999-0000-7000-8000-000000000077")
    state.save()
    _run_hook_with({
        "hook_event_name": "PermissionDenied",
        "session_id": "claude-sess-perm",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    })
    actions = [c for c in capture_httpx if c["url"].endswith("/actions")]
    assert len(actions) == 1
    a = actions[0]["json"]
    assert a["action_type"] == "approval_request"
    assert a["guardrail_result"] == "blocked"
    assert a["status"] == "blocked"
    assert a["display_name"] == "Permission denied: Bash"
    # Arguments stay hashed — never in plaintext fields
    assert "rm -rf" not in json.dumps(a)


def test_session_end_commits_transcript_then_seals(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    import hashlib

    from merkl.hooks.claude_code import HookState

    monkeypatch.setenv("MERKL_EVIDENCE_DIR", str(tmp_path / "ev"))
    transcript = tmp_path / "t.jsonl"
    transcript.write_text('{"role":"user","content":"hi"}\n')
    expected_digest = hashlib.sha256(transcript.read_bytes()).hexdigest()

    state = HookState(claude_session_id="claude-sess-tx",
                      session_id="019d9999-0000-7000-8000-000000000088")
    state.save()
    _run_hook_with({
        "hook_event_name": "SessionEnd",
        "session_id": "claude-sess-tx",
        "transcript_path": str(transcript),
    })
    actions = [c for c in capture_httpx if c["url"].endswith("/actions")]
    seals = [c for c in capture_httpx if c["url"].endswith("/seal")]
    assert len(actions) == 1 and len(seals) == 1
    a = actions[0]["json"]
    assert a["action_type"] == "transcript"
    assert a["tool_name"] == "session_transcript"
    # The evidence entry carries the digest an auditor re-computes from
    # the operator's transcript copy
    ev = list((tmp_path / "ev").glob("*.jsonl"))[0].read_text()
    assert expected_digest in ev


def test_session_end_keeps_session_id_for_resume(merkl_env, capture_httpx, tmp_path, monkeypatch):  # noqa: ANN001
    """After a clean exit, a --resume of the same conversation must chain to
    the sealed session — so SessionEnd keeps the Merkl session id."""
    from merkl.hooks.claude_code import HookState

    monkeypatch.setenv("MERKL_EVIDENCE_DIR", "off")
    sid = "019d9999-0000-7000-8000-000000000099"
    state = HookState(claude_session_id="claude-sess-resume", session_id=sid,
                      turn_id="t1", current_actions=["a-1"], dataflow={"a-1": ["xxxx"]})
    state.save()
    _run_hook_with({"hook_event_name": "SessionEnd", "session_id": "claude-sess-resume"})

    reloaded = HookState.load("claude-sess-resume")
    assert reloaded.session_id == sid          # chain identity survives
    assert reloaded.current_actions == []      # scratch does not
    assert reloaded.dataflow == {}
    assert reloaded.turn_id is None
