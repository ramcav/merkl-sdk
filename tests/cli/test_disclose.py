"""merkl disclose — operator-side disclosure packaging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from merkl.cli.disclose import disclose, find_evidence_entry


def _write_evidence(tmp_path: Path) -> Path:
    d = tmp_path / "evidence"
    d.mkdir()
    entries = [
        {"action_id": "aaa-1", "session_id": "sess-1", "tool_name": "Bash",
         "input": {"command": "ls"}, "output": "x",
         "input_hash": "0" * 64, "output_hash": "1" * 64},
        {"action_id": "bbb-2", "session_id": "sess-1", "tool_name": "Read",
         "input": {"file": "f"}, "output": "y",
         "input_hash": "2" * 64, "output_hash": "3" * 64},
    ]
    with open(d / "sess-1.jsonl", "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return d


def test_find_evidence_entry_returns_raw_line(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    found = find_evidence_entry(d, "bbb-2")
    assert found is not None
    entry, raw = found
    assert entry["tool_name"] == "Read"
    assert json.loads(raw) == entry  # raw line round-trips


def test_find_evidence_entry_missing(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    assert find_evidence_entry(d, "nope") is None


def test_disclose_writes_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    d = _write_evidence(tmp_path)

    class _Resp:
        status_code = 200
        is_success = True
        text = "<html>verifier</html>"

    captured = {}

    def fake_get(url, **kw):
        captured["url"] = url
        captured["headers"] = kw.get("headers")
        return _Resp()

    monkeypatch.setattr(httpx, "get", fake_get)
    out = disclose(
        "aaa-1",
        evidence_dir=d,
        endpoint="http://merkl.test",
        api_key="mk_x",
        out_dir=tmp_path / "pkg",
    )
    assert captured["url"] == "http://merkl.test/v1/sessions/sess-1/verify.html"
    assert captured["headers"]["Authorization"] == "Bearer mk_x"
    assert (out / "verify.html").read_text() == "<html>verifier</html>"
    lines = (out / "evidence.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1  # ONLY the disclosed action
    assert json.loads(lines[0])["action_id"] == "aaa-1"


def test_disclose_unsealed_session_explains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    d = _write_evidence(tmp_path)

    class _Resp:
        status_code = 422
        is_success = False
        text = "not sealed"

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp())
    with pytest.raises(SystemExit) as e:
        disclose("aaa-1", evidence_dir=d, endpoint="http://merkl.test", api_key="k")
    assert "seal" in str(e.value)


def test_disclose_missing_action_exits(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    with pytest.raises(SystemExit) as e:
        disclose("ghost", evidence_dir=d, endpoint="http://merkl.test", api_key="k")
    assert "No evidence entry" in str(e.value)
