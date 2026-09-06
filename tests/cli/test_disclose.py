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


def _receipt_store(tmp_path: Path) -> Path:
    """A local receipt store holding the receipt for action aaa-1."""
    import json as _json

    from merkl.core.vectors import VECTORS_DIR

    case = _json.loads((VECTORS_DIR / "receipts.json").read_text())["cases"][0]
    store = tmp_path / "receipts"
    store.mkdir()
    receipt = {
        "envelope": case["envelope"],
        "leaves": case["leaves"],
        "action_id": "aaa-1",
    }
    (store / "r1.json").write_text(_json.dumps(receipt))
    return store


def test_disclose_renders_the_page_locally(tmp_path: Path) -> None:
    """No notary, no network: the page is rendered here (plan D7)."""
    d = _write_evidence(tmp_path)
    out = disclose("aaa-1", evidence_dir=d, endpoint=None, out_dir=tmp_path / "pkg")
    page = (out / "verify.html").read_text()
    assert page.startswith("<!DOCTYPE html>")
    assert "merkl-receipt-leaf-v1" in page, "the verifier is inlined, not fetched"
    lines = (out / "evidence.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1  # ONLY the disclosed action
    assert json.loads(lines[0])["action_id"] == "aaa-1"
    assert (out / "bundle.json").is_file()
    assert "works offline" in (out / "README.txt").read_text()


def test_disclose_includes_the_local_receipt(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    store = _receipt_store(tmp_path)
    out = disclose(
        "aaa-1", evidence_dir=d, receipt_dir=store, endpoint=None, out_dir=tmp_path / "pkg"
    )
    bundle = json.loads((out / "bundle.json").read_text())
    assert len(bundle["receipts"]) == 1
    assert "disclosure" not in bundle


def test_disclose_leaves_reveals_only_what_was_asked_for(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    store = _receipt_store(tmp_path)
    out = disclose(
        "aaa-1",
        evidence_dir=d,
        receipt_dir=store,
        endpoint=None,
        out_dir=tmp_path / "pkg",
        leaves=["instruction", "policy_decision"],
    )
    bundle = json.loads((out / "bundle.json").read_text())
    disclosed = bundle["disclosure"]
    assert [leaf["name"] for leaf in disclosed["leaves"]] == ["instruction", "policy_decision"]
    assert len(disclosed["leaf_hashes"]) == 8, "every leaf is still committed, as a hash"
    assert not bundle.get("receipts"), "the whole receipt is not shipped alongside it"


def test_disclose_leaves_without_a_receipt_says_why(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    with pytest.raises(SystemExit) as e:
        disclose("aaa-1", evidence_dir=d, receipt_dir=tmp_path / "none", leaves=["intent"])
    assert "needs a receipt" in str(e.value)


def test_disclose_degrades_to_level_1_when_the_notary_is_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disclosure that needed the notary to be up would not be much of a disclosure."""
    import httpx

    d = _write_evidence(tmp_path)

    class _Resp:
        status_code = 422
        is_success = False
        text = "not sealed"

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp())
    out = disclose(
        "aaa-1", evidence_dir=d, endpoint="http://merkl.test", api_key="k", out_dir=tmp_path / "p"
    )
    assert "level 1 only" in (out / "README.txt").read_text()
    assert (out / "verify.html").is_file()


def test_disclose_uses_the_notary_bundle_when_it_has_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    from merkl.core.vectors.bundles import BUNDLES_DIR

    d = _write_evidence(tmp_path)
    session = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
    captured: dict[str, object] = {}

    class _Resp:
        status_code = 200
        is_success = True

        def json(self) -> dict[str, object]:
            return session

    def fake_get(url: str, **kw: object) -> _Resp:
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
    assert captured["url"] == "http://merkl.test/v1/sessions/sess-1/export"
    assert captured["headers"]["Authorization"] == "Bearer mk_x"
    bundle = json.loads((out / "bundle.json").read_text())
    assert bundle["session"]["session_id"] == session["session"]["session_id"]
    assert "level 2" in (out / "README.txt").read_text()


def test_disclose_missing_action_exits(tmp_path: Path) -> None:
    d = _write_evidence(tmp_path)
    with pytest.raises(SystemExit) as e:
        disclose("ghost", evidence_dir=d, endpoint="http://merkl.test", api_key="k")
    assert "No evidence entry" in str(e.value)
