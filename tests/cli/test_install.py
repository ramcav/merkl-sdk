"""merkl install — hook command correctness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from merkl.cli.main import _install_claude_code, _uninstall_claude_code


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MERKL_API_KEY", raising=False)
    return tmp_path


def _settings(tmp_path: Path) -> dict:
    return json.loads((tmp_path / ".claude" / "settings.json").read_text())


def test_install_uses_sys_executable(project_dir: Path) -> None:
    _install_claude_code(api_key="mk_test")
    cmd = _settings(project_dir)["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert sys.executable in cmd            # never bare "python"
    assert "MERKL_API_KEY=mk_test" in cmd   # key baked in
    assert "MERKL_ENDPOINT" not in cmd      # default endpoint stays hardcoded


def test_install_registers_all_events(project_dir: Path) -> None:
    _install_claude_code(api_key="mk_test")
    events = set(_settings(project_dir)["hooks"].keys())
    assert events == {
        "PostToolUse", "SessionEnd", "UserPromptSubmit",
        "PermissionRequest", "PermissionDenied",
    }


def test_install_endpoint_flag_for_self_hosting(project_dir: Path) -> None:
    _install_claude_code(api_key="mk_test", endpoint="https://merkl.internal")
    cmd = _settings(project_dir)["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert "MERKL_ENDPOINT=https://merkl.internal" in cmd


def test_install_key_from_env(project_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MERKL_API_KEY", "mk_env")
    _install_claude_code()
    cmd = _settings(project_dir)["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert "MERKL_API_KEY=mk_env" in cmd


def test_uninstall_removes_any_command_variant(project_dir: Path) -> None:
    _install_claude_code(api_key="mk_test")
    _uninstall_claude_code()
    hooks = _settings(project_dir)["hooks"]
    assert all(not bucket for bucket in hooks.values())
