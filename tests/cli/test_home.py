"""``$MERKL_HOME`` — one directory, named once, read by every command.

The image sets it to the volume, which is what lets the printed ``docker run``
lines carry no ``--home`` at all. A flag still wins over it, because an operator
running two signers on one host has to be able to say which is which.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from merkl.cli import home as home_module
from merkl.cli.home import (
    CONTAINER_AGENT_DIR,
    MERKL_HOME_ENV,
    agent_key_path,
    default_bundle_dir,
    default_home,
    notary_path,
    policy_path,
    resolve_home,
    treasury_path,
    wallets_path,
)


class TestDefaultHome:
    def test_the_environment_names_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(MERKL_HOME_ENV, "/var/lib/merkl-signer")
        assert default_home() == Path("/var/lib/merkl-signer")

    def test_without_it_the_old_default_stands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(MERKL_HOME_ENV, raising=False)
        assert default_home() == Path.home() / ".merkl" / "signer"

    def test_an_empty_value_is_not_a_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(MERKL_HOME_ENV, "   ")
        assert default_home() == Path.home() / ".merkl" / "signer"

    def test_a_tilde_is_expanded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(MERKL_HOME_ENV, "~/somewhere")
        assert default_home() == Path.home() / "somewhere"

    def test_a_flag_beats_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(MERKL_HOME_ENV, "/var/lib/merkl-signer")
        assert resolve_home(Path("/tmp/other")) == Path("/tmp/other")


class TestTheLayout:
    def test_every_file_is_under_the_home(self, tmp_path: Path) -> None:
        for path in (
            policy_path(tmp_path),
            notary_path(tmp_path),
            wallets_path(tmp_path),
            treasury_path(tmp_path),
            agent_key_path(tmp_path, "agent-0"),
        ):
            assert tmp_path in path.parents

    def test_the_bundle_goes_to_the_container_mount_when_there_is_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mount = tmp_path / "agent"
        mount.mkdir()
        monkeypatch.setattr(home_module, "CONTAINER_AGENT_DIR", mount)
        assert default_bundle_dir(tmp_path / "home", "agent-0") == mount

    def test_and_under_the_home_when_there_is_not(self, tmp_path: Path) -> None:
        assert not CONTAINER_AGENT_DIR.is_dir(), "this test host has a /agent directory"
        home = tmp_path / "home"
        assert default_bundle_dir(home, "agent-0") == home / "agents" / "agent-0" / "bundle"


def test_the_serve_and_token_commands_read_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No ``--home`` anywhere: the relay store still lands in ``$MERKL_HOME``."""
    from merkl.cli.signer import token_command

    monkeypatch.setenv(MERKL_HOME_ENV, str(tmp_path / "home"))
    assert token_command("add", "agent-0") == 0
    capsys.readouterr()
    assert (tmp_path / "home" / "relay" / "relay-tokens.json").exists()
