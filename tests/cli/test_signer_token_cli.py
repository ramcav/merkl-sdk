"""``merkl signer token add|revoke|list`` — relay credential management."""

from __future__ import annotations

from pathlib import Path

from merkl.cli.signer import token_command
from merkl.signer.relay_auth import RelayTokenStore


class TestTokenAdd:
    def test_prints_the_token_exactly_once(self, tmp_path: Path, capsys) -> None:
        assert token_command("add", "ci", home=tmp_path) == 0
        out = capsys.readouterr().out
        assert "ci:" in out
        stored = RelayTokenStore(tmp_path / "relay").load()
        assert len(stored) == 1
        assert stored[0].id == "ci"

    def test_a_duplicate_id_is_refused(self, tmp_path: Path, capsys) -> None:
        token_command("add", "ci", home=tmp_path)
        capsys.readouterr()
        assert token_command("add", "ci", home=tmp_path) == 1

    def test_without_an_id_is_a_usage_error(self, tmp_path: Path, capsys) -> None:
        assert token_command("add", None, home=tmp_path) == 2


class TestTokenList:
    def test_lists_ids_never_tokens(self, tmp_path: Path, capsys) -> None:
        token_command("add", "ci", home=tmp_path)
        first = capsys.readouterr().out
        token_command("add", "dashboard", home=tmp_path)
        second = capsys.readouterr().out

        assert token_command("list", None, home=tmp_path) == 0
        out = capsys.readouterr().out
        assert "ci" in out
        assert "dashboard" in out
        # neither the added tokens' secrets nor the header line leaked into the list
        for printed in (first, second):
            secret = printed.strip().splitlines()[-1] if printed.strip() else ""
            assert secret == "" or secret not in out

    def test_with_none_configured(self, tmp_path: Path, capsys) -> None:
        assert token_command("list", None, home=tmp_path) == 0
        assert "no relay tokens" in capsys.readouterr().out


class TestTokenRevoke:
    def test_removes_it(self, tmp_path: Path, capsys) -> None:
        token_command("add", "ci", home=tmp_path)
        capsys.readouterr()
        assert token_command("revoke", "ci", home=tmp_path) == 0
        assert RelayTokenStore(tmp_path / "relay").load() == ()

    def test_an_unknown_id_is_refused(self, tmp_path: Path, capsys) -> None:
        assert token_command("revoke", "nope", home=tmp_path) == 1

    def test_without_an_id_is_a_usage_error(self, tmp_path: Path, capsys) -> None:
        assert token_command("revoke", None, home=tmp_path) == 2
