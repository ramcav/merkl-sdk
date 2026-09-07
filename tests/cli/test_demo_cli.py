"""``merkl demo`` — the CLI entry point that runs the five scenarios."""

from __future__ import annotations

from pathlib import Path

from merkl.cli.demo import demo_command


class TestDemoCommand:
    def test_the_fake_rail_runs_and_exits_clean(self, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        code = demo_command(out=tmp_path / "out", node=False)
        assert code == 0
        out = capsys.readouterr().out
        assert "An ordinary invoice" in out
        assert "pages written to" in out
        for stem in (
            "1-benign-payment",
            "2-injection-drain",
            "3-over-threshold-approval",
            "4-structuring",
            "5-reference-mismatch",
        ):
            assert (tmp_path / "out" / "fake" / f"{stem}.html").exists()
        assert (tmp_path / "out" / "fake" / "index.html").exists()

    def test_a_default_output_folder_is_used_when_none_is_given(self) -> None:
        from merkl.cli.demo import DEFAULT_OUT

        assert Path("merkl-demo") == DEFAULT_OUT

    def test_xrpl_without_the_extra_installed_reports_a_clear_error(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        """A missing xrpl/signer-xrpl extra is a clean exit, not a traceback."""
        import merkl.cli.demo as demo_module

        def raises_import_error(*_args: object, **_kwargs: object) -> None:
            raise ImportError("simulated: xrpl extra not installed")

        monkeypatch.setattr(demo_module, "_run_xrpl", raises_import_error)
        code = demo_command(out=tmp_path / "out", xrpl=True, node=False)
        assert code == 2
