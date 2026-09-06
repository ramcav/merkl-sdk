"""``merkl.demo.pages`` — the folder a human opens, checked by both verifiers.

The claim under test is the one the whole demo exists to make: five pages, each
checked by two implementations that share no code, and both agreeing. A page
that only ``merkl verify`` liked would not be much of a demonstration.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from merkl.demo.pages import validator_pins, verify_with_node, verify_with_python, write_pages
from merkl.demo.scenarios import FakeEnvironment, run_all

pytestmark = pytest.mark.asyncio

NODE_MISSING = shutil.which("node") is None


class TestWritePages:
    async def test_five_pages_are_written_in_order(self, tmp_path: Path) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        reports = write_pages(results, tmp_path / "out", rail="fake")
        names = [r.page.name for r in reports]
        assert names == [
            "1-benign-payment.html",
            "2-injection-drain.html",
            "3-over-threshold-approval.html",
            "4-structuring.html",
            "5-reference-mismatch.html",
        ]
        for r in reports:
            assert r.page.exists()
            assert r.bundle.exists()

    async def test_the_index_and_readme_are_written_too(self, tmp_path: Path) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        write_pages(results, tmp_path / "out", rail="fake")
        assert (tmp_path / "out" / "index.html").exists()
        assert (tmp_path / "out" / "README.txt").exists()
        readme = (tmp_path / "out" / "README.txt").read_text()
        assert "merkl verify" in readme
        assert "@merkl/verify" in readme

    async def test_a_fake_rail_page_carries_pinnable_validator_keys(self, tmp_path: Path) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        write_pages(results, tmp_path / "out", rail="fake")
        validators_file = tmp_path / "out" / "bundles" / "1-benign-payment.validators.json"
        assert validators_file.exists()
        data = json.loads(validators_file.read_text())
        assert data["validators"]
        assert data["quorum"] >= 1

    async def test_the_python_verifier_finds_nothing_contradicted_on_every_page(
        self, tmp_path: Path
    ) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        reports = write_pages(results, tmp_path / "out", rail="fake", node=False)
        for report in reports:
            python_reading = report.readings[0]
            assert python_reading.verifier == "merkl verify"
            assert python_reading.ok, python_reading.detail

    @pytest.mark.skipif(NODE_MISSING, reason="node is not on PATH")
    async def test_the_two_verifiers_agree_on_every_page(self, tmp_path: Path) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        reports = write_pages(results, tmp_path / "out", rail="fake", node=True)
        for report in reports:
            assert len(report.readings) == 2
            python_reading, node_reading = report.readings
            assert python_reading.ran and node_reading.ran
            assert python_reading.ok == node_reading.ok == True  # noqa: E712
            assert python_reading.complete == node_reading.complete
            assert report.agreed


class TestVerifierReading:
    async def test_a_page_re_read_from_disk_verifies_with_python_directly(
        self, tmp_path: Path
    ) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        reports = write_pages(results, tmp_path / "out", rail="fake", node=False)
        page = reports[0].page
        pins = validator_pins(results[0])
        reading = verify_with_python(page, validators=pins, quorum=2)
        assert reading.ok

    @pytest.mark.skipif(NODE_MISSING, reason="node is not on PATH")
    async def test_a_missing_node_is_reported_as_did_not_run_never_a_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = FakeEnvironment(home=tmp_path / "rig")
        results = await run_all(env)
        reports = write_pages(results, tmp_path / "out", rail="fake", node=False)
        page = reports[0].page
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        reading = verify_with_node(page, validators={}, quorum=0)
        assert not reading.ran
        assert not reading.ok
