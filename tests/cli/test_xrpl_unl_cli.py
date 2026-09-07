"""``merkl xrpl pin-unl`` — offline, over the committed real testnet UNL fixture."""

from __future__ import annotations

import json
from pathlib import Path

from merkl.cli.xrpl_unl import pin_unl_command
from merkl.core.vectors.xrpl import FIXTURES_FILE


def _unl_file(tmp_path: Path) -> Path:
    fixtures = json.loads(FIXTURES_FILE.read_text(encoding="utf-8"))
    path = tmp_path / "unl.json"
    path.write_text(json.dumps(fixtures["unl"]), encoding="utf-8")
    return path


def test_pins_the_real_testnet_unl(tmp_path: Path, capsys: object) -> None:
    out = tmp_path / "pinned.json"
    code = pin_unl_command(str(_unl_file(tmp_path)), out=out)
    assert code == 0
    pinned = json.loads(out.read_text(encoding="utf-8"))
    assert pinned["rail"] == "xrpl"
    assert len(pinned["validators"]) == 6
    assert pinned["quorum"] == 5
    assert set(pinned["validators"].keys()) == set(pinned["validators"].values())


def test_a_local_file_that_is_not_a_unl_document_fails_loudly(tmp_path: Path) -> None:
    path = tmp_path / "not-a-unl.json"
    path.write_text("{}", encoding="utf-8")
    assert pin_unl_command(str(path)) == 1


def test_an_unreadable_source_is_a_usage_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    assert pin_unl_command(str(missing)) == 2


def test_a_forged_signature_is_refused(tmp_path: Path) -> None:
    fixtures = json.loads(FIXTURES_FILE.read_text(encoding="utf-8"))
    unl = dict(fixtures["unl"])
    sig = bytearray(bytes.fromhex(unl["signature"]))
    sig[0] ^= 0xFF
    unl["signature"] = sig.hex()
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(unl), encoding="utf-8")
    assert pin_unl_command(str(path)) == 1
