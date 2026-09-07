"""``merkl.core.leaf.action_leaf`` is byte-identical to merkl-api's leaf.

The fixture holds hashes produced by ``merkl_api.action.hashing.compute_leaf_hash``
running under merkl-api's own interpreter (see
``tests/core/reference/gen_merkl_api_reference.py``). This test never imports
``merkl_api`` — the SDK must not depend on the server.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from merkl.core.leaf import action_leaf

_FIXTURE = pathlib.Path(__file__).parent / "reference" / "merkl_api_action_leaf_v1.json"
_REFERENCE = json.loads(_FIXTURE.read_text())
_CASES: list[dict[str, Any]] = _REFERENCE["cases"]


def _fields(case: dict[str, Any], *, drift: Any) -> dict[str, Any]:
    return {
        "action_id": case["action_id"],
        "session_id": case["session_id"],
        "action_type": case["action_type"],
        "tool_name": case["tool_name"],
        "input_hash": case["input_hash"],
        "output_hash": case["output_hash"],
        "timestamp": case["timestamp"],
        "drift_score": drift,
        "guardrail_result": case["guardrail_result"],
        "display_name": case["display_name"],
        "depends_on": case["depends_on"],
        "status": case["status"],
        "category": case["category"],
    }


def test_fixture_covers_enough_ground() -> None:
    assert _REFERENCE["tag"] == "merkl-leaf-v1"
    assert len(_CASES) >= 12
    assert len({c["action_type"] for c in _CASES}) >= 7
    assert any(c["depends_on"] for c in _CASES)
    assert any(not c["tool_name"] for c in _CASES)
    assert any(c["drift_score_str"] == "1e-05" for c in _CASES)


@pytest.mark.parametrize("case", _CASES, ids=[c["tool_name"] or "empty" for c in _CASES])
def test_matches_merkl_api_from_the_exact_string(case: dict[str, Any]) -> None:
    assert action_leaf(**_fields(case, drift=case["drift_score_str"])).hex() == case["leaf"]


@pytest.mark.parametrize("case", _CASES, ids=[c["tool_name"] or "empty" for c in _CASES])
def test_matches_merkl_api_from_the_float(case: dict[str, Any]) -> None:
    assert action_leaf(**_fields(case, drift=case["drift_score"])).hex() == case["leaf"]


def test_a_changed_field_breaks_identity() -> None:
    case = _CASES[0]
    tampered = _fields(case, drift=case["drift_score_str"]) | {"tool_name": "other"}
    assert action_leaf(**tampered).hex() != case["leaf"]
