"""Generate merkl-api's own ``merkl-leaf-v1`` hashes as a frozen fixture.

Run with **merkl-api's** interpreter, which has ``merkl_api`` importable::

    /Users/.../merkl-api/.venv/bin/python \
        tests/core/reference/gen_merkl_api_reference.py

It writes ``merkl_api_action_leaf_v1.json`` next to itself: plain fields plus the
leaf hash that ``merkl_api.action.hashing.compute_leaf_hash`` produces for them.
``tests/core/test_action_leaf_identity.py`` feeds those fields to
``merkl.core.leaf.action_leaf`` and demands the same digest, which is how the SDK
proves byte identity without ever importing ``merkl_api``.

Cases are fixed, not random: regenerating must be a no-op.
"""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime
from typing import Any

from merkl_api.action.hashing import compute_leaf_hash
from merkl_api.action.models import ActionRecord, DriftScore

from merkl.shared.enums import ActionStatus, ActionType, GuardrailResult
from merkl.shared.hashing import SHA256Hash, canonical_hash
from merkl.shared.ids import ActionId, AgentId, SessionId
from merkl.shared.timestamps import Timestamp

OUT = pathlib.Path(__file__).with_name("merkl_api_action_leaf_v1.json")

_A = "01936b2e-0000-7000-8000-{:012d}"
_S = "01936b2e-1111-7000-8000-000000000001"


def _case(  # noqa: PLR0913
    n: int,
    *,
    tool_name: str,
    action_type: ActionType = ActionType.TOOL_CALL,
    input_data: Any = "in",
    output_data: Any = "out",
    when: datetime,
    drift: float,
    guardrail: GuardrailResult = GuardrailResult.PASSED,
    display_name: str = "",
    depends_on: list[str] | None = None,
    status: ActionStatus = ActionStatus.SUCCESS,
    category: str = "",
) -> dict[str, Any]:
    record = ActionRecord(
        action_id=ActionId.from_str(_A.format(n)),
        session_id=SessionId.from_str(_S),
        agent_id=AgentId("agent-fixture"),
        timestamp=Timestamp.from_datetime(when),
        action_type=action_type,
        tool_name=tool_name,
        input_hash=canonical_hash(input_data),
        output_hash=canonical_hash(output_data),
        drift_score=DriftScore(drift),
        guardrail_result=guardrail,
        policy_reference="policy-fixture",
        duration_ms=12,
        display_name=display_name,
        depends_on=list(depends_on or []),
        status=status,
        category=category,
        input_preview="preview in",
        output_preview="preview out",
        visibility="hidden",
    )
    leaf: SHA256Hash = compute_leaf_hash(record)
    return {
        "action_id": str(record.action_id),
        "session_id": str(record.session_id),
        "action_type": record.action_type.value,
        "tool_name": record.tool_name,
        "input_hash": record.input_hash.hex(),
        "output_hash": record.output_hash.hex(),
        "timestamp": record.timestamp.datetime.isoformat(),
        "drift_score": record.drift_score.value,
        "drift_score_str": str(record.drift_score.value),
        "guardrail_result": record.guardrail_result.value,
        "display_name": record.display_name,
        "depends_on": list(record.depends_on),
        "status": record.status.value,
        "category": record.category,
        "leaf": leaf.hex(),
    }


def build() -> dict[str, Any]:
    t0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    t_micro = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    cases = [
        _case(1, tool_name="query_db", when=t0, drift=0.0),
        _case(2, tool_name="query_db", when=t_micro, drift=1.0),
        _case(3, tool_name="", when=t0, drift=0.5, category="finance"),
        _case(
            4,
            tool_name="submit_payment",
            action_type=ActionType.TRANSACTION,
            when=t_micro,
            drift=0.123456789,
            guardrail=GuardrailResult.PENDING_APPROVAL,
            display_name="Submit payment",
            depends_on=["zzz", "aaa", "mmm"],
            status=ActionStatus.PENDING,
            category="payments",
        ),
        _case(
            5,
            tool_name="café ☕ — naïve",
            when=t0,
            drift=0.3333333333333333,
            display_name="日本語 display",
            category="unicode",
        ),
        _case(
            6,
            tool_name="blocked_tool",
            when=t0,
            drift=0.9999999999999999,
            guardrail=GuardrailResult.BLOCKED,
            status=ActionStatus.BLOCKED,
        ),
        _case(
            7,
            tool_name="human",
            action_type=ActionType.HUMAN_INPUT,
            input_data={"b": 1, "a": [1, 2, {"z": None}]},
            output_data=None,
            when=t_micro,
            drift=0.1,
            guardrail=GuardrailResult.NOT_EVALUATED,
            depends_on=["01936b2e-0000-7000-8000-000000000001"],
        ),
        _case(
            8,
            tool_name="reasoning",
            action_type=ActionType.REASONING,
            when=t0,
            drift=0.07,
            display_name="",
            depends_on=[],
            status=ActionStatus.FAILED,
            category="",
        ),
        _case(9, tool_name="sub", action_type=ActionType.SUB_AGENT, when=t0, drift=0.25),
        _case(
            10,
            tool_name="transcript",
            action_type=ActionType.TRANSCRIPT,
            when=datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
            drift=0.999,
            category="session",
        ),
        _case(
            11,
            tool_name="api",
            action_type=ActionType.API_REQUEST,
            input_data=["x", 1, True, None],
            output_data={"k": "v"},
            when=t0,
            drift=2 / 3,
            depends_on=["b", "a"],
        ),
        _case(
            12,
            tool_name="data",
            action_type=ActionType.DATA_ACCESS,
            when=t0,
            drift=1e-05,
            category="db",
        ),
    ]
    return {
        "description": (
            "merkl-leaf-v1 action leaves produced by merkl_api.action.hashing."
            "compute_leaf_hash. Regenerate with merkl-api's venv; the SDK's "
            "merkl.core.leaf.action_leaf must reproduce every 'leaf' value."
        ),
        "tag": "merkl-leaf-v1",
        "source": "merkl_api.action.hashing.compute_leaf_hash",
        "cases": cases,
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")
