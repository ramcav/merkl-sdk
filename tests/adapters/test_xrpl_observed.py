"""The settled-transaction readback helpers must exist and agree on the anchor memo.

Regression: a refactor deleted ``_observed_anchor`` while ``submit`` still called it,
so every real settlement would have raised NameError. Unit tests never reached the
live submit path, so this exercises the helpers on a realistic ``tx`` result.
"""

from __future__ import annotations

import json

from merkl.adapters.xrpl import adapter as xa

COMMITMENT = "ab" * 32


def _result() -> dict:
    agent_memo = json.dumps(
        {"action": "payment", "agent_id": "a1", "session_id": "s1", "task_id": "t1"},
        separators=(",", ":"),
    )
    return {
        "tx_json": {
            "Account": "rDHhMK86oeA7CChheYcBrAD4fKA7xUbjfY",
            "Memos": [
                {
                    "Memo": {
                        "MemoType": xa.MEMO_TYPE.encode().hex().upper(),
                        "MemoData": COMMITMENT.upper(),
                    }
                },
                {
                    "Memo": {
                        "MemoType": xa.MEMO_AGENT_TYPE.encode().hex().upper(),
                        "MemoData": agent_memo.encode().hex().upper(),
                    }
                },
            ],
        }
    }


def test_observed_anchor_reads_the_commitment_memo() -> None:
    assert xa._observed_anchor(_result()) == COMMITMENT


def test_observed_memos_decodes_both_memos_in_order() -> None:
    memos = xa._observed_memos(_result())
    assert memos is not None and len(memos) == 2
    assert memos[0]["type"] == xa.MEMO_TYPE and memos[0]["data"] == COMMITMENT
    assert memos[1]["type"] == xa.MEMO_AGENT_TYPE
    assert memos[1]["data"]["task_id"] == "t1"


def test_observed_anchor_is_none_without_memos() -> None:
    assert xa._observed_anchor({"tx_json": {"Account": "r"}}) is None
    assert xa._observed_memos({"tx_json": {}}) is None
