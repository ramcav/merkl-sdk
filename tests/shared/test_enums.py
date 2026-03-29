"""Tests for all domain enums."""

from __future__ import annotations

import pytest

from merkl.shared.enums import (
    ActionStatus,
    ActionType,
    GuardrailResult,
    ProvenanceLevel,
    SessionStatus,
)


class TestActionStatus:
    def test_action_status_members(self) -> None:
        expected = {"SUCCESS", "FAILED", "BLOCKED", "PENDING"}
        actual = {m.name for m in ActionStatus}
        assert actual == expected

    def test_action_status_values(self) -> None:
        assert ActionStatus("success") == ActionStatus.SUCCESS
        assert ActionStatus("failed") == ActionStatus.FAILED
        assert ActionStatus("blocked") == ActionStatus.BLOCKED
        assert ActionStatus("pending") == ActionStatus.PENDING

    def test_action_status_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            ActionStatus("bogus")



class TestActionType:
    def test_action_type_members(self) -> None:
        expected = {
            "TOOL_CALL", "DATA_ACCESS", "API_REQUEST", "TRANSACTION",
            "APPROVAL_REQUEST", "REASONING", "SUB_AGENT", "HUMAN_INPUT",
        }
        actual = {m.name for m in ActionType}
        assert actual == expected

    def test_new_action_types(self) -> None:
        assert ActionType("reasoning") == ActionType.REASONING
        assert ActionType("sub_agent") == ActionType.SUB_AGENT
        assert ActionType("human_input") == ActionType.HUMAN_INPUT

    def test_old_action_types_preserved(self) -> None:
        assert ActionType("tool_call") == ActionType.TOOL_CALL
        assert ActionType("data_access") == ActionType.DATA_ACCESS

    def test_action_type_is_string_serializable(self) -> None:
        assert isinstance(ActionType.TOOL_CALL, str)


class TestGuardrailResult:
    def test_guardrail_result_members(self) -> None:
        expected = {"PASSED", "BLOCKED", "PENDING_APPROVAL", "NOT_EVALUATED"}
        actual = {m.name for m in GuardrailResult}
        assert actual == expected


class TestSessionStatus:
    def test_session_status_members(self) -> None:
        expected = {"OPEN", "CLOSED", "ABORTED", "EXPIRED"}
        actual = {m.name for m in SessionStatus}
        assert actual == expected


class TestProvenanceLevel:
    def test_provenance_level_members(self) -> None:
        expected = {
            "SYSTEM",
            "USER",
            "INTERNAL",
            "EXTERNAL_VERIFIED",
            "EXTERNAL_UNVERIFIED",
            "UNTRUSTED",
        }
        actual = {m.name for m in ProvenanceLevel}
        assert actual == expected
