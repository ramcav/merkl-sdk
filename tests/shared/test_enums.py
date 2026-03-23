"""Tests for all domain enums."""

from __future__ import annotations

from merkl.shared.enums import (
    ActionType,
    GuardrailResult,
    ProvenanceLevel,
    SessionStatus,
)


class TestActionType:
    def test_action_type_members(self) -> None:
        expected = {"TOOL_CALL", "DATA_ACCESS", "API_REQUEST", "TRANSACTION", "APPROVAL_REQUEST"}
        actual = {m.name for m in ActionType}
        assert actual == expected

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
