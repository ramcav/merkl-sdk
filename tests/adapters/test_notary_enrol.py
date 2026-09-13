"""``EnrolClient`` — the two bodies, pinned against ``P17-CONTRACT.md``.

Three engineers built this route from one contract at the same time, so the
member names are the interface and a test that only checks "it posted something"
would let a rename through. Every assertion here is a line of that table.

The fake notary is an ``httpx.MockTransport``: a real client, real JSON, real
status codes, no socket.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from merkl.adapters.notary import (
    AgentRecord,
    EnrolClient,
    Enrolment,
    NotaryEnrolError,
    NotaryRecord,
)

ENROLMENT_TOKEN = "enr_" + "a" * 43
SIGNER_TOKEN = "sgn_" + "b" * 43
TREASURY = "rTREASURY0000000000000000000000000"
AGENTS = (
    AgentRecord(id="agent-0", public_key="ab" * 32, address="rAGENT00000000000000000000000000000"),
)

ANSWER = {
    "signer_id": "sig_01",
    "org_slug": "acme",
    "treasury_url": "https://app.merkl.ai/acme/treasuries/" + TREASURY,
    "signer_token": SIGNER_TOKEN,
    "notary_api_key": "mk_live_notarealkey",
}


class Recorder:
    """Every request the client made, so a test can read the body back."""

    def __init__(self, answer: Any = None, status: int = 200) -> None:
        self.requests: list[httpx.Request] = []
        self._answer = ANSWER if answer is None else answer
        self._status = status

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status, json=self._answer)

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[index].content)

    def bearer(self, index: int = 0) -> str:
        return self.requests[index].headers["Authorization"]


class TestEnrol:
    def test_the_body_is_exactly_what_the_contract_names(self) -> None:
        recorder = Recorder()
        client = EnrolClient("https://api.merkl.ai", transport=recorder.transport)

        client.enrol(
            ENROLMENT_TOKEN,
            treasury=TREASURY,
            network="xrpl-mainnet",
            signer_public_key="cd" * 32,
            agents=AGENTS,
            required_drops="2100000",
        )

        assert str(recorder.requests[0].url) == "https://api.merkl.ai/v1/signers/enrol"
        assert recorder.body() == {
            "treasury": TREASURY,
            "network": "xrpl-mainnet",
            "signer_public_key": "cd" * 32,
            "agents": [
                {
                    "id": "agent-0",
                    "public_key": "ab" * 32,
                    "address": "rAGENT00000000000000000000000000000",
                }
            ],
            "required_drops": "2100000",
        }

    def test_the_enrolment_token_is_the_bearer(self) -> None:
        recorder = Recorder()
        EnrolClient("https://api.merkl.ai", transport=recorder.transport).enrol(
            ENROLMENT_TOKEN,
            treasury=TREASURY,
            network="xrpl-testnet",
            signer_public_key="cd" * 32,
            agents=AGENTS,
            required_drops="0",
        )
        assert recorder.bearer() == f"Bearer {ENROLMENT_TOKEN}"

    def test_the_answer_becomes_an_enrolment(self) -> None:
        recorder = Recorder()
        enrolment = EnrolClient("https://api.merkl.ai", transport=recorder.transport).enrol(
            ENROLMENT_TOKEN,
            treasury=TREASURY,
            network="xrpl-testnet",
            signer_public_key="cd" * 32,
            agents=AGENTS,
            required_drops="0",
        )
        assert enrolment == Enrolment(**ANSWER)

    def test_a_trailing_slash_on_the_notary_url_does_not_double_up(self) -> None:
        recorder = Recorder()
        EnrolClient("https://api.merkl.ai/", transport=recorder.transport).enrol(
            ENROLMENT_TOKEN,
            treasury=TREASURY,
            network="xrpl-testnet",
            signer_public_key="cd" * 32,
            agents=AGENTS,
            required_drops="0",
        )
        assert str(recorder.requests[0].url) == "https://api.merkl.ai/v1/signers/enrol"

    def test_an_answer_missing_the_signer_token_is_refused(self) -> None:
        recorder = Recorder(answer={**ANSWER, "signer_token": ""})
        with pytest.raises(NotaryEnrolError, match="signer_token"):
            EnrolClient("https://api.merkl.ai", transport=recorder.transport).enrol(
                ENROLMENT_TOKEN,
                treasury=TREASURY,
                network="xrpl-testnet",
                signer_public_key="cd" * 32,
                agents=AGENTS,
                required_drops="0",
            )

    def test_a_refusal_names_the_status_and_never_the_request(self) -> None:
        recorder = Recorder(answer={"detail": "that token was already spent"}, status=409)
        with pytest.raises(NotaryEnrolError) as caught:
            EnrolClient("https://api.merkl.ai", transport=recorder.transport).enrol(
                ENROLMENT_TOKEN,
                treasury=TREASURY,
                network="xrpl-testnet",
                signer_public_key="cd" * 32,
                agents=AGENTS,
                required_drops="0",
            )
        assert "409" in str(caught.value)
        assert "already spent" in str(caught.value)
        assert ENROLMENT_TOKEN not in str(caught.value)


class TestReady:
    def test_the_body_is_exactly_what_the_contract_names(self) -> None:
        recorder = Recorder(answer={"signer_id": "sig_01", "status": "ready"})
        client = EnrolClient("https://api.merkl.ai", transport=recorder.transport)

        client.ready(
            SIGNER_TOKEN,
            signer_list_tx="A" * 64,
            disable_master_tx="B" * 64,
            trust_lines=[{"currency": "RLUSD", "issuer": "rISSUER"}],
            relay_token="notary:secret",
            agent_bundle={"trader.toml": "[agent]\n"},
        )

        assert str(recorder.requests[0].url) == "https://api.merkl.ai/v1/signers/ready"
        assert recorder.bearer() == f"Bearer {SIGNER_TOKEN}"
        assert recorder.body() == {
            "signer_list_tx": "A" * 64,
            "disable_master_tx": "B" * 64,
            "trust_lines": [{"currency": "RLUSD", "issuer": "rISSUER"}],
            "relay_token": "notary:secret",
            "agent_bundle": {"files": {"trader.toml": "[agent]\n"}},
        }

    def test_a_self_hosted_signer_sends_null_for_both_managed_members(self) -> None:
        """No bundle to hand over and no relay token to push with: nulls, not absences."""
        recorder = Recorder(answer={"status": "ready"})
        EnrolClient("https://api.merkl.ai", transport=recorder.transport).ready(
            SIGNER_TOKEN, signer_list_tx="A" * 64, disable_master_tx="B" * 64
        )
        body = recorder.body()
        assert body["relay_token"] is None
        assert body["agent_bundle"] is None
        assert body["trust_lines"] == []


class TestNotaryRecord:
    def test_it_round_trips_through_a_0600_file(self, tmp_path: Path) -> None:
        record = NotaryRecord(
            url="https://api.merkl.ai",
            signer_id="sig_01",
            signer_token=SIGNER_TOKEN,
            org_slug="acme",
            treasury_url="https://app.merkl.ai/acme/treasuries/" + TREASURY,
            network="xrpl-testnet",
        )
        path = tmp_path / "notary.json"
        record.write(path)

        assert path.stat().st_mode & 0o777 == 0o600, "it holds a bearer token"
        assert NotaryRecord.read(path) == record

    def test_an_absent_file_means_this_signer_follows_nobody(self, tmp_path: Path) -> None:
        assert NotaryRecord.read(tmp_path / "notary.json") is None

    def test_the_network_is_optional_and_omitted_when_unknown(self, tmp_path: Path) -> None:
        record = NotaryRecord(
            url="https://api.merkl.ai",
            signer_id="sig_01",
            signer_token=SIGNER_TOKEN,
            org_slug="acme",
            treasury_url="https://app.merkl.ai/acme/treasuries/x",
        )
        assert "network" not in record.to_content()
        path = tmp_path / "notary.json"
        record.write(path)
        assert NotaryRecord.read(path) == record

    def test_a_file_missing_the_token_is_refused_rather_than_half_read(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "notary.json"
        path.write_text(json.dumps({"url": "https://api.merkl.ai", "signer_id": "sig_01"}))
        with pytest.raises(NotaryEnrolError, match="signer_token"):
            NotaryRecord.read(path)
