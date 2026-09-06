"""The Nitro signer client: the same contract, plus one question worth asking.

An HTTP server here stands in for the parent proxy. That is not a shortcut — the
parent proxy *is* an HTTP server that turns each request into a vsock frame, and
the whole point of ``docs/SIGNER-RPC.md`` is that the client cannot tell. The
first test is the load-bearing one: the Nitro client adds no method, so anything
the dev client can ask, this one asks identically.

The attestation documents are forged by ``tests/nitro_factory.py`` against a
throwaway root the test pins. Against the package default — the real AWS root —
they fail at the chain check, which is the property that makes them safe to have
in a test suite at all.
"""

from __future__ import annotations

import base64
import datetime
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from merkl.adapters.signer_dev import DevSignerClient
from merkl.adapters.signer_nitro import NitroSignerClient, UnattestedSignerError
from merkl.core.checks import CheckStatus
from merkl.core.verify.attestation import AttestationTrust
from tests.nitro_factory import PRODUCTION_PCRS, fake_attestation, fake_pki

AT = datetime.datetime(2026, 5, 1, 8, 0, tzinfo=datetime.UTC)
PKI = fake_pki(
    valid_from=AT - datetime.timedelta(hours=1), valid_to=AT + datetime.timedelta(hours=2)
)
SIGNER_KEY = "11" * 32
POLICY_HASH = "22" * 32
PINNED = {index: PRODUCTION_PCRS[index].hex() for index in (0, 1, 2, 8)}


def leaf3(
    *, public_key: str = SIGNER_KEY, user_data: str | None = POLICY_HASH
) -> dict[str, str]:
    document = fake_attestation(
        PKI,
        at=AT,
        public_key=bytes.fromhex(public_key),
        user_data=bytes.fromhex(user_data) if user_data else None,
    )
    return {
        "format": "aws-nitro",
        "document": base64.b64encode(document).decode(),
        "policy_public_key": public_key,
    }


class FakeParentProxy(BaseHTTPRequestHandler):
    """Answers the phase-2 contract verbatim, as the real proxy does."""

    attestation: Any = None
    public_key: str = SIGNER_KEY
    seen: list[str] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        method = body.get("method")
        type(self).seen.append(method)
        results: dict[str, Any] = {
            "public_key": {"public_key": type(self).public_key, "key_type": "ed25519"},
            "attestation": {"attestation": type(self).attestation},
            "health": {
                "status": "ok",
                "attested": type(self).attestation is not None,
                "signer_public_key": type(self).public_key,
            },
        }
        payload = json.dumps(
            {"protocol": "merkl-signer-rpc-v1", "result": results.get(method, {})}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib
        pass


@pytest.fixture()
def proxy() -> Iterator[str]:
    FakeParentProxy.attestation = leaf3()
    FakeParentProxy.public_key = SIGNER_KEY
    FakeParentProxy.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeParentProxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()


def trust(**overrides: Any) -> AttestationTrust:
    fields: dict[str, Any] = {"pcrs": PINNED, "root_pem": PKI.root_pem, "max_age_seconds": 300}
    fields.update(overrides)
    return AttestationTrust(**fields)


# --------------------------------------------------------------------------- #
# The contract is unchanged
# --------------------------------------------------------------------------- #


def test_the_nitro_client_adds_no_rpc_method() -> None:
    """Phase 3 is a deployment change. If this fails, it became a protocol change."""
    added = set(vars(NitroSignerClient)) - {"__doc__", "__module__"}
    assert added == {"attestation_report", "assert_attested"}
    assert issubclass(NitroSignerClient, DevSignerClient)


@pytest.mark.asyncio
async def test_it_answers_the_phase_two_methods(proxy: str) -> None:
    async with NitroSignerClient(base_url=proxy) as client:
        assert await client.public_key() == SIGNER_KEY
        health = await client.health()
        assert health["status"] == "ok"
        assert health["attested"] is True


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_approved_enclave_verifies(proxy: str) -> None:
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(
            trust=trust(), now=AT + datetime.timedelta(seconds=10), policy_hash=POLICY_HASH
        )
    assert result.ok and result.complete, [(c.name, c.detail) for c in result.checks]


@pytest.mark.asyncio
async def test_the_policy_hash_is_optional_and_its_absence_is_named(proxy: str) -> None:
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(
            trust=trust(), now=AT + datetime.timedelta(seconds=10)
        )
    user_data = result.get("attestation.user_data")
    assert user_data is not None and user_data.status is CheckStatus.NOT_IMPLEMENTED
    assert result.ok and not result.complete


@pytest.mark.asyncio
async def test_a_dev_signer_is_reported_as_unattested(proxy: str) -> None:
    FakeParentProxy.attestation = None
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(trust=trust(), now=AT)
    assert [c.name for c in result.failures] == ["signer.attested"]
    assert "dev signer" in result.failures[0].detail


@pytest.mark.asyncio
async def test_a_signer_whose_key_disagrees_with_its_own_attestation(proxy: str) -> None:
    """The signer hands over one key and the enclave vouched for another."""
    FakeParentProxy.public_key = "33" * 32
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(
            trust=trust(), now=AT + datetime.timedelta(seconds=10)
        )
    names = [c.name for c in result.failures]
    assert "signer.attested_key_agrees" in names


@pytest.mark.asyncio
async def test_the_real_aws_root_refuses_the_test_pki(proxy: str) -> None:
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(
            trust=AttestationTrust(pcrs=PINNED), now=AT + datetime.timedelta(seconds=10)
        )
    assert "attestation.certificate_chain" in [c.name for c in result.failures]


@pytest.mark.asyncio
async def test_an_unknown_format_is_refused(proxy: str) -> None:
    FakeParentProxy.attestation = {**leaf3(), "format": "sgx-dcap"}
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(trust=trust(), now=AT)
    assert [c.name for c in result.failures] == ["signer.attested"]


@pytest.mark.asyncio
async def test_a_document_that_is_not_base64_is_refused(proxy: str) -> None:
    FakeParentProxy.attestation = {**leaf3(), "document": "not-base64"}
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.attestation_report(trust=trust(), now=AT)
    assert not result.ok


@pytest.mark.asyncio
async def test_assert_attested_raises_naming_every_failure(proxy: str) -> None:
    FakeParentProxy.attestation = leaf3(user_data="44" * 32)
    async with NitroSignerClient(base_url=proxy) as client:
        with pytest.raises(UnattestedSignerError, match="attestation.user_data"):
            await client.assert_attested(
                trust=trust(),
                now=AT + datetime.timedelta(seconds=10),
                policy_hash=POLICY_HASH,
            )


@pytest.mark.asyncio
async def test_assert_attested_does_not_raise_on_an_unasked_check(proxy: str) -> None:
    """A caller who pinned no allowlist gets a report, not an exception."""
    async with NitroSignerClient(base_url=proxy) as client:
        result = await client.assert_attested(
            trust=trust(pcrs={}), now=AT + datetime.timedelta(seconds=10)
        )
    pcrs = result.get("attestation.pcrs")
    assert pcrs is not None and pcrs.status is CheckStatus.NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_a_stale_attestation_is_refused(proxy: str) -> None:
    async with NitroSignerClient(base_url=proxy) as client:
        with pytest.raises(UnattestedSignerError, match="attestation.timestamp"):
            await client.assert_attested(
                trust=trust(), now=AT + datetime.timedelta(hours=1)
            )
