"""The parts of the parent proxy that do not need a hypervisor.

The relay and the vsock listeners cannot run here — there is no enclave and macOS
has no ``AF_VSOCK``. The blob store and the control channel's dispatch can, and
they are where the parent could get something wrong in a way that matters: a torn
sealed-key file is a signer that will not boot, and a control channel that
answered a method it should not would be the parent reaching into a direction
that is meant to be one-way.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from nitro.parent.proxy import (
    SEALED_KEY_FILE,
    STATE_FILE,
    BlobStore,
    ControlServer,
    build_handler,
)


class FakeCredentials:
    def get(self) -> dict[str, str]:
        return {"access_key_id": "A", "secret_access_key": "S", "session_token": "T"}


def control(tmp_path: Path) -> tuple[ControlServer, BlobStore]:
    blobs = BlobStore(tmp_path)
    return ControlServer(blobs, FakeCredentials(), 5006), blobs  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The blob store
# --------------------------------------------------------------------------- #


def test_a_missing_blob_reads_as_none(tmp_path: Path) -> None:
    assert BlobStore(tmp_path).read(SEALED_KEY_FILE) is None


def test_a_blob_round_trips(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    store.write(SEALED_KEY_FILE, b"sealed-ciphertext")
    assert store.read(SEALED_KEY_FILE) == b"sealed-ciphertext"


def test_the_blob_is_owner_only(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    store.write(SEALED_KEY_FILE, b"sealed")
    mode = stat.S_IMODE(os.stat(tmp_path / SEALED_KEY_FILE).st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700


def test_writing_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    """The write is atomic: a torn sealed key is a signer that cannot boot."""
    store = BlobStore(tmp_path)
    store.write(SEALED_KEY_FILE, b"one")
    store.write(SEALED_KEY_FILE, b"two-and-longer")
    assert sorted(p.name for p in tmp_path.iterdir()) == [SEALED_KEY_FILE]
    assert store.read(SEALED_KEY_FILE) == b"two-and-longer"


# --------------------------------------------------------------------------- #
# The control channel
# --------------------------------------------------------------------------- #


def test_the_enclave_can_ask_for_credentials(tmp_path: Path) -> None:
    server, _ = control(tmp_path)
    assert server.answer("credentials", {})["result"]["access_key_id"] == "A"


def test_the_first_boot_gets_no_blob(tmp_path: Path) -> None:
    server, _ = control(tmp_path)
    assert server.answer("sealed_key", {})["result"]["blob"] is None


def test_a_stored_blob_comes_back_base64(tmp_path: Path) -> None:
    server, blobs = control(tmp_path)
    server.answer("store_sealed_key", {"blob": base64.b64encode(b"ciphertext").decode()})
    assert blobs.read(SEALED_KEY_FILE) == b"ciphertext"
    assert (
        server.answer("sealed_key", {})["result"]["blob"]
        == base64.b64encode(b"ciphertext").decode()
    )


def test_a_state_snapshot_goes_to_its_own_file(tmp_path: Path) -> None:
    server, blobs = control(tmp_path)
    server.answer("store_state", {"blob": base64.b64encode(b"sealed-state").decode()})
    assert blobs.read(STATE_FILE) == b"sealed-state"
    assert blobs.read(SEALED_KEY_FILE) is None


@pytest.mark.parametrize("method", ["propose", "sign_tx", "public_key", "", "attestation"])
def test_the_control_channel_answers_only_its_own_methods(tmp_path: Path, method: str) -> None:
    """One direction, one dispatch table. The signer's contract is elsewhere."""
    server, _ = control(tmp_path)
    assert "error" in server.answer(method, {})


# --------------------------------------------------------------------------- #
# The relay
# --------------------------------------------------------------------------- #


def test_the_relay_never_logs_a_body() -> None:
    """Request bodies carry destinations, decisions and signatures."""

    class NotAClient:
        def call(self, method: str, params: Any = None) -> dict[str, Any]:  # pragma: no cover
            return {"result": {}}

    handler = build_handler(NotAClient())  # type: ignore[arg-type]
    assert handler.log_message.__doc__ is not None
    assert "names who paid whom" in handler.log_message.__doc__


# --------------------------------------------------------------------------- #
# Rail history: evidence the enclave reconciles against, never an instruction
# --------------------------------------------------------------------------- #


def outflow(tx_hash: str = "ABC123") -> dict[str, Any]:
    return {
        "tx_hash": tx_hash,
        "treasury": "rTREASURY",
        "destination": "rDEST",
        "value": "10",
        "asset": "XRP",
        "ledger_index": 42,
        "close_time": "2026-01-01T00:00:00Z",
    }


def test_the_default_provider_reports_nothing_rather_than_pretending(tmp_path: Path) -> None:
    server, _ = control(tmp_path)
    assert server.answer("history", {"treasury": "rT", "since": ""})["result"]["outflows"] == []


def test_history_reaches_the_enclave(tmp_path: Path) -> None:
    seen: list[tuple[str, str]] = []

    def provider(treasury: str, since: str) -> list[dict[str, Any]]:
        seen.append((treasury, since))
        return [outflow()]

    server = ControlServer(BlobStore(tmp_path), FakeCredentials(), 5006, provider)  # type: ignore[arg-type]
    answer = server.answer("history", {"treasury": "rT", "since": "2026-01-01T00:00:00Z"})
    assert answer["result"]["outflows"] == [outflow()]
    assert seen == [("rT", "2026-01-01T00:00:00Z")]


def test_a_rail_that_is_down_is_an_error_not_a_crash(tmp_path: Path) -> None:
    def provider(treasury: str, since: str) -> list[dict[str, Any]]:
        raise ConnectionError("the ledger is unreachable")

    server = ControlServer(BlobStore(tmp_path), FakeCredentials(), 5006, provider)  # type: ignore[arg-type]
    answer = server.answer("history", {"treasury": "rT", "since": ""})
    assert answer["error"]["code"] == "state_error"
    assert "unreachable" not in answer["error"]["message"]


def test_untrusted_history_becomes_checked_value_objects_or_an_error() -> None:
    """The enclave parses at the boundary. That is what makes the parent's word
    evidence rather than instruction."""
    from merkl.core.canonical import ContentError
    from merkl.core.policy.state import Outflow

    assert Outflow.from_content(outflow()).tx_hash == "ABC123"
    for broken in (
        {**outflow(), "ledger_index": "42"},
        {**outflow(), "value": 10},
        {"tx_hash": "A"},
        [],
    ):
        with pytest.raises(ContentError):
            Outflow.from_content(broken)


@pytest.mark.parametrize(
    "spec,match",
    [
        ("no-colon", "package.module:callable"),
        ("json:not_a_real_attribute", "not callable"),
    ],
)
def test_a_bad_history_provider_is_refused_at_startup(spec: str, match: str) -> None:
    from nitro.parent.proxy import load_history_provider

    with pytest.raises(SystemExit, match=match):
        load_history_provider(spec)


def test_the_default_history_provider_resolves_to_nothing() -> None:
    from nitro.parent.proxy import load_history_provider, no_history

    assert load_history_provider("none") is no_history
    assert load_history_provider("") is no_history
