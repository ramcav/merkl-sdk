"""The vsock framing, driven over a socketpair.

``AF_VSOCK`` needs a hypervisor. The framing does not, and the framing is where
the bugs live: a length prefix a reader trusts, a partial read that looks like a
close, a message shape one transport shapes differently from the other. All of
that is exercised here against a real pair of sockets, so the only thing left
untested on this machine is which constant goes into ``socket.socket``.

The point of the last test is the one worth stating: the *same* ``RpcRouter``
answers over vsock and over HTTP, and the answers must be byte-identical.
``docs/SIGNER-RPC.md`` promises one contract; an enclave that answered
differently would make swapping in an attested signer a rewrite instead of a
configuration change.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from merkl.signer.server import PROTOCOL, RpcRouter, handle_request
from merkl.signer.vsock import (
    MAX_FRAME_BYTES,
    VsockError,
    recv_frame,
    send_frame,
    serve_connection,
)
from tests.signer.test_signer import make_engine


def pair() -> tuple[socket.socket, socket.socket]:
    left, right = socket.socketpair()
    left.settimeout(5.0)
    right.settimeout(5.0)
    return left, right


def test_a_frame_round_trips() -> None:
    left, right = pair()
    send_frame(left, b'{"method": "health"}')
    assert recv_frame(right) == b'{"method": "health"}'


def test_two_frames_do_not_run_into_each_other() -> None:
    left, right = pair()
    send_frame(left, b"first")
    send_frame(left, b"second-and-longer")
    assert recv_frame(right) == b"first"
    assert recv_frame(right) == b"second-and-longer"


def test_an_empty_frame_is_a_frame() -> None:
    left, right = pair()
    send_frame(left, b"")
    assert recv_frame(right) == b""


def test_a_clean_close_reads_as_no_frame() -> None:
    left, right = pair()
    left.close()
    assert recv_frame(right) is None


def test_a_close_mid_frame_is_an_error_not_a_shrug() -> None:
    left, right = pair()
    left.sendall((10).to_bytes(4, "big") + b"abc")
    left.close()
    with pytest.raises(VsockError, match="closed after"):
        recv_frame(right)


def test_an_oversized_frame_is_refused_before_it_is_sent() -> None:
    left, _ = pair()
    with pytest.raises(VsockError, match="over the"):
        send_frame(left, b"x" * (MAX_FRAME_BYTES + 1))


def test_an_oversized_announcement_is_refused_before_allocating() -> None:
    """The peer is the untrusted party. A trusted length prefix is a memory bomb."""
    left, right = pair()
    left.sendall((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    with pytest.raises(VsockError, match="over the limit"):
        recv_frame(right)


# --------------------------------------------------------------------------- #
# Serving
# --------------------------------------------------------------------------- #


def serve_in_background(router: RpcRouter, connection: socket.socket) -> threading.Thread:
    thread = threading.Thread(target=serve_connection, args=(router, connection), daemon=True)
    thread.start()
    return thread


def call(client: socket.socket, method: str, params: dict | None = None) -> dict:
    send_frame(client, json.dumps({"method": method, "params": params or {}}).encode())
    frame = recv_frame(client)
    assert frame is not None
    result: dict = json.loads(frame)
    return result


def test_the_enclave_answers_health(tmp_path: Path) -> None:
    engine, _, keystore = make_engine(tmp_path)
    client, server = pair()
    serve_in_background(RpcRouter(engine), server)
    body = call(client, "health")
    assert body["protocol"] == PROTOCOL
    assert body["result"]["status"] == "ok"
    assert body["result"]["signer_public_key"] == keystore.public_key()


def test_a_dev_signer_over_vsock_still_reports_itself_unattested(tmp_path: Path) -> None:
    engine, _, _ = make_engine(tmp_path)
    client, server = pair()
    serve_in_background(RpcRouter(engine), server)
    assert call(client, "attestation")["result"] == {"attestation": None}


def test_many_calls_on_one_connection(tmp_path: Path) -> None:
    engine, _, _ = make_engine(tmp_path)
    client, server = pair()
    serve_in_background(RpcRouter(engine), server)
    for _ in range(5):
        assert call(client, "public_key")["result"]["key_type"] == "ed25519"


@pytest.mark.parametrize(
    "frame,code",
    [
        (b"not json", "signer_error"),
        (b"[1, 2]", "signer_error"),
        (b'{"method": 7}', "signer_error"),
        (b'{"method": "nope", "params": {}}', "signer_error"),
    ],
)
def test_a_bad_request_gets_an_error_and_keeps_the_connection(
    tmp_path: Path, frame: bytes, code: str
) -> None:
    engine, _, _ = make_engine(tmp_path)
    client, server = pair()
    serve_in_background(RpcRouter(engine), server)
    send_frame(client, frame)
    body_bytes = recv_frame(client)
    assert body_bytes is not None
    body = json.loads(body_bytes)
    assert body["error"]["code"] == code
    assert call(client, "health")["result"]["status"] == "ok"


def test_the_server_stops_when_the_peer_goes_away(tmp_path: Path) -> None:
    engine, _, _ = make_engine(tmp_path)
    client, server = pair()
    thread = serve_in_background(RpcRouter(engine), server)
    client.close()
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_vsock_and_http_answer_identically(tmp_path: Path) -> None:
    """One contract, two transports. The reason phase 3 is a swap, not a rewrite."""
    engine, _, _ = make_engine(tmp_path)
    router = RpcRouter(engine)
    client, server = pair()
    serve_in_background(router, server)
    for method in ("health", "public_key", "attestation"):
        over_vsock = call(client, method)
        _, over_http = handle_request(router, method, {}, None)
        assert over_vsock == {"protocol": PROTOCOL, **over_http}
