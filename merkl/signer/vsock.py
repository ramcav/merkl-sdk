"""The same RPC over vsock, which is the only wire an enclave has.

A Nitro Enclave has no network device, no disk and no way to reach anything
except a virtio socket to its parent instance. That is the property the whole
design rests on: the parent can start the enclave, stop it, and refuse to carry
its traffic, and it cannot read what is inside. So the signer's RPC — the same
methods, the same request and response shapes as ``docs/SIGNER-RPC.md`` — has to
travel over a stream socket instead of HTTP.

The framing is four bytes of big-endian length and then JSON. Not HTTP, because
an HTTP server inside the enclave would be a parser in the trusted computing base
earning nothing: there is exactly one peer, exactly one content type, and no
proxies, caches or headers to speak of. Not newline-delimited JSON either, since
a length prefix means the reader never has to scan attacker-supplied bytes to
find where a message ends.

Both halves live here, and both are exercised over ``socket.socketpair()`` in the
tests, so the framing is executed on any machine while ``AF_VSOCK`` itself — the
one part that needs a hypervisor — is a two-line difference in how the socket is
made.

Everything crossing this boundary is untrusted in the direction that matters. The
parent supplies requests, sealed blobs and rail history; the enclave decides. The
enclave supplies decisions, signatures and attestation documents; the parent
stores and relays them. Neither is asked to believe the other's account of
anything the receipt will later have to prove.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any, Final

from merkl.core.canonical import JSONObject
from merkl.shared.errors import MerklError, TransportError
from merkl.signer.server import PROTOCOL, RpcRouter, handle_request

LENGTH_PREFIX: Final = struct.Struct("!I")
MAX_FRAME_BYTES: Final = 4 * 1024 * 1024
"""Same ceiling as the HTTP transport, so one contract means one size limit."""

VMADDR_CID_PARENT: Final = 3
"""The parent instance's context id, as seen from inside an enclave."""

DEFAULT_PORT: Final = 5005


class VsockError(TransportError):
    """The vsock transport failed. Not a decision — no receipt exists."""


def send_frame(connection: socket.socket, payload: bytes) -> None:
    """Length-prefix and write one message."""
    if len(payload) > MAX_FRAME_BYTES:
        raise VsockError(f"frame is {len(payload)} bytes, over the {MAX_FRAME_BYTES} limit")
    connection.sendall(LENGTH_PREFIX.pack(len(payload)) + payload)


def recv_frame(connection: socket.socket) -> bytes | None:
    """Read one message, or ``None`` when the peer closed cleanly.

    The declared length is checked against the cap *before* anything is
    allocated: the peer is the party this design assumes may be hostile, and a
    reader that trusts a length prefix is a reader that can be told to allocate
    four gigabytes.
    """
    header = _read_exactly(connection, LENGTH_PREFIX.size)
    if header is None:
        return None
    (length,) = LENGTH_PREFIX.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise VsockError(f"peer announced a {length}-byte frame, over the limit")
    body = _read_exactly(connection, length)
    if body is None:
        raise VsockError("peer closed in the middle of a frame")
    return body


def _read_exactly(connection: socket.socket, count: int) -> bytes | None:
    """Exactly ``count`` bytes, ``None`` if the peer closed before sending any.

    A close *between* bytes is not the same event as a close before them: the
    first is a truncated message and the second is a peer that finished.
    """
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            if not chunks:
                return None
            raise VsockError(f"peer closed after {count - remaining} of {count} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# Enclave side
# --------------------------------------------------------------------------- #


def serve_connection(router: RpcRouter, connection: socket.socket) -> None:
    """Answer every request on one connection until the peer goes away.

    A malformed frame gets an error response and the connection stays open. The
    parent is not trusted, but it is not an adversary worth hanging up on either:
    a signer that dropped the link on a bad request would be a signer a buggy
    proxy could take offline.
    """
    while True:
        try:
            frame = recv_frame(connection)
        except (VsockError, OSError):
            return
        if frame is None:
            return
        send_frame(connection, json.dumps(_answer(router, frame)).encode())


def _answer(router: RpcRouter, frame: bytes) -> JSONObject:
    try:
        body = json.loads(frame)
    except json.JSONDecodeError as exc:
        return _error("signer_error", f"invalid JSON: {exc}")
    if not isinstance(body, dict):
        return _error("signer_error", "request must be an object")
    method = body.get("method")
    params = body.get("params", {})
    if not isinstance(method, str) or not isinstance(params, dict):
        return _error("signer_error", "request needs a string method and an object params")
    auth = body.get("auth")
    bearer = auth.get("bearer") if isinstance(auth, dict) else None
    try:
        _, payload = handle_request(router, method, params, body.get("id"), bearer=bearer)
    except MerklError as exc:  # pragma: no cover - handle_request maps these
        return _error(getattr(exc, "error_code", "signer_error"), str(exc))
    return {"protocol": PROTOCOL, **payload}


def _error(code: str, message: str) -> JSONObject:
    return {"protocol": PROTOCOL, "error": {"code": code, "message": message}}


class VsockRpcServer:
    """Listen on a vsock port and serve the signer RPC. Enclave side.

    Threaded for the same reason the HTTP server is: one slow caller must not
    stop the others. Mutating methods still serialize, because ``RpcRouter``
    holds the lock — two proposals evaluating at once would each see the spending
    window before the other reserved against it.
    """

    def __init__(self, router: RpcRouter, *, port: int = DEFAULT_PORT, backlog: int = 16) -> None:
        self._router = router
        self._port = port
        self._backlog = backlog
        self._socket = _stream_socket()
        self._stopped = threading.Event()

    @property
    def port(self) -> int:
        """The vsock port this server listens on."""
        return self._port

    def bind(self) -> None:
        self._socket.bind((socket.VMADDR_CID_ANY, self._port))  # type: ignore[attr-defined]
        self._socket.listen(self._backlog)

    def serve_forever(self) -> None:  # pragma: no cover - needs a hypervisor
        self.bind()
        while not self._stopped.is_set():
            connection, _ = self._socket.accept()
            thread = threading.Thread(
                target=self._serve, args=(connection,), daemon=True, name="merkl-vsock"
            )
            thread.start()

    def _serve(self, connection: socket.socket) -> None:  # pragma: no cover
        try:
            serve_connection(self._router, connection)
        finally:
            connection.close()

    def close(self) -> None:
        self._stopped.set()
        self._socket.close()


# --------------------------------------------------------------------------- #
# Parent side
# --------------------------------------------------------------------------- #


class VsockRpcClient:
    """Call the enclave's RPC from the parent. One connection, reconnecting.

    The parent proxy holds one of these and turns HTTP requests into frames. It
    reconnects rather than pooling because an enclave restart is a real event —
    the sealed key blob has to be handed over again — and a client that silently
    reused a dead socket would report a transport error where the operator needs
    to see a restart.
    """

    def __init__(self, *, cid: int = 0, port: int = DEFAULT_PORT, timeout: float = 30.0) -> None:
        self._cid = cid
        self._port = port
        self._timeout = timeout
        self._connection: socket.socket | None = None
        self._lock = threading.Lock()

    def _connect(self) -> socket.socket:
        connection = _stream_socket()
        connection.settimeout(self._timeout)
        try:
            connection.connect((self._cid, self._port))
        except OSError as exc:
            connection.close()
            raise VsockError(
                f"cannot reach the enclave on vsock {self._cid}:{self._port}: {exc}"
            ) from exc
        return connection

    def call(
        self, method: str, params: JSONObject | None = None, *, auth: JSONObject | None = None
    ) -> JSONObject:
        """One request, one response. Reconnects once if the link went away.

        ``auth`` carries the relay credential across vsock, which has no
        headers of its own — ``{"bearer": "<token>"}``, the same shape the
        parent proxy lifts out of the HTTP ``Authorization`` header it received
        and forwards unchanged (``nitro/parent/proxy.py``).
        """
        body: dict[str, Any] = {"method": method, "params": params or {}}
        if auth is not None:
            body["auth"] = auth
        encoded = json.dumps(body).encode()
        with self._lock:
            for attempt in (1, 2):
                if self._connection is None:
                    self._connection = self._connect()
                try:
                    send_frame(self._connection, encoded)
                    frame = recv_frame(self._connection)
                except (OSError, VsockError):
                    self._drop()
                    if attempt == 2:
                        raise
                    continue
                if frame is None:
                    self._drop()
                    if attempt == 2:
                        raise VsockError("the enclave closed the connection")
                    continue
                return _decode_response(frame)
        raise VsockError("unreachable")  # pragma: no cover

    def _drop(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def close(self) -> None:
        with self._lock:
            self._drop()


def _decode_response(frame: bytes) -> JSONObject:
    try:
        body: Any = json.loads(frame)
    except json.JSONDecodeError as exc:
        raise VsockError(f"the enclave sent a non-JSON response: {exc}") from exc
    if not isinstance(body, dict):
        raise VsockError("the enclave sent a response that is not an object")
    return body


def _stream_socket() -> socket.socket:
    """An ``AF_VSOCK`` stream socket, or a clear error on a machine without one."""
    family = getattr(socket, "AF_VSOCK", None)
    if family is None:
        raise VsockError(
            "this kernel has no AF_VSOCK; vsock exists inside a Nitro Enclave and on its "
            "parent instance, and nowhere else"
        )
    return socket.socket(family, socket.SOCK_STREAM)
