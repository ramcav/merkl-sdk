"""The dev signer's RPC surface: JSON over HTTP, on a Unix socket or localhost.

Stdlib only. A signer is a thing that holds a key and answers a handful of
questions; putting a web framework behind it would add dependencies, a worker
model and a config surface to a process whose whole job is to be small enough to
reason about. ``ThreadingHTTPServer`` with one lock is the honest shape.

The contract is documented in ``docs/SIGNER-RPC.md`` and is the *same* contract
the Nitro parent proxy speaks over vsock in phase 3. One request shape, one
response shape, one method list — the transport underneath is the only
difference, which is what makes ``DevSigner`` and ``NitroSigner`` swappable
rather than similar.

Every mutating call runs under a single lock. Two proposals evaluated
concurrently would each see the window before the other reserved, which is
exactly the race a spending limit exists to prevent.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final

from merkl.core.canonical import ContentError, JSONObject
from merkl.shared.errors import MerklError
from merkl.signer.auth import AuthError
from merkl.signer.engine import SignerEngine, SignerError

MAX_BODY_BYTES: Final = 4 * 1024 * 1024
PROTOCOL: Final = "merkl-signer-rpc-v1"

ERROR_CODES: Final[dict[str, int]] = {
    "signer_auth_error": 401,
    "signer_error": 400,
    "content_error": 400,
    "policy_error": 400,
    "state_error": 409,
    "signer_state_error": 409,
    "keystore_error": 500,
}


class RpcRouter:
    """The method table, and the lock that makes it safe to serve concurrently."""

    def __init__(self, engine: SignerEngine) -> None:
        self._engine = engine
        self._lock = threading.Lock()

    def dispatch(self, method: str, params: JSONObject) -> JSONObject:
        engine = self._engine
        if method == "health":
            return engine.health()
        if method == "public_key":
            return engine.public_key()
        if method == "attestation":
            return {"attestation": engine.attestation()}
        with self._lock:
            if method == "propose":
                return engine.propose(params.get("request", params))
            if method == "approve":
                return engine.approve(
                    _string(params, "challenge"),
                    _array(params, "assertions"),
                    params.get("prepared_tx"),
                )
            if method == "reject":
                return engine.reject(
                    _string(params, "challenge"),
                    _array(params, "assertions"),
                )
            if method == "settle":
                return engine.settle(
                    _string(params, "reservation_id"), _string(params, "settlement_ref")
                )
            if method == "release":
                return engine.release(_string(params, "reservation_id"))
            if method == "policy_update":
                return engine.policy_update(params.get("signed_policy", params))
        raise SignerError(f"unknown method {method!r}")


def _string(params: JSONObject, key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise SignerError(f"{key} must be a string")
    return value


def _array(params: JSONObject, key: str) -> list[Any]:
    value = params.get(key, [])
    if not isinstance(value, list):
        raise SignerError(f"{key} must be an array")
    return value


def handle_request(
    router: RpcRouter, method: str, params: JSONObject, request_id: Any = None
) -> tuple[int, JSONObject]:
    """Dispatch one call and shape the answer, transport-independent.

    The HTTP handler and the vsock server both go through here, so the two
    transports cannot drift into reporting the same failure differently — which
    matters because ``docs/SIGNER-RPC.md`` promises one contract, and a caller
    that has to know whether it is talking to a dev signer or an enclave has
    already lost the property phase 3 exists to add.

    **An error is never a decision.** A refused payment comes back ``200`` with a
    full ``deny`` decision; the errors mapped here mean no decision was reached
    and no receipt exists.
    """
    try:
        result = router.dispatch(method, params)
    except (AuthError, SignerError, ContentError, MerklError) as exc:
        return ERROR_CODES.get(getattr(exc, "error_code", ""), 400), {
            "error": {
                "code": getattr(exc, "error_code", "signer_error"),
                "message": str(exc),
            },
            "id": request_id,
        }
    return int(HTTPStatus.OK), {"result": result, "id": request_id}


class _Handler(BaseHTTPRequestHandler):
    """POST anything, get JSON back. Errors are JSON too, never an HTML page."""

    server_version = "merkl-signer/1"
    router: RpcRouter

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send(HTTPStatus.BAD_REQUEST, {"error": {"message": "bad Content-Length"}})
            return
        if length > MAX_BODY_BYTES:
            self._send(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": {"message": "body too large"}}
            )
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": {"message": f"invalid JSON: {exc}"}})
            return
        if not isinstance(body, dict):
            self._send(HTTPStatus.BAD_REQUEST, {"error": {"message": "request must be an object"}})
            return

        method = body.get("method")
        params = body.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            self._send(
                HTTPStatus.BAD_REQUEST,
                {"error": {"message": "request needs a string method and an object params"}},
            )
            return
        status, payload = handle_request(self.router, method, params, body.get("id"))
        self._send(status, payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        """``GET /health`` so a supervisor can check liveness without a body."""
        if self.path.rstrip("/") in ("", "/health"):
            self._send(HTTPStatus.OK, {"result": self.router.dispatch("health", {})})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": {"message": "POST a JSON-RPC body to /"}})

    def _send(self, status: HTTPStatus | int, payload: JSONObject) -> None:
        body = json.dumps({"protocol": PROTOCOL, **payload}).encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence by default: request logs from a signer leak who paid whom."""

    def address_string(self) -> str:
        """A Unix socket peer has no address, and stdlib assumes it does."""
        address = self.client_address
        return address[0] if isinstance(address, tuple) and address else "local"


class _UnixHTTPServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` over ``AF_UNIX``.

    A Unix socket is the default because file permissions are a real access
    control: ``0600`` means only this user's processes can ask the signer to
    sign, with no listening TCP port for anything else on the host to find.
    """

    address_family = socket.AF_UNIX
    allow_reuse_address = False

    def server_bind(self) -> None:
        path = Path(str(self.server_address))
        if path.exists():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        socketserver.TCPServer.server_bind(self)
        os.chmod(path, 0o600)

    def get_request(self) -> tuple[Any, Any]:
        connection, _ = self.socket.accept()
        return connection, ("local", 0)


def build_server(
    engine: SignerEngine,
    *,
    socket_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Bind a signer server. ``socket_path`` wins; otherwise localhost only.

    Never binds anything but the loopback address by default. A signer reachable
    from the network is a signer whose only protection is the agent key.
    """
    router = RpcRouter(engine)
    handler = type("MerklSignerHandler", (_Handler,), {"router": router})
    if socket_path is not None:
        return _UnixHTTPServer(str(socket_path), handler)  # type: ignore[arg-type]
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SignerError(
            f"refusing to bind the signer to {host!r}; use a Unix socket, or bind loopback "
            "and put your own proxy in front of it"
        )
    return ThreadingHTTPServer((host, port), handler)


def serve(
    engine: SignerEngine,
    *,
    socket_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> None:  # pragma: no cover - the blocking entry point
    """Serve until interrupted. Used by ``merkl signer serve``."""
    server = build_server(engine, socket_path=socket_path, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if socket_path is not None:
            Path(socket_path).unlink(missing_ok=True)
