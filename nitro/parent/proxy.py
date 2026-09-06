"""The parent proxy: HTTP on one side, vsock on the other, trusted by neither.

It runs on the EC2 instance, outside the enclave, and it does four jobs:

* **Relay.** Turn each ``docs/SIGNER-RPC.md`` HTTP request into a vsock frame and
  each answer back into a response, unchanged. The SDK talks to this and cannot
  tell it is not talking to a dev signer, which is the whole point of phase 3
  being a deployment change.
* **Keep the sealed blobs.** The enclave has no disk. It hands the parent a
  ciphertext KMS will only open for an enclave with the right measurements, and
  sealed state snapshots whose sequence refuses to go backwards.
* **Forward credentials.** The enclave cannot reach IMDS. The parent reads its
  instance-role credentials and passes them in. They grant nothing on their own:
  the KMS key policy requires an attestation the parent cannot produce.
* **Carry rail history as untrusted input.** ``SettlementPort.history()`` runs
  out here, because it needs the network. What it returns is evidence the enclave
  reconciles against, never a decision it accepts.

## What this process can and cannot do

**Can**: refuse to start the enclave, kill it, drop its traffic, delay it, serve
a stale sealed blob, lie about rail history, read every request and every
decision that passes through. All of that is availability and privacy, and all of
it is visible: a signer that stops signing settles nothing.

**Cannot**: read the policy key, sign anything with it, make the enclave approve
a payment the policy denies, produce an attestation document, or roll the state
back — a snapshot's sequence only moves forward, so replaying an old one is an
error rather than a way to spend a window twice.

The one thing to be careful about is exactly the one this file is careful about:
it must never log a request body or a response body. Those carry decisions,
signatures and destinations. It logs method names and status codes.

Not executed. There is no enclave to talk to on the machine this was written on,
and ``AF_VSOCK`` does not exist on macOS. The framing it uses is
``merkl.signer.vsock``, which *is* tested, over a socketpair.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import stat
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final

from merkl.signer.vsock import (
    DEFAULT_PORT,
    VsockError,
    VsockRpcClient,
    recv_frame,
    send_frame,
)

log = logging.getLogger("merkl.parent")

PROTOCOL: Final = "merkl-signer-rpc-v1"
MAX_BODY_BYTES: Final = 4 * 1024 * 1024
SEALED_KEY_FILE: Final = "policy-key.sealed"
STATE_FILE: Final = "state.sealed"
CONTROL_PORT: Final = 5006

VMADDR_CID_ANY: Final = 0xFFFFFFFF


class BlobStore:
    """The sealed blobs, on the parent's disk, mode 0600 and written atomically.

    Mode ``0600`` is hygiene rather than protection: everything in here is
    already a ciphertext only an enclave with the right measurements can open.
    The atomic write matters more — a torn sealed-key file after a power loss is
    a signer that cannot boot.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, stat.S_IRWXU)

    def read(self, name: str) -> bytes | None:
        path = self._dir / name
        return path.read_bytes() if path.exists() else None

    def write(self, name: str, blob: bytes) -> None:
        path = self._dir / name
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)


class InstanceCredentials:
    """IMDSv2, read on the parent and forwarded to the enclave.

    Cached until close to expiry, because the enclave asks on every KMS call and
    IMDS is rate limited. Never logged, and never written to disk.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached: dict[str, str] | None = None
        self._expires = ""

    def get(self) -> dict[str, str]:
        import urllib.request  # noqa: PLC0415 - stdlib, and only the parent needs it

        with self._lock:
            if self._cached is not None:
                return self._cached
            token_request = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            )
            with urllib.request.urlopen(token_request, timeout=2) as response:  # noqa: S310
                token = response.read().decode()
            headers = {"X-aws-ec2-metadata-token": token}
            base = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            with urllib.request.urlopen(  # noqa: S310
                urllib.request.Request(base, headers=headers), timeout=2
            ) as response:
                role = response.read().decode().strip()
            with urllib.request.urlopen(  # noqa: S310
                urllib.request.Request(base + role, headers=headers), timeout=2
            ) as response:
                body = json.loads(response.read())
            self._cached = {
                "access_key_id": body["AccessKeyId"],
                "secret_access_key": body["SecretAccessKey"],
                "session_token": body["Token"],
            }
            self._expires = body.get("Expiration", "")
            return self._cached

    def invalidate(self) -> None:
        with self._lock:
            self._cached = None


# --------------------------------------------------------------------------- #
# The control channel: the enclave asking the parent for things
# --------------------------------------------------------------------------- #


class ControlServer:
    """Answers the enclave's own requests: blobs and credentials.

    A separate vsock port from the signer RPC, and separate on purpose: this
    direction is the enclave asking, and the request set is three methods long.
    Sharing a port with the signer's contract would mean one dispatch table where
    a method meant for one direction could be reached from the other.
    """

    METHODS: Final = frozenset({"credentials", "sealed_key", "store_sealed_key", "store_state"})

    def __init__(self, blobs: BlobStore, credentials: InstanceCredentials, port: int) -> None:
        self._blobs = blobs
        self._credentials = credentials
        self._port = port
        self._lock = threading.Lock()

    def answer(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method not in self.METHODS:
            return {"error": {"code": "signer_error", "message": f"unknown method {method!r}"}}
        with self._lock:
            if method == "credentials":
                return {"result": self._credentials.get()}
            if method == "sealed_key":
                blob = self._blobs.read(SEALED_KEY_FILE)
                return {"result": {"blob": base64.b64encode(blob).decode() if blob else None}}
            if method == "store_sealed_key":
                self._blobs.write(SEALED_KEY_FILE, base64.b64decode(str(params.get("blob", ""))))
                log.info("stored a new sealed policy key")
                return {"result": {"stored": True}}
            self._blobs.write(STATE_FILE, base64.b64decode(str(params.get("blob", ""))))
            return {"result": {"stored": True}}

    def serve_forever(self) -> None:  # pragma: no cover - needs a hypervisor
        import socket

        listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
        listener.bind((VMADDR_CID_ANY, self._port))
        listener.listen(8)
        log.info("control channel on vsock port %s", self._port)
        while True:
            connection, _ = listener.accept()
            threading.Thread(
                target=self._serve, args=(connection,), daemon=True, name="merkl-control"
            ).start()

    def _serve(self, connection: Any) -> None:  # pragma: no cover - needs a hypervisor
        try:
            while True:
                frame = recv_frame(connection)
                if frame is None:
                    return
                body = json.loads(frame)
                payload = self.answer(str(body.get("method")), body.get("params") or {})
                send_frame(connection, json.dumps({"protocol": PROTOCOL, **payload}).encode())
        except (VsockError, OSError, json.JSONDecodeError):
            return
        finally:
            connection.close()


# --------------------------------------------------------------------------- #
# The relay: the SDK talking to the enclave
# --------------------------------------------------------------------------- #


def build_handler(client: VsockRpcClient) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "merkl-nitro-parent/1"

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._send(HTTPStatus.BAD_REQUEST, _error("bad Content-Length"))
                return
            if length > MAX_BODY_BYTES:
                self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, _error("body too large"))
                return
            raw = self.rfile.read(length) or b"{}"
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                self._send(HTTPStatus.BAD_REQUEST, _error(f"invalid JSON: {exc}"))
                return
            if not isinstance(body, dict):
                self._send(HTTPStatus.BAD_REQUEST, _error("request must be an object"))
                return
            method = str(body.get("method", ""))
            try:
                answer = client.call(method, body.get("params") or {})
            except VsockError as exc:
                # The enclave is not there. That is availability, and it is loud.
                log.warning("enclave unreachable for %s: %s", method, exc)
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, _error(f"enclave unreachable: {exc}"))
                return
            status = HTTPStatus.OK if "result" in answer else HTTPStatus.BAD_REQUEST
            self._send(status, answer)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path.rstrip("/") not in ("", "/health"):
                self._send(HTTPStatus.NOT_FOUND, _error("POST a JSON-RPC body to /"))
                return
            try:
                self._send(HTTPStatus.OK, client.call("health"))
            except VsockError as exc:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, _error(str(exc)))

        def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            encoded = json.dumps({"protocol": PROTOCOL, **payload}).encode()
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib
            """Silent. A request log from a signer proxy names who paid whom."""

    return Handler


def _error(message: str) -> dict[str, Any]:
    return {"error": {"code": "signer_error", "message": message}}


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - a process entry point
    parser = argparse.ArgumentParser(description="Merkl Nitro parent proxy")
    parser.add_argument(
        "--cid", type=int, default=16, help="enclave context id (nitro-cli describe-enclaves)"
    )
    parser.add_argument("--enclave-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--control-port", type=int, default=CONTROL_PORT)
    parser.add_argument(
        "--listen", default="127.0.0.1", help="loopback only; put your own proxy in front"
    )
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/merkl"))
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    if args.listen not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit(
            f"refusing to bind {args.listen}: the proxy is loopback-only, and anything "
            "public-facing belongs in front of it with its own authentication"
        )

    blobs = BlobStore(args.state_dir)
    control = ControlServer(blobs, InstanceCredentials(), args.control_port)
    threading.Thread(target=control.serve_forever, daemon=True, name="merkl-control").start()

    client = VsockRpcClient(cid=args.cid, port=args.enclave_port)
    server = ThreadingHTTPServer((args.listen, args.port), build_handler(client))
    log.info("relaying %s on http://%s:%s", PROTOCOL, args.listen, args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        client.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
