"""The forwarder in the signer image: bytes in, the same bytes out, nothing read.

The signer's bind guard is the thing being protected here. It refuses anything
but loopback or a Unix socket, and these tests are what let it keep refusing
inside a container: the process on ``0.0.0.0`` is this one, and what it does is
so small that putting it there is not a decision anybody has to trust.
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
from collections.abc import AsyncIterator, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio

from merkl.signer.forward import (
    DEFAULT_LISTEN,
    LISTEN_ENV,
    UPSTREAM_ENV,
    build_forwarder,
    main,
    split_host_port,
)

pytestmark = pytest.mark.asyncio

LOCAL = "127.0.0.1"


def port_of(server: asyncio.Server) -> int:
    address: Any = server.sockets[0].getsockname()
    return int(address[1])


async def connect(server: asyncio.Server) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(LOCAL, port_of(server))


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    """Short enough for an AF_UNIX path; pytest's own tmp_path is not, on macOS."""
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


class TestAddresses:
    """``split_host_port`` — the one thing the forwarder parses, and it is not payload."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("0.0.0.0:8787", ("0.0.0.0", 8787)),
            ("127.0.0.1:1", ("127.0.0.1", 1)),
            (" 0.0.0.0:8787 ", ("0.0.0.0", 8787)),
            (":8787", ("0.0.0.0", 8787)),
            ("[::]:8787", ("::", 8787)),
            ("[::1]:8787", ("::1", 8787)),
            ("signer:8787", ("signer", 8787)),
        ],
    )
    async def test_it_reads_an_address(self, value: str, expected: tuple[str, int]) -> None:
        assert split_host_port(value) == expected

    @pytest.mark.parametrize("value", ["8787", "0.0.0.0", "0.0.0.0:http", "0.0.0.0:99999", "[::]"])
    async def test_it_refuses_what_is_not_one(self, value: str) -> None:
        with pytest.raises(ValueError, match="port|address"):
            split_host_port(value)

    async def test_the_default_is_every_address_on_the_published_port(self) -> None:
        assert split_host_port(DEFAULT_LISTEN) == ("0.0.0.0", 8787)


@pytest.fixture
def http_upstream() -> Iterator[str]:
    """A loopback HTTP server, standing in for ``merkl signer serve --host 127.0.0.1``."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            self._answer(f"GET {self.path}".encode())

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._answer(b"POST " + body)

        def _answer(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib naming
            pass

    server = ThreadingHTTPServer((LOCAL, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{LOCAL}:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class TestHttpRoundTrip:
    async def test_a_request_and_its_answer_survive_the_hop(self, http_upstream: str) -> None:
        server = await build_forwarder(f"{LOCAL}:0", http_upstream)
        async with server:
            base = f"http://{LOCAL}:{port_of(server)}"
            got = await asyncio.to_thread(httpx.get, f"{base}/health")
            assert got.status_code == 200
            assert got.content == b"GET /health"

    async def test_a_body_goes_up_and_comes_back_unchanged(self, http_upstream: str) -> None:
        server = await build_forwarder(f"{LOCAL}:0", http_upstream)
        payload = b'{"method":"health","params":{}}'
        async with server:
            base = f"http://{LOCAL}:{port_of(server)}"
            got = await asyncio.to_thread(httpx.post, base, content=payload)
            assert got.content == b"POST " + payload

    async def test_one_forwarder_serves_request_after_request(self, http_upstream: str) -> None:
        """Nothing accumulates: a connection ending is a connection released."""
        server = await build_forwarder(f"{LOCAL}:0", http_upstream)
        async with server:
            base = f"http://{LOCAL}:{port_of(server)}"
            for index in range(5):
                got = await asyncio.to_thread(httpx.get, f"{base}/{index}")
                assert got.content == f"GET /{index}".encode()

    async def test_it_forwards_to_a_unix_socket_too(self, socket_dir: Path) -> None:
        """The shape the image actually uses: the signer owns a 0600 socket."""
        socket_path = socket_dir / "signer.sock"

        async def echo_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_unix_server(echo_http, str(socket_path))
        async with upstream:
            server = await build_forwarder(f"{LOCAL}:0", str(socket_path))
            async with server:
                got = await asyncio.to_thread(
                    httpx.get, f"http://{LOCAL}:{port_of(server)}/health"
                )
                assert got.status_code == 200
                assert got.text == "ok"


@pytest_asyncio.fixture
async def echo() -> AsyncIterator[tuple[str, list[bytes]]]:
    """An upstream that reflects every byte, and records what it was sent."""
    seen: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            seen.append(chunk)
            writer.write(chunk)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, LOCAL, 0)
    async with server:
        yield f"{LOCAL}:{port_of(server)}", seen


class TestItRefusesNothing:
    """Not a filter, not a parser: anything the client sends reaches the signer."""

    async def test_bytes_that_are_not_http_pass_through_verbatim(
        self, echo: tuple[str, list[bytes]]
    ) -> None:
        upstream, seen = echo
        raw = bytes(range(256)) + b"\x00\r\n\r\nnot a request at all\xff"
        server = await build_forwarder(f"{LOCAL}:0", upstream)
        async with server:
            reader, writer = await connect(server)
            writer.write(raw)
            await writer.drain()
            assert await reader.readexactly(len(raw)) == raw
            writer.close()
            await writer.wait_closed()
        assert b"".join(seen) == raw

    async def test_a_body_larger_than_one_chunk_is_not_truncated(
        self, echo: tuple[str, list[bytes]]
    ) -> None:
        upstream, _ = echo
        raw = bytes(range(256)) * 4096  # 1 MiB, many reads
        server = await build_forwarder(f"{LOCAL}:0", upstream)
        async with server:
            reader, writer = await connect(server)
            writer.write(raw)
            await writer.drain()
            assert await reader.readexactly(len(raw)) == raw
            writer.close()
            await writer.wait_closed()

    async def test_an_unauthenticated_call_is_the_signers_to_refuse(
        self, http_upstream: str
    ) -> None:
        """No 401 of its own: the answer the caller gets is the signer's answer."""
        server = await build_forwarder(f"{LOCAL}:0", http_upstream)
        async with server:
            got = await asyncio.to_thread(
                httpx.get,
                f"http://{LOCAL}:{port_of(server)}/health",
                headers={"Authorization": "Bearer nonsense"},
            )
            assert got.status_code == 200
            assert got.content == b"GET /health"


class TestClosing:
    async def test_the_upstream_closing_closes_the_client(self) -> None:
        async def greet_then_close(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.write(b"hello")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(greet_then_close, LOCAL, 0)
        async with upstream:
            server = await build_forwarder(f"{LOCAL}:0", f"{LOCAL}:{port_of(upstream)}")
            async with server:
                reader, writer = await connect(server)
                assert await asyncio.wait_for(reader.read(), timeout=5) == b"hello"
                assert reader.at_eof()
                writer.close()
                await writer.wait_closed()

    async def test_the_client_closing_closes_the_upstream(self) -> None:
        ended = asyncio.Event()

        async def wait_for_eof(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read()
            ended.set()
            writer.close()

        upstream = await asyncio.start_server(wait_for_eof, LOCAL, 0)
        async with upstream:
            server = await build_forwarder(f"{LOCAL}:0", f"{LOCAL}:{port_of(upstream)}")
            async with server:
                _, writer = await connect(server)
                writer.write(b"a request nobody answers")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                await asyncio.wait_for(ended.wait(), timeout=5)

    async def test_an_upstream_that_is_not_there_drops_the_connection(
        self, socket_dir: Path
    ) -> None:
        """Exactly what talking to the signer directly would give, and it keeps serving."""
        server = await build_forwarder(f"{LOCAL}:0", str(socket_dir / "nothing-here.sock"))
        async with server:
            reader, writer = await connect(server)
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
            writer.close()
            await writer.wait_closed()
            second, second_writer = await connect(server)
            assert await asyncio.wait_for(second.read(), timeout=5) == b""
            second_writer.close()
            await second_writer.wait_closed()


class TestMain:
    async def test_the_listen_address_defaults_to_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(LISTEN_ENV, "not-an-address")
        monkeypatch.setenv(UPSTREAM_ENV, "/nowhere.sock")
        with pytest.raises(SystemExit) as caught:
            main([])
        assert caught.value.code == 2

    async def test_a_listen_address_that_is_not_one_is_refused_before_binding(self) -> None:
        with pytest.raises(SystemExit) as caught:
            main(["--listen", "0.0.0.0", "--upstream", "/nowhere.sock"])
        assert caught.value.code == 2
