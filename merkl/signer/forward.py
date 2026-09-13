"""A byte-for-byte TCP forwarder — the proxy the signer's bind guard asks for.

``merkl.signer.server.build_server`` refuses to bind anything but loopback or a
Unix socket, and it is right to: a signer reachable from the network is a signer
whose only protection is the agent key. Its refusal names the way out —
"use a Unix socket, or bind loopback and put your own proxy in front of it" —
and inside a container there is nobody else to be that proxy. ``docker run -p
127.0.0.1:8787:8787`` publishes a port the container must actually be listening
on, and a compose service reached as ``signer:8787`` needs an address other
containers can route to; neither is loopback *inside* the container.

So the image runs two processes: the signer on a Unix socket, and this, on
``0.0.0.0:8787``, moving bytes between them and doing nothing else. The guard
stays exactly as strict as it was — the thing bound to the world is 130 lines
that hold no key, parse no protocol and make no decision, while everything that
does any of those is still reachable only through a socket at mode ``0600``.

**It parses nothing and refuses nothing.** Every byte in either direction is
relayed unread. A forwarder that understood HTTP would be a second
implementation of the RPC surface's rules, drifting from the first; a forwarder
that filtered would be an access control nobody audited, in front of the one
that *is* audited (``docs/SIGNER-RPC.md``, "Who may call what"). Authentication
is the signer's job and stays there — an unauthenticated call reaches the signer
and is refused by the signer, with the signer's own error.

Like everything under ``merkl/signer/`` this writes to no stream at all
(``tests/signer/test_signer_purity.py``): it carries request bodies, which name
destinations and amounts. A connection it cannot serve is dropped, and the
supervisor in ``docker/signer-entrypoint.sh`` is what notices a process is gone.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Awaitable, Callable, Sequence
from typing import Final

LISTEN_ENV: Final = "MERKL_SIGNER_LISTEN"
"""Where the forwarder listens, ``host:port``. The image's published address."""

UPSTREAM_ENV: Final = "MERKL_SIGNER_UPSTREAM"
"""What it forwards to: a Unix socket path, or a ``host:port`` with a colon."""

DEFAULT_LISTEN: Final = "0.0.0.0:8787"
DEFAULT_UPSTREAM: Final = "/run/merkl-signer/signer.sock"
CHUNK_BYTES: Final = 64 * 1024

UNAVAILABLE_BODY: Final = (
    b'{"protocol":"merkl-signer-rpc-v1","error":{"code":"signer_unavailable",'
    b'"message":"the signer behind this address is not accepting connections yet '
    b'\\u2014 it is starting, or it is waiting for its first policy from the notary"},'
    b'"id":null}'
)
"""What a caller gets when there is nothing upstream to forward to.

The alternative was to drop the connection, which is what this did before, and
which is indistinguishable from a container that is not running at all. A signer
following the notary spends its first seconds — or its first hour, if nobody has
published a policy yet — with no socket to forward to, and "connection refused"
is a poor way to say "give the customer time to press Publish".

It is not a parse and it is not a refusal: nothing about the request is read,
this is written on *connect* failure alone, and a request that reaches the signer
is answered by the signer. The forwarder still understands no protocol; it can
only say that there is no protocol behind it."""

UNAVAILABLE_RESPONSE: Final = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(UNAVAILABLE_BODY)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n" + UNAVAILABLE_BODY
)

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


def split_host_port(value: str) -> tuple[str, int]:
    """``"0.0.0.0:8787"`` -> ``("0.0.0.0", 8787)``. ``"[::]:8787"`` works too.

    An empty host means every address, the same thing it means to ``bind``.
    """
    text = value.strip()
    if text.startswith("["):
        host, closed, rest = text[1:].partition("]")
        if not closed or not rest.startswith(":"):
            raise ValueError(f"{value!r} is not a bracketed address of the form [host]:port")
        port_text = rest[1:]
    else:
        host, colon, port_text = text.rpartition(":")
        if not colon:
            raise ValueError(f"{value!r} is not an address of the form host:port")
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"{value!r} does not end in a port number") from None
    if not 0 <= port <= 65535:
        raise ValueError(f"{port} is not a port number")
    return host or "0.0.0.0", port


def _half_close(writer: asyncio.StreamWriter) -> None:
    """Tell the far side this direction is finished, without closing the socket.

    A peer that is still writing gets to finish. Anything the transport dislikes
    about a half-close is not worth reporting: the connection is ending anyway.
    """
    try:
        if writer.can_write_eof():
            writer.write_eof()
    except (OSError, RuntimeError):
        pass


async def _shut(writer: asyncio.StreamWriter) -> None:
    """Close one side and wait for it, tolerating a peer that already went away."""
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, RuntimeError):
        pass


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Move bytes one way until the source ends, then half-close the destination."""
    try:
        while True:
            chunk = await reader.read(CHUNK_BYTES)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except OSError:
        return
    finally:
        _half_close(writer)


async def _open_upstream(upstream: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to the signer: a ``host:port`` if it has a colon, else a socket path."""
    if ":" in upstream:
        host, port = split_host_port(upstream)
        return await asyncio.open_connection(host, port)
    return await asyncio.open_unix_connection(upstream)


def _forward_to(upstream: str) -> Handler:
    """One accepted connection, spliced onto one upstream connection.

    Either side closing ends both. The upstream direction is the one waited on:
    once the signer has finished answering there is nothing left for the client
    to say, and a client that holds its own side open forever must not pin a
    connection to the signer open with it. A client that closes first reaches
    the same place by the other road — its EOF half-closes the upstream, the
    signer closes, and the upstream direction ends.
    """

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_reader, up_writer = await _open_upstream(upstream)
        except OSError:
            # The signer is not up yet, or not there at all. Say so, in the
            # signer's own error shape, rather than dropping the connection: a
            # signer following the notary has no socket until the first policy
            # exists, and a customer who has not pressed Publish yet deserves a
            # sentence rather than "connection refused".
            try:
                writer.write(UNAVAILABLE_RESPONSE)
                await writer.drain()
            except OSError:
                pass
            await _shut(writer)
            return
        outbound = asyncio.create_task(_pump(reader, up_writer))
        try:
            await _pump(up_reader, writer)
        finally:
            outbound.cancel()
            await asyncio.gather(outbound, return_exceptions=True)
            await _shut(up_writer)
            await _shut(writer)

    return handle


async def build_forwarder(listen: str, upstream: str) -> asyncio.Server:
    """Listen on ``listen`` and forward every connection to ``upstream``.

    Returns the server without serving it, so a caller (a test, mostly) can read
    the port back off ``server.sockets`` when it asked for port ``0``.
    """
    host, port = split_host_port(listen)
    return await asyncio.start_server(_forward_to(upstream), host, port)


async def forward_forever(listen: str, upstream: str) -> None:  # pragma: no cover - blocking
    server = await build_forwarder(listen, upstream)
    async with server:
        await server.serve_forever()


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m merkl.signer.forward`` — the image's second process."""
    parser = argparse.ArgumentParser(
        prog="merkl-signer-forward",
        description=(
            "Forward a public address to a signer bound to a Unix socket or loopback. "
            "Relays bytes unread: authentication stays the signer's job."
        ),
    )
    parser.add_argument(
        "--listen",
        default=os.environ.get(LISTEN_ENV) or DEFAULT_LISTEN,
        metavar="HOST:PORT",
        help=f"Address to listen on (default: ${LISTEN_ENV}, else {DEFAULT_LISTEN})",
    )
    parser.add_argument(
        "--upstream",
        default=os.environ.get(UPSTREAM_ENV) or DEFAULT_UPSTREAM,
        metavar="PATH|HOST:PORT",
        help=f"The signer to forward to (default: ${UPSTREAM_ENV}, else {DEFAULT_UPSTREAM})",
    )
    args = parser.parse_args(argv)
    try:
        split_host_port(args.listen)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        asyncio.run(forward_forever(args.listen, args.upstream))
    except KeyboardInterrupt:  # pragma: no cover - a terminal, not a container
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
