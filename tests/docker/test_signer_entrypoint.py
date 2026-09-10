"""``docker/signer-entrypoint.sh`` — the pair it supervises, and what it passes through.

The image's failure in 0.2.0 was that its command asked the signer to bind
``0.0.0.0``, which ``build_server`` refuses, so the container crash-looped on
first boot. The fix is not to soften the guard: it is to run the proxy the guard
names. These tests run the real script against the real ``merkl signer serve``
with the demo policy — no container, because what is being checked is the
supervision and the wiring, and both are the script's.

If either half exits, the container exits with that code. A signer nobody can
reach and a forwarder with nothing behind it are both worthless, and a container
that stays up in either state is a container whose health check lies.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from merkl.demo.rig import build_policy, sign_policy

ENTRYPOINT = Path(__file__).parents[2] / "docker" / "signer-entrypoint.sh"
PASSPHRASE = "entrypoint-test"
DEADLINE = 30.0
SIGNER = "signer serve"
FORWARDER = "merkl.signer.forward"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def children_of(pid: int) -> list[tuple[int, str]]:
    """Every process whose parent is ``pid``, without a psutil dependency."""
    listing = subprocess.run(
        ["ps", "-Ao", "pid=,ppid=,command="], capture_output=True, text=True, check=True
    ).stdout
    found: list[tuple[int, str]] = []
    for line in listing.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) == 3 and fields[1].isdigit() and int(fields[1]) == pid:
            found.append((int(fields[0]), fields[2]))
    return found


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class Pair:
    """One run of the entrypoint, plus what a caller needs to poke at it."""

    def __init__(self, process: subprocess.Popen[str], port: int, socket_path: Path) -> None:
        self.process = process
        self.port = port
        self.socket_path = socket_path
        self._output: str | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def half(self, marker: str) -> int:
        """The pid of one half, by what it is running."""
        matches = [pid for pid, command in children_of(self.process.pid) if marker in command]
        assert len(matches) == 1, f"expected one {marker}, found {matches}"
        return matches[0]

    def wait_until_answering(self) -> None:
        """Wait for the *signer*, not the forwarder.

        The forwarder answers 503 the moment it is up, before the signer has a
        socket — which is the point of it (a signer waiting for its first policy
        from the notary is unreachable for as long as the customer takes to
        press Publish), and which makes "something answered" the wrong readiness
        check.
        """
        until = time.monotonic() + DEADLINE
        while time.monotonic() < until:
            if self.process.poll() is not None:
                pytest.fail(f"the entrypoint exited early: {self.stop()}")
            try:
                response = httpx.get(f"{self.base_url}/health", timeout=2.0)
            except httpx.HTTPError:
                time.sleep(0.2)
                continue
            if response.status_code != 503:
                return
            time.sleep(0.2)
        pytest.fail(f"the signer did not answer on {self.base_url} in {DEADLINE}s: {self.stop()}")

    def wait_for_forwarder(self) -> httpx.Response:
        """Wait for anything at all to answer, 503 included."""
        until = time.monotonic() + DEADLINE
        while time.monotonic() < until:
            try:
                return httpx.get(f"{self.base_url}/health", timeout=2.0)
            except httpx.HTTPError:
                time.sleep(0.2)
        pytest.fail(f"nothing answered on {self.base_url} within {DEADLINE}s: {self.stop()}")

    def wait_for_exit(self) -> int:
        return self.process.wait(timeout=DEADLINE)

    def stop(self) -> str:
        """Kill the whole session, then drain. An orphan would hold the pipe open.

        Idempotent: teardown calls it after a test already has.
        """
        if self._output is None:
            with contextlib.suppress(OSError):
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            self._output = self.process.communicate()[0]
        return self._output


def run_entrypoint(
    home: Path,
    socket_dir: Path,
    *arguments: str,
    listen_port: int | None = None,
    agent_dir: Path | None = None,
) -> Pair:
    port = listen_port if listen_port is not None else free_port()
    socket_path = socket_dir / "signer.sock"
    environment = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "MERKL_SIGNER_PASSPHRASE": PASSPHRASE,
        "MERKL_SIGNER_LISTEN": f"127.0.0.1:{port}",
        "MERKL_SIGNER_SOCKET": str(socket_path),
        "MERKL_HOME": str(home),
        "MERKL_AGENT_DIR": str(agent_dir or home / "no-agent-dir"),
        "HOME": str(home),
    }
    process = subprocess.Popen(
        ["/bin/sh", str(ENTRYPOINT), *arguments],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    return Pair(process, port, socket_path)


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    """Short enough for an AF_UNIX path; pytest's own tmp_path is not, on macOS."""
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    """The demo policy, signed by the demo admin key. None of those keys is a secret."""
    path = tmp_path / "policy.signed.json"
    path.write_text(json.dumps(sign_policy(build_policy()).to_content()))
    return path


@pytest.fixture
def serving(home: Path, socket_dir: Path, policy: Path) -> Iterator[Pair]:
    pair = run_entrypoint(home, socket_dir, "signer", "serve", "--policy", str(policy))
    try:
        pair.wait_until_answering()
        yield pair
    finally:
        pair.stop()


class TestTheServedPair:
    def test_the_public_address_reaches_the_signer(self, serving: Pair) -> None:
        """The whole bug, in one request: a port outside, the signer inside."""
        response = httpx.get(f"{serving.base_url}/health", timeout=5.0)
        assert response.status_code == 200
        body = response.json()
        assert body["protocol"] == "merkl-signer-rpc-v1"
        assert body["result"]["status"] == "ok"

    def test_the_signer_itself_is_on_a_unix_socket(self, serving: Pair) -> None:
        """Not loopback-and-hope: the guard's other answer, so nothing else can reach it."""
        assert serving.socket_path.is_socket()
        assert serving.socket_path.stat().st_mode & 0o777 == 0o600

    def test_an_rpc_call_round_trips_through_the_forwarder(self, serving: Pair) -> None:
        response = httpx.post(serving.base_url, json={"method": "public_key"}, timeout=5.0)
        assert response.status_code == 200
        assert len(response.json()["result"]["public_key"]) == 64

    def test_the_entrypoint_owns_both_halves(self, serving: Pair) -> None:
        assert serving.half(SIGNER) != serving.half(FORWARDER)


class TestSupervision:
    def test_the_forwarder_dying_takes_the_signer_with_it(self, serving: Pair) -> None:
        signer = serving.half(SIGNER)
        os.kill(serving.half(FORWARDER), signal.SIGKILL)
        assert serving.wait_for_exit() != 0
        assert "the forwarder exited with" in serving.stop()
        assert not alive(signer), "the signer was left running with nothing in front of it"

    def test_the_signer_dying_takes_the_forwarder_with_it(self, serving: Pair) -> None:
        forwarder = serving.half(FORWARDER)
        os.kill(serving.half(SIGNER), signal.SIGKILL)
        assert serving.wait_for_exit() != 0
        assert "the signer exited with" in serving.stop()
        assert not alive(forwarder), "the forwarder was left forwarding to nothing"

    def test_a_signer_that_refuses_to_start_stops_the_container_with_its_code(
        self, home: Path, socket_dir: Path, tmp_path: Path
    ) -> None:
        """`serve` exits 2 on an unreadable policy; so must the container."""
        port = free_port()
        pair = run_entrypoint(
            home,
            socket_dir,
            "signer",
            "serve",
            "--policy",
            str(tmp_path / "there-is-no-policy.json"),
            listen_port=port,
        )
        assert pair.wait_for_exit() == 2
        output = pair.stop()
        assert "cannot read the policy" in output
        assert "the signer exited with 2" in output
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))  # and the forwarder is not still holding the port


class TestBootstrap:
    """`signer bootstrap` is served the same way `serve` is: with a forwarder."""

    def test_it_gets_a_forwarder_too(self, home: Path, socket_dir: Path) -> None:
        """Mainnet with no --confirm exits 5 before touching a key or a network.

        The exit code is the point twice over: 5 is `treasury init`'s refusal to
        disable a master key nobody typed the sentence for, and the container
        reporting it at all is the pair path — a subcommand exec'd straight
        through would say nothing about a signer.
        """
        pair = run_entrypoint(home, socket_dir, "signer", "bootstrap", "--xrpl-mainnet")
        assert pair.wait_for_exit() == 5
        output = pair.stop()
        assert "there is nobody here to ask" in output
        assert "the signer exited with 5" in output


class TestWaitingForTheFirstPolicy:
    """A signer that is following a notary with nothing published yet.

    It has no socket to forward to for as long as the customer takes to sign the
    policy. The forwarder is up throughout and says so — 503 in the signer's own
    error shape, rather than a refused connection that reads as "the container
    never started".
    """

    def test_the_public_address_answers_503_rather_than_refusing(
        self, home: Path, socket_dir: Path
    ) -> None:
        (home / "notary.json").write_text(
            json.dumps(
                {
                    "url": f"http://127.0.0.1:{free_port()}",
                    "signer_id": "sig_01",
                    "signer_token": "sgn_" + "b" * 43,
                    "org_slug": "acme",
                    "treasury_url": "https://app.merkl.ai/acme/treasuries/rT",
                }
            )
        )
        pair = run_entrypoint(home, socket_dir, "signer", "serve")
        try:
            response = pair.wait_for_forwarder()
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "signer_unavailable"
            assert response.json()["protocol"] == "merkl-signer-rpc-v1"
            assert pair.process.poll() is None, "and it is still waiting, not dead"
        finally:
            pair.stop()


class TestTheAgentDirectory:
    """Whatever a one-shot subcommand left in /agent goes back to its owner."""

    def test_the_bundle_is_handed_back_to_whoever_owns_the_directory(
        self, home: Path, socket_dir: Path, tmp_path: Path
    ) -> None:
        agent_dir = tmp_path / "merkl-agent"
        agent_dir.mkdir()
        (agent_dir / "trader.toml").write_text("[agent]\n")
        before = agent_dir.stat().st_uid

        pair = run_entrypoint(home, socket_dir, "signer", "token", "list", agent_dir=agent_dir)
        assert pair.wait_for_exit() == 0

        assert (agent_dir / "trader.toml").stat().st_uid == before
        assert (agent_dir / "trader.toml").read_text() == "[agent]\n"

    def test_an_agent_directory_that_is_not_there_is_not_an_error(
        self, home: Path, socket_dir: Path, tmp_path: Path
    ) -> None:
        pair = run_entrypoint(
            home, socket_dir, "signer", "token", "list", agent_dir=tmp_path / "nowhere"
        )
        assert pair.wait_for_exit() == 0


class TestEveryOtherSubcommand:
    """`treasury init`, `signer token`, `policy show` — run straight through, as before."""

    def test_a_non_serve_command_runs_the_cli_and_starts_no_forwarder(
        self, home: Path, socket_dir: Path
    ) -> None:
        port = free_port()
        pair = run_entrypoint(home, socket_dir, "signer", "token", "list", listen_port=port)
        assert pair.wait_for_exit() == 0
        assert "no relay tokens configured" in pair.stop()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))  # nothing was ever listening on it

    def test_policy_show_still_reads_a_policy(
        self, home: Path, socket_dir: Path, policy: Path
    ) -> None:
        pair = run_entrypoint(home, socket_dir, "policy", "show", str(policy))
        assert pair.wait_for_exit() == 0
        assert "rTREASURY0000000000000000000000000" in pair.stop()
