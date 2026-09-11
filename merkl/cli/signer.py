"""``merkl signer serve|bootstrap|token`` — run the dev signer.

Prints the public key, the policy hash and, loudly, that the signer is
unattested. A dev signer that looked like a production one would be the most
dangerous thing in the repository: the whole trust argument is that a receipt
tells you what held the key, and a receipt from here says "nothing did".

Phase 17 gave ``serve`` a second way to find its policy. When ``<home>`` holds a
``notary.json`` — written by ``merkl treasury init --enrol`` — the signer
**follows the notary**: it waits for the first policy the customer publishes,
picks up changes afterwards, pulls the approvals people gave in the dashboard,
and heartbeats so the page can say the policy is actually in force. All of that
lives in ``merkl.adapters.notary.follower``; the signer package itself still
knows no notary and writes to no stream. What is *not* new is who verifies what:
a policy is checked against the pinned admin credential here, an approval
against the approvers the policy names, and a notary that lied would be refused
by the same code that has always refused a liar.

Without ``notary.json``, nothing changed: ``--policy`` (now defaulting to
``<home>/policy.signed.json``) is the whole story.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path

from merkl.adapters.notary.enrol import NotaryEnrolError, NotaryRecord
from merkl.cli.home import notary_path, resolve_home, treasury_path
from merkl.cli.home import policy_path as home_policy_path
from merkl.core.policy.approvals import verify_policy_signature
from merkl.core.policy.document import PolicyError, SignedPolicy
from merkl.signer.engine import SignerEngine
from merkl.signer.keystore import (
    KEY_FILE,
    PASSPHRASE_ENV,
    PASSPHRASE_FILE,
    DevKeystore,
    KeystoreError,
)
from merkl.signer.rails import network_of_endpoint
from merkl.signer.relay_auth import RelayTokenStore
from merkl.signer.risk import StaticRiskScorer
from merkl.signer.server import RpcRouter, serve
from merkl.signer.state import SealedStateStore

RAIL_ENDPOINT_ENV = "MERKL_RAIL_ENDPOINT"


def _log(line: str) -> None:
    """Where the follower's lines go. Its only route to a stream, on purpose."""
    print(line, file=sys.stderr, flush=True)


def _resolve_passphrase(home: Path) -> str | None:
    """The keystore passphrase for a *served* signer: the environment, or a prompt.

    Never a generated file. ``merkl signer serve`` opens a keystore somebody else
    created — ``merkl treasury init``, a deployment script, the e2e rig — and
    those may have been given an explicit passphrase, in which case there is no
    passphrase file to read. Letting the keystore generate one there wrote a
    stray secret beside a key it could not open, and then failed with a message
    about a damaged file. So: the environment, else a prompt, else let the
    keystore use the file it wrote when it created the key itself.
    """
    if os.environ.get(PASSPHRASE_ENV):
        return None  # DevKeystore reads it, and reads it the same way we would
    if (home / "keystore" / PASSPHRASE_FILE).exists():
        return None  # this keystore made its own passphrase; keep using it
    if not (home / "keystore" / KEY_FILE).exists():
        return None  # first boot: the keystore creates both, as it always has
    if not sys.stdin.isatty():
        return None  # no way to ask; DevKeystore raises a precise error instead
    return getpass.getpass(f"passphrase for the keystore at {home / 'keystore'}: ")


def _network_problem(policy: SignedPolicy, endpoint: str | None) -> str | None:
    """Whether a configured rail endpoint disagrees with the chain the policy names."""
    network = policy.document.network
    if network is None or not endpoint:
        return None
    observed = network_of_endpoint(policy.document.rail, endpoint)
    if observed is None or observed == network:
        return None
    return (
        f"the rail endpoint {endpoint} is on {observed}, but this policy governs {network}. "
        "The same address exists on both chains and means nothing in common between them, "
        "so the signer refuses to serve one from the other."
    )


def _enrolled_network_problem(policy: SignedPolicy, record: NotaryRecord | None) -> str | None:
    """The same refusal, from what the signer was enrolled as when no endpoint says.

    In a container there is no ``--rail-endpoint``: the signer never calls the
    rail, and the URL that would have named a chain lives in the *agent's*
    config, not here. ``notary.json`` is then the only thing on disk that knows
    which chain this treasury is on, and serving a mainnet policy from a signer
    somebody enrolled on testnet is exactly as wrong as the other way round.
    """
    if record is None or record.network is None:
        return None
    network = policy.document.network
    if network is None or network == record.network:
        return None
    return (
        f"this signer was enrolled on {record.network}, and this policy governs {network}. "
        "The same address exists on both chains and means nothing in common between them, "
        "so the signer refuses to serve one from the other."
    )


def serve_command(
    *,
    policy_path: Path | None = None,
    home: Path | None = None,
    socket_path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
    blocklist: tuple[str, ...] = (),
    rail_endpoint: str | None = None,
    follow: bool = True,
) -> int:
    """Load the policy, unseal the key and the state, then serve.

    ``follow`` exists for the suite: everything up to and including the
    follower's construction is worth testing, and a test that then blocked on a
    ten-second poll against a notary that is not there would be a test nobody
    runs.
    """
    home = resolve_home(home)
    path = policy_path or home_policy_path(home)

    try:
        record = NotaryRecord.read(notary_path(home))
    except NotaryEnrolError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    follower = None
    if record is not None and follow:
        from merkl.adapters.notary.follower import NotaryFollower

        follower = NotaryFollower(record, home=home, log=_log)

    if not path.exists() and follower is not None:
        print(f"merkl signer — following the notary at {record.url}")  # type: ignore[union-attr]
        print("  policy       waiting for the first one to be published")
        print("  listening    every RPC answers 503 until there is one")
        policy_or_none = follower.await_first_policy()
        if policy_or_none is None:  # pragma: no cover - only a stop callback ends the wait
            return 2
        policy = policy_or_none
    else:
        loaded = _read_policy(path)
        if isinstance(loaded, int):
            return loaded
        policy = loaded
        if follower is not None:
            follower.adopt(policy)

    endpoint = rail_endpoint or os.environ.get(RAIL_ENDPOINT_ENV)
    problem = _network_problem(policy, endpoint) or (
        _enrolled_network_problem(policy, record) if not endpoint else None
    )
    if problem is not None:
        print(problem, file=sys.stderr)
        return 4

    try:
        keystore = DevKeystore(home / "keystore", passphrase=_resolve_passphrase(home))
    except KeystoreError as exc:
        print(str(exc), file=sys.stderr)
        return 5
    state = SealedStateStore(home / "state", policy.document.treasury, keystore.seal_key())
    engine = SignerEngine(
        policy=policy,
        keystore=keystore,
        state=state,
        risk=StaticRiskScorer.of(blocklist),
    )
    relay_tokens = RelayTokenStore(home / "relay").load()
    router = RpcRouter(engine, relay_tokens)

    where = str(socket_path) if socket_path else f"http://{host}:{port}"
    chain = policy.document.network or f"{policy.document.rail} (no network named)"
    print(f"merkl signer — treasury {policy.document.treasury}")
    print(f"  policy       {policy.document.version}  {policy.policy_hash[:16]}…")
    print(f"  network      {chain}")
    print(f"  public key   {keystore.public_key()}")
    print(f"  state        {state.path} (sequence {state.sequence})")
    print(f"  listening    {where}")
    if record is not None:
        print(f"  notary       {record.url} (pulling policy and approvals)")
    if relay_tokens:
        print(
            f"  relay auth   {len(relay_tokens)} token(s) configured — every method but "
            "propose now requires one"
        )
    else:
        print(
            "  relay auth   none configured — every method is reachable through the "
            "transport alone ('merkl signer token add' to change that)"
        )
    print()
    print("  UNATTESTED SIGNER. No enclave vouches for this key, and every receipt it")
    print("  produces records that as a fact. Do not point real money at it.")

    if follower is not None:
        follower.attach(router)
        follower.start()
    serve(
        engine,
        socket_path=socket_path,
        host=host,
        port=port,
        relay_tokens=relay_tokens,
        router=router,
    )
    return 0


def bootstrap_command(
    *,
    home: Path | None = None,
    network: str,
    agents: int = 1,
    wallet_file: Path | None = None,
    trust: tuple[str, ...] = (),
    enrol: str | None = None,
    notary: str | None = None,
    confirm: str | None = None,
    agent_dir: Path | None = None,
    bundle_to_notary: bool = False,
    socket_path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
    blocklist: tuple[str, ...] = (),
    rail_endpoint: str | None = None,
) -> int:
    """``merkl signer bootstrap`` — set the treasury up, then serve it, in one process.

    What a managed container runs: there is nobody at a terminal, so the mainnet
    sentence has to arrive as ``--confirm`` and its absence is an exit rather
    than a prompt into a closed stdin. Everything else is exactly
    ``treasury init`` followed by ``signer serve``, in that order, in the same
    process — which is the point, because the keystore ``init`` creates is the
    one ``serve`` opens a second later, in the volume, without either of them
    having moved a byte of it.
    """
    from merkl.cli.treasury import init_command

    code = init_command(
        home=home,
        agents=agents,
        wallet_file=wallet_file,
        network=network,
        trust=trust,
        enrol=enrol,
        notary=notary,
        confirm=confirm,
        agent_dir=agent_dir,
        bundle_to_notary=bundle_to_notary,
        interactive=False,
    )
    if code != 0:
        return code
    print()
    return serve_command(
        home=home,
        socket_path=socket_path,
        host=host,
        port=port,
        blocklist=blocklist,
        rail_endpoint=rail_endpoint,
    )


def token_command(
    action: str,
    token_id: str | None,
    *,
    home: Path | None = None,
    as_env: bool = False,
) -> int:
    """``merkl signer token add|revoke|list`` — manage the relay credential list.

    Writes directly to the store the signer reads at boot
    (``docs/SIGNER-RPC.md``, "Who may call what"); the signer must be restarted
    to pick up a change. ``add`` prints the fresh bearer token exactly once —
    only its SHA-256 is ever written to disk.

    ``--env`` prints the two finished lines a notary deployment pastes into its
    environment instead of the token on its own. The same secret either way; the
    difference is that nobody has to work out which variable it goes in, and
    ``SIGNER_RELAY_TOKENS`` is keyed by treasury, which this command can look up
    and a person copying between two terminals cannot.
    """
    home = resolve_home(home)
    store = RelayTokenStore(home / "relay")
    if action == "add":
        if not token_id:
            print("usage: merkl signer token add <id>", file=sys.stderr)
            return 2
        try:
            bearer = store.add(token_id)
        except Exception as exc:  # noqa: BLE001 - one message for any config problem
            print(str(exc), file=sys.stderr)
            return 1
        if as_env:
            treasury = _treasury_of(home)
            print(f"MERKL_SIGNER_TOKEN={bearer}")
            print(f'SIGNER_RELAY_TOKENS={{"{treasury}": "{bearer}"}}')
            return 0
        print(f"relay token {token_id!r} created. This is the only time it is shown:")
        print()
        print(f"  {bearer}")
        print()
        print("Pass it as 'Authorization: Bearer <token>', --relay-token, or")
        print("$MERKL_RELAY_TOKEN. Restart the signer to enforce it.")
        return 0
    if action == "revoke":
        if not token_id:
            print("usage: merkl signer token revoke <id>", file=sys.stderr)
            return 2
        if not store.revoke(token_id):
            print(f"no relay token named {token_id!r}", file=sys.stderr)
            return 1
        print(f"relay token {token_id!r} revoked. Restart the signer to enforce it.")
        return 0
    tokens = store.list()
    if not tokens:
        print("no relay tokens configured — every non-propose method is unauthenticated")
        return 0
    for entry in tokens:
        print(entry.id)
    return 0


# -- internals ---------------------------------------------------------------- #


def _read_policy(path: Path) -> SignedPolicy | int:
    """The policy at ``path``, or the exit code its problem deserves."""
    try:
        policy = SignedPolicy.from_content(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read the policy at {path}: {exc}", file=sys.stderr)
        return 2
    except PolicyError as exc:
        print(
            f"the policy at {path} is not a policy this signer will serve: {exc}",
            file=sys.stderr,
        )
        return 2
    if not verify_policy_signature(policy):
        print(
            f"the policy at {path} is not signed by the admin key it names; refusing to serve it",
            file=sys.stderr,
        )
        return 3
    return policy


def _treasury_of(home: Path) -> str:
    """Which treasury this home serves, from whatever on disk knows.

    ``treasury.json`` first because it exists from the moment the keys do; the
    policy second because a signer set up before this phase has one and nothing
    else. A home with neither prints the placeholder rather than a wrong
    address — an operator can fill that in, and cannot un-paste a lie.
    """
    from merkl.cli.treasury import TreasuryRecord

    try:
        record = TreasuryRecord.read(treasury_path(home))
    except (OSError, KeyError, json.JSONDecodeError):  # pragma: no cover - a mangled file
        record = None
    if record is not None:
        return record.treasury
    path = home_policy_path(home)
    if path.exists():
        try:
            return str(SignedPolicy.from_content(json.loads(path.read_text())).document.treasury)
        except (OSError, ValueError, PolicyError):  # pragma: no cover - a mangled file
            pass
    return "<treasury>"


__all__ = ["bootstrap_command", "serve_command", "token_command"]
