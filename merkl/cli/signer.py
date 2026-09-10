"""``merkl signer serve`` — run the dev signer.

Prints the public key, the policy hash and, loudly, that the signer is
unattested. A dev signer that looked like a production one would be the most
dangerous thing in the repository: the whole trust argument is that a receipt
tells you what held the key, and a receipt from here says "nothing did".
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path

from merkl.cli.home import resolve_home
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
from merkl.signer.server import serve
from merkl.signer.state import SealedStateStore

RAIL_ENDPOINT_ENV = "MERKL_RAIL_ENDPOINT"


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


def serve_command(
    *,
    policy_path: Path,
    home: Path | None = None,
    socket_path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
    blocklist: tuple[str, ...] = (),
    rail_endpoint: str | None = None,
) -> int:
    """Load the policy, unseal the key and the state, then serve."""
    home = resolve_home(home)
    try:
        policy = SignedPolicy.from_content(json.loads(policy_path.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read the policy at {policy_path}: {exc}", file=sys.stderr)
        return 2
    except PolicyError as exc:
        print(
            f"the policy at {policy_path} is not a policy this signer will serve: {exc}",
            file=sys.stderr,
        )
        return 2
    if not verify_policy_signature(policy):
        print(
            f"the policy at {policy_path} is not signed by the admin key it names; refusing "
            "to serve it",
            file=sys.stderr,
        )
        return 3
    endpoint = rail_endpoint or os.environ.get(RAIL_ENDPOINT_ENV)
    problem = _network_problem(policy, endpoint)
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

    where = str(socket_path) if socket_path else f"http://{host}:{port}"
    chain = policy.document.network or f"{policy.document.rail} (no network named)"
    print(f"merkl signer — treasury {policy.document.treasury}")
    print(f"  policy       {policy.document.version}  {policy.policy_hash[:16]}…")
    print(f"  network      {chain}")
    print(f"  public key   {keystore.public_key()}")
    print(f"  state        {state.path} (sequence {state.sequence})")
    print(f"  listening    {where}")
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
    serve(engine, socket_path=socket_path, host=host, port=port, relay_tokens=relay_tokens)
    return 0


def token_command(action: str, token_id: str | None, *, home: Path | None = None) -> int:
    """``merkl signer token add|revoke|list`` — manage the relay credential list.

    Writes directly to the store the signer reads at boot
    (``docs/SIGNER-RPC.md``, "Who may call what"); the signer must be restarted
    to pick up a change. ``add`` prints the fresh bearer token exactly once —
    only its SHA-256 is ever written to disk.
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
