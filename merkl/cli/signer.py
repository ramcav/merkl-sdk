"""``merkl signer serve`` — run the dev signer.

Prints the public key, the policy hash and, loudly, that the signer is
unattested. A dev signer that looked like a production one would be the most
dangerous thing in the repository: the whole trust argument is that a receipt
tells you what held the key, and a receipt from here says "nothing did".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from merkl.core.policy.approvals import verify_policy_signature
from merkl.core.policy.document import SignedPolicy
from merkl.signer.engine import SignerEngine
from merkl.signer.keystore import DevKeystore
from merkl.signer.relay_auth import RelayTokenStore
from merkl.signer.risk import StaticRiskScorer
from merkl.signer.server import serve
from merkl.signer.state import SealedStateStore

DEFAULT_HOME = Path.home() / ".merkl" / "signer"


def serve_command(
    *,
    policy_path: Path,
    home: Path | None = None,
    socket_path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8787,
    blocklist: tuple[str, ...] = (),
) -> int:
    """Load the policy, unseal the key and the state, then serve."""
    home = home or DEFAULT_HOME
    try:
        policy = SignedPolicy.from_content(json.loads(policy_path.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read the policy at {policy_path}: {exc}", file=sys.stderr)
        return 2
    if not verify_policy_signature(policy):
        print(
            f"the policy at {policy_path} is not signed by the admin key it names; refusing "
            "to serve it",
            file=sys.stderr,
        )
        return 3

    keystore = DevKeystore(home / "keystore")
    state = SealedStateStore(home / "state", policy.document.treasury, keystore.seal_key())
    engine = SignerEngine(
        policy=policy,
        keystore=keystore,
        state=state,
        risk=StaticRiskScorer.of(blocklist),
    )
    relay_tokens = RelayTokenStore(home / "relay").load()

    where = str(socket_path) if socket_path else f"http://{host}:{port}"
    print(f"merkl signer — treasury {policy.document.treasury}")
    print(f"  policy       {policy.document.version}  {policy.policy_hash[:16]}…")
    print(f"  public key   {keystore.public_key()}")
    print(f"  state        {state.path} (sequence {state.sequence})")
    print(f"  listening    {where}")
    if relay_tokens:
        print(f"  relay auth   {len(relay_tokens)} token(s) configured — every method but "
              "propose now requires one")
    else:
        print("  relay auth   none configured — every method is reachable through the "
              "transport alone ('merkl signer token add' to change that)")
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
    home = home or DEFAULT_HOME
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
