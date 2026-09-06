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

from merkl.core.policy.document import SignedPolicy, verify_policy_signature
from merkl.signer.engine import SignerEngine
from merkl.signer.keystore import DevKeystore
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

    where = str(socket_path) if socket_path else f"http://{host}:{port}"
    print(f"merkl signer — treasury {policy.document.treasury}")
    print(f"  policy       {policy.document.version}  {policy.policy_hash[:16]}…")
    print(f"  public key   {keystore.public_key()}")
    print(f"  state        {state.path} (sequence {state.sequence})")
    print(f"  listening    {where}")
    print()
    print("  UNATTESTED SIGNER. No enclave vouches for this key, and every receipt it")
    print("  produces records that as a fact. Do not point real money at it.")
    serve(engine, socket_path=socket_path, host=host, port=port)
    return 0
