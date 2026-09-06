"""``merkl treasury init`` and ``verify`` — set up and check the co-signing account.

Init funds a testnet treasury, installs the signer list (any one agent plus the
policy key reaches quorum; no set of agents alone does), disables the master key
and then reads the account back to prove both. It refuses to report success
otherwise.

Seeds are written to one ``0600`` file. Nothing here prints one.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from merkl.cli.signer import DEFAULT_HOME
from merkl.signer.keystore import DevKeystore


def init_command(
    *,
    home: Path | None = None,
    agents: int = 1,
    wallet_file: Path | None = None,
    json_rpc_url: str | None = None,
) -> int:
    """Bootstrap a testnet treasury against this machine's signer key."""
    try:
        from merkl.adapters.xrpl import TESTNET_JSON_RPC, XrplAdapterError, bootstrap_treasury
    except ImportError:
        print("the xrpl extra is not installed: pip install 'merkl-sdk[xrpl]'", file=sys.stderr)
        return 2

    keystore = DevKeystore((home or DEFAULT_HOME) / "keystore")
    print("funding a testnet treasury and two agent accounts from the faucet…")
    try:
        setup = asyncio.run(
            bootstrap_treasury(
                policy_public_key=keystore.public_key(),
                agent_count=agents,
                json_rpc_url=json_rpc_url or TESTNET_JSON_RPC,
                wallet_file=wallet_file,
            )
        )
    except XrplAdapterError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 3

    print()
    print(f"  treasury        {setup.treasury}")
    for i, agent in enumerate(setup.agents):
        print(f"  agent {i}         {agent}  (weight 1)")
    print(f"  policy signer   {setup.policy_address}  (weight {len(setup.agents)})")
    print(f"  quorum          {setup.quorum}")
    print(f"  master disabled {setup.master_disabled}")
    print(f"  regular key     {setup.regular_key or 'none'}")
    print(f"  signer list tx  {setup.signer_list_tx}")
    print(f"  disable master  {setup.disable_master_tx}")
    print(f"  seeds           {setup.wallet_file} (0600, never commit this)")
    print()
    print(
        "  This treasury can only pay through the signer list, and no set of agent keys "
        "reaches quorum without the policy key."
        if setup.safe
        else "  NOT SAFE — see above."
    )
    return 0 if setup.safe else 4


def verify_command(treasury: str, *, json_rpc_url: str | None = None) -> int:
    """Read an existing treasury's flags and signer list."""
    try:
        from merkl.adapters.xrpl import TESTNET_JSON_RPC, verify_treasury
    except ImportError:
        print("the xrpl extra is not installed: pip install 'merkl-sdk[xrpl]'", file=sys.stderr)
        return 2
    report = asyncio.run(verify_treasury(treasury, json_rpc_url or TESTNET_JSON_RPC))
    print(json.dumps(report, indent=2))
    return 0 if report["safe"] else 4
