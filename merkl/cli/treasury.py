"""``merkl treasury init`` and ``verify`` — set up and check the co-signing account.

Init sets the trust lines, installs the signer list (any one agent plus the
policy key reaches quorum; no set of agents alone does), disables the master key
and then reads the account back to prove both. It refuses to report success
otherwise.

Testnet funds from the faucet. Mainnet does not: there is no faucet, the wallets
are the operator's own, the reserve arithmetic is printed from the network's own
numbers before anything is submitted, and the operator has to type a sentence —
because disabling a master key on an account with real money in it is a thing
that happens once.

Seeds are written to one ``0600`` file. Nothing here prints one.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from merkl.cli.home import resolve_home
from merkl.core.rail import NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET
from merkl.signer.keystore import DevKeystore

MAINNET_CONFIRMATION = "disable the master key on mainnet"
"""What an operator types to prove they meant it. No flag bypasses this."""


def init_command(
    *,
    home: Path | None = None,
    agents: int = 1,
    wallet_file: Path | None = None,
    json_rpc_url: str | None = None,
    network: str = NETWORK_XRPL_TESTNET,
    trust: tuple[str, ...] = (),
) -> int:
    """Bootstrap a treasury against this machine's signer key."""
    try:
        from merkl.adapters.xrpl import (
            MAINNET_JSON_RPC,
            TESTNET_JSON_RPC,
            TrustLine,
            XrplAdapterError,
            bootstrap_treasury,
            read_reserves,
        )
    except ImportError:
        print("the xrpl extra is not installed: pip install 'merkl-sdk[xrpl]'", file=sys.stderr)
        return 2

    mainnet = network == NETWORK_XRPL_MAINNET
    endpoint = json_rpc_url or (MAINNET_JSON_RPC if mainnet else TESTNET_JSON_RPC)
    keystore = DevKeystore(resolve_home(home) / "keystore")

    try:
        lines = tuple(TrustLine.parse(entry) for entry in trust)
    except XrplAdapterError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if mainnet:
        try:
            reserves = asyncio.run(read_reserves(endpoint))
        except Exception as exc:  # noqa: BLE001 - a node that will not answer is a stop, not a crash
            print(f"could not read the network's reserves from {endpoint}: {exc}", file=sys.stderr)
            return 3
        print(f"XRPL MAINNET — {endpoint}")
        print()
        print("  This will permanently disable the treasury's master key. After it runs,")
        print("  nothing moves out of that account without the policy signer.")
        print()
        for row in reserves.explain(len(lines)):
            print(row)
        print()
        print(f"  policy.network        {NETWORK_XRPL_MAINNET}  (write this into the policy)")
        print(f"  seeds read from       {wallet_file or '~/.merkl/xrpl-mainnet.wallets.json'}")
        print()
        typed = input(f"Type '{MAINNET_CONFIRMATION}' to continue: ").strip()
        if typed != MAINNET_CONFIRMATION:
            print("not confirmed; nothing was submitted", file=sys.stderr)
            return 5
    else:
        print("funding a testnet treasury and its agent accounts from the faucet…")

    for asset in lines:
        print(f"  trust line            {asset.code}.{asset.issuer} limit {asset.limit}")

    try:
        setup = asyncio.run(
            bootstrap_treasury(
                policy_public_key=keystore.public_key(),
                agent_count=agents,
                json_rpc_url=endpoint,
                wallet_file=wallet_file,
                network=network,
                trust_lines=lines,
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
    for asset in setup.trust_lines:
        print(f"  trust line      {asset.code}.{asset.issuer}")
    print(f"  policy.network  {setup.network}")
    print(f"  seeds           {setup.wallet_file} (0600, never commit this)")
    print()
    print(
        "  This treasury can only pay through the signer list, and no set of agent keys "
        "reaches quorum without the policy key."
        if setup.safe
        else "  NOT SAFE — see above."
    )
    if setup.safe:
        print(
            "  Every payment needs a person's approval until you set a threshold. "
            "Write a policy whose human-tier amount is 0 for each allowed asset, "
            f"whose network is {setup.network}, then `merkl policy sign`."
        )
        if setup.trust_lines:
            print(
                "  The trust lines are set. An agent may only trade the assets its policy "
                "section allowlists, and only if that section says may_swap."
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
