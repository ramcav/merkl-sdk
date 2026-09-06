"""Treasury bootstrap — the arrangement that makes Merkl a mandatory co-signer.

Three transactions, in this order, and the order is the security property:

1. ``SignerListSet`` — each agent key gets weight 1, the policy key gets weight
   *N* (the number of agents), and the quorum is *N+1*. Any one agent plus the
   policy key reaches quorum (1 + N); every agent together, without the policy
   key, reaches only N. There is no subset of agent keys that can move funds
   (plan D18);
2. ``AccountSet asfDisableMaster`` — the master key can no longer sign, so the
   signer list is the only way anything leaves the account. Doing this *before*
   the signer list exists would lock the account permanently, which is why the
   order is not a preference;
3. ``account_info`` — read it back. ``lsfDisableMaster`` must be set and there
   must be no ``RegularKey``, because a regular key is a single signer that
   bypasses the list entirely. If either check fails, this refuses to report
   success (plan D14).

Seeds are written to one ``0600`` file and never printed, logged or returned.
Testnet only: :func:`bootstrap_treasury` refuses to touch a mainnet endpoint,
because funding from a faucet is a testnet idea and an accidental mainnet run
would disable a master key on a real account.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from pathlib import Path
from typing import Any, Final

from xrpl.asyncio.account import get_next_valid_seq_number
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.asyncio.transaction import submit_and_wait
from xrpl.asyncio.wallet import generate_faucet_wallet
from xrpl.models.requests import AccountInfo
from xrpl.models.transactions import AccountSet, AccountSetAsfFlag, SignerEntry, SignerListSet
from xrpl.wallet import Wallet

from merkl.adapters.xrpl.adapter import (
    TESTNET_JSON_RPC,
    XrplAdapterError,
    signer_address,
)

LSF_DISABLE_MASTER: Final = 0x00100000
DEFAULT_WALLET_FILE: Final = "xrpl-testnet.wallets.json"
TESTNET_HOSTS: Final = (
    "altnet.rippletest.net",
    "s.devnet.rippletest.net",
    "localhost",
    "127.0.0.1",
)


@dataclasses.dataclass(frozen=True)
class TreasurySetup:
    """The result of a bootstrap. Public values only — no seed ever appears here."""

    treasury: str
    agents: tuple[str, ...]
    policy_address: str
    quorum: int
    master_disabled: bool
    regular_key: str | None
    signer_list_tx: str
    disable_master_tx: str
    wallet_file: str

    @property
    def safe(self) -> bool:
        """True when the account can only move funds through the signer list."""
        return self.master_disabled and self.regular_key is None

    def to_content(self) -> dict[str, Any]:
        return {
            "treasury": self.treasury,
            "agents": list(self.agents),
            "policy_address": self.policy_address,
            "quorum": self.quorum,
            "master_disabled": self.master_disabled,
            "regular_key": self.regular_key,
            "signer_list_tx": self.signer_list_tx,
            "disable_master_tx": self.disable_master_tx,
            "safe": self.safe,
        }


def _write_secret(path: Path, payload: dict[str, Any]) -> None:
    """One ``0600`` file, created atomically. Seeds go here and nowhere else."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, stat.S_IRWXU)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, json.dumps(payload, indent=2).encode() + b"\n")
    finally:
        os.close(fd)
    os.replace(tmp, path)


def load_wallets(path: Path | str) -> dict[str, Wallet]:
    """Read back the seeds this module wrote. Returns wallets, never seeds."""
    document = json.loads(Path(path).read_text())
    return {name: Wallet.from_seed(entry["seed"]) for name, entry in document["wallets"].items()}


def _require_testnet(url: str) -> None:
    if not any(host in url for host in TESTNET_HOSTS):
        raise XrplAdapterError(
            f"{url} does not look like a test network. Bootstrap funds from a faucet and "
            "disables a master key; it will not run against mainnet."
        )


async def bootstrap_treasury(
    *,
    policy_public_key: str,
    agent_count: int = 1,
    json_rpc_url: str = TESTNET_JSON_RPC,
    wallet_file: Path | str | None = None,
    disable_master: bool = True,
) -> TreasurySetup:
    """Fund a treasury, install the signer list, disable the master key, verify."""
    _require_testnet(json_rpc_url)
    if agent_count < 1:
        raise XrplAdapterError("a treasury needs at least one agent")

    client = AsyncJsonRpcClient(json_rpc_url)
    treasury = await generate_faucet_wallet(client, debug=False)
    agents = [await generate_faucet_wallet(client, debug=False) for _ in range(agent_count)]
    policy_address = signer_address(policy_public_key)

    path = Path(wallet_file or Path.home() / ".merkl" / DEFAULT_WALLET_FILE)
    _write_secret(
        path,
        {
            "network": json_rpc_url,
            "policy_address": policy_address,
            "wallets": {
                "treasury": {"seed": treasury.seed, "address": treasury.classic_address},
                **{
                    f"agent-{i}": {"seed": w.seed, "address": w.classic_address}
                    for i, w in enumerate(agents)
                },
            },
        },
    )

    quorum = agent_count + 1
    entries = [SignerEntry(account=w.classic_address, signer_weight=1) for w in agents]
    entries.append(SignerEntry(account=policy_address, signer_weight=agent_count))
    signer_list = SignerListSet(
        account=treasury.classic_address,
        signer_quorum=quorum,
        signer_entries=entries,
        sequence=await get_next_valid_seq_number(treasury.classic_address, client),
    )
    signer_list_result = await submit_and_wait(signer_list, client, treasury)
    _require_success(signer_list_result.result, "SignerListSet")

    disable_tx = ""
    if disable_master:
        disable = AccountSet(
            account=treasury.classic_address,
            set_flag=AccountSetAsfFlag.ASF_DISABLE_MASTER,
            sequence=await get_next_valid_seq_number(treasury.classic_address, client),
        )
        disable_result = await submit_and_wait(disable, client, treasury)
        _require_success(disable_result.result, "AccountSet asfDisableMaster")
        disable_tx = str(disable_result.result.get("hash", ""))

    info = await client.request(
        AccountInfo(account=treasury.classic_address, ledger_index="validated")
    )
    account_data = info.result.get("account_data", {})
    master_disabled = bool(int(account_data.get("Flags", 0)) & LSF_DISABLE_MASTER)
    regular_key = account_data.get("RegularKey")

    setup = TreasurySetup(
        treasury=str(treasury.classic_address),
        agents=tuple(str(w.classic_address) for w in agents),
        policy_address=policy_address,
        quorum=quorum,
        master_disabled=master_disabled,
        regular_key=str(regular_key) if regular_key else None,
        signer_list_tx=str(signer_list_result.result.get("hash", "")),
        disable_master_tx=disable_tx,
        wallet_file=str(path),
    )
    if disable_master and not setup.safe:
        raise XrplAdapterError(
            "the treasury is not safe to use: "
            f"master_disabled={setup.master_disabled}, regular_key={setup.regular_key}. "
            "A RegularKey or an enabled master key can move funds without the policy key."
        )
    return setup


def _require_success(result: dict[str, Any], what: str) -> None:
    code = (result.get("meta") or {}).get("TransactionResult")
    if code != "tesSUCCESS":
        raise XrplAdapterError(f"{what} failed: {code}")


async def verify_treasury(treasury: str, json_rpc_url: str = TESTNET_JSON_RPC) -> dict[str, Any]:
    """Read an existing treasury's account flags. Used by ``merkl treasury verify``."""
    client = AsyncJsonRpcClient(json_rpc_url)
    info = await client.request(AccountInfo(account=treasury, ledger_index="validated"))
    data = info.result.get("account_data", {})
    master_disabled = bool(int(data.get("Flags", 0)) & LSF_DISABLE_MASTER)
    regular_key = data.get("RegularKey")
    signer_list = (info.result.get("signer_lists") or [{}])[0] if info.result else {}
    return {
        "treasury": treasury,
        "master_disabled": master_disabled,
        "regular_key": regular_key,
        "signer_quorum": signer_list.get("SignerQuorum"),
        "signer_entries": [
            {
                "account": e["SignerEntry"]["Account"],
                "weight": e["SignerEntry"]["SignerWeight"],
            }
            for e in signer_list.get("SignerEntries", [])
        ],
        "safe": master_disabled and not regular_key,
    }
