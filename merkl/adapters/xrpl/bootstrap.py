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

Trust lines come first, before any of the three, because they are the one thing
the treasury can never do again afterwards: a ``TrustSet`` is signed by the
account, the account signs with its master key, and step 2 turns that key off.
An asset the treasury cannot hold is an asset it cannot buy, so a treasury meant
to trade has to declare its lines while it still can.

Seeds are written to one ``0600`` file and never printed, logged or returned.

Mainnet is possible and deliberately awkward. There is no faucet, so the wallets
are read from an existing seed file rather than created; the reserve arithmetic
is printed from the network's own numbers before anything is submitted; and the
caller must confirm in words, because step 2 is irreversible on an account with
real money in it.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

from xrpl.asyncio.account import get_next_valid_seq_number
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.asyncio.transaction import submit_and_wait
from xrpl.asyncio.wallet import generate_faucet_wallet
from xrpl.models.amounts import IssuedCurrencyAmount
from xrpl.models.requests import AccountInfo, ServerInfo
from xrpl.models.transactions import (
    AccountSet,
    AccountSetAsfFlag,
    SignerEntry,
    SignerListSet,
    TrustSet,
)
from xrpl.wallet import Wallet

from merkl.adapters.xrpl.adapter import (
    TESTNET_JSON_RPC,
    XrplAdapterError,
    currency_code,
    signer_address,
)
from merkl.core.rail import NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET

LSF_DISABLE_MASTER: Final = 0x00100000
DEFAULT_WALLET_FILE: Final = "xrpl-testnet.wallets.json"
MAINNET_WALLET_FILE: Final = "xrpl-mainnet.wallets.json"
TESTNET_HOSTS: Final = (
    "altnet.rippletest.net",
    "s.devnet.rippletest.net",
    "localhost",
    "127.0.0.1",
)

DEFAULT_TRUST_LIMIT: Final = "1000000000"
"""How much of an issued asset a new trust line will hold.

``--trust CODE.issuer`` names an asset, not a size. A line's limit is a ceiling
on the *counterparty*, not an authority the agent gains — the policy is what
bounds what the agent may move — so it is set high enough not to be the thing
that breaks a legitimate trade, and an operator who wants a tighter one sets it
themselves with ``TrustSet``."""


@dataclasses.dataclass(frozen=True)
class TrustLine:
    """One issued asset the treasury will be able to hold."""

    code: str
    issuer: str
    limit: str = DEFAULT_TRUST_LIMIT

    @classmethod
    def parse(cls, text: str) -> TrustLine:
        """``CODE.issuer`` — the form ``merkl treasury init --trust`` takes."""
        code, _, issuer = text.partition(".")
        if not code or not issuer:
            raise XrplAdapterError(f"--trust wants CODE.issuer, got {text!r}")
        return cls(code=code, issuer=issuer)

    def to_content(self) -> dict[str, Any]:
        return {"code": self.code, "issuer": self.issuer, "limit": self.limit}


@dataclasses.dataclass(frozen=True)
class Reserves:
    """What the network requires an account to hold, in XRP.

    Read from the node rather than hardcoded: XRPL has changed both numbers
    before, and an operator funding a mainnet account from arithmetic this
    library remembered from a previous year would fund it wrongly.
    """

    base: Decimal
    owner: Decimal

    def required(self, owned: int) -> Decimal:
        return self.base + self.owner * owned

    def explain(self, trust_lines: int) -> list[str]:
        """The arithmetic, itemised, so nobody has to take the total on trust."""
        owned = 1 + trust_lines
        lines = [
            f"  base reserve          {self.base} XRP",
            f"  signer list           {self.owner} XRP  (one owner reserve)",
        ]
        if trust_lines:
            total = self.owner * trust_lines
            lines.append(f"  trust lines           {total} XRP  ({trust_lines} x {self.owner})")
        lines.append(f"  minimum balance       {self.required(owned)} XRP, permanently locked")
        return lines


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
    network: str = NETWORK_XRPL_TESTNET
    """The chain this treasury lives on, in the vocabulary ``policy.network`` uses.

    Written into the seed file and printed, because a policy for this treasury
    must name the same value or the signer refuses to serve it at boot."""

    trust_lines: tuple[TrustLine, ...] = ()

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
            "network": self.network,
            "trust_lines": [line.to_content() for line in self.trust_lines],
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


async def read_reserves(json_rpc_url: str) -> Reserves:
    """The network's own base and owner reserves, in XRP."""
    client = AsyncJsonRpcClient(json_rpc_url)
    response = await client.request(ServerInfo())
    ledger = (response.result.get("info") or {}).get("validated_ledger") or {}
    base, owner = ledger.get("reserve_base_xrp"), ledger.get("reserve_inc_xrp")
    if base is None or owner is None:
        raise XrplAdapterError(
            f"{json_rpc_url} did not report its reserves; refusing to guess what an "
            "account must hold"
        )
    return Reserves(base=Decimal(str(base)), owner=Decimal(str(owner)))


async def _set_trust_lines(
    client: AsyncJsonRpcClient, treasury: Wallet, lines: Sequence[TrustLine]
) -> None:
    """Declare every asset the treasury will hold, while it can still sign.

    Before the signer list and before the master key goes, because a ``TrustSet``
    afterwards would need the quorum, and the quorum needs a policy — the whole
    arrangement this bootstrap exists to install. An asset with no line is an
    asset a trade cannot buy, so this is not setup, it is the trading authority
    itself.
    """
    for line in lines:
        trust = TrustSet(
            account=treasury.classic_address,
            limit_amount=IssuedCurrencyAmount(
                currency=currency_code(line.code), issuer=line.issuer, value=line.limit
            ),
            sequence=await get_next_valid_seq_number(treasury.classic_address, client),
        )
        result = await submit_and_wait(trust, client, treasury)
        _require_success(result.result, f"TrustSet {line.code}.{line.issuer}")


async def bootstrap_treasury(
    *,
    policy_public_key: str,
    agent_count: int = 1,
    json_rpc_url: str = TESTNET_JSON_RPC,
    wallet_file: Path | str | None = None,
    disable_master: bool = True,
    network: str = NETWORK_XRPL_TESTNET,
    trust_lines: Sequence[TrustLine] = (),
) -> TreasurySetup:
    """Fund a treasury, install the signer list, disable the master key, verify.

    On testnet the wallets come from the faucet. On mainnet there is no faucet,
    so they are read from ``wallet_file`` — an operator funds those accounts
    themselves, and this refuses to run against accounts it cannot see money in.
    """
    if agent_count < 1:
        raise XrplAdapterError("a treasury needs at least one agent")
    mainnet = network == NETWORK_XRPL_MAINNET
    if not mainnet:
        _require_testnet(json_rpc_url)

    client = AsyncJsonRpcClient(json_rpc_url)
    path = Path(
        wallet_file
        or Path.home() / ".merkl" / (MAINNET_WALLET_FILE if mainnet else DEFAULT_WALLET_FILE)
    )
    if mainnet:
        treasury, agents = _existing_wallets(path, agent_count)
    else:
        treasury = await generate_faucet_wallet(client, debug=False)
        agents = [await generate_faucet_wallet(client, debug=False) for _ in range(agent_count)]
    policy_address = signer_address(policy_public_key)

    if not mainnet:
        _write_secret(
            path,
            {
                "network": json_rpc_url,
                "policy_network": network,
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

    await _set_trust_lines(client, treasury, trust_lines)

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
        network=network,
        trust_lines=tuple(trust_lines),
    )
    if disable_master and not setup.safe:
        raise XrplAdapterError(
            "the treasury is not safe to use: "
            f"master_disabled={setup.master_disabled}, regular_key={setup.regular_key}. "
            "A RegularKey or an enabled master key can move funds without the policy key."
        )
    return setup


def _existing_wallets(path: Path, agent_count: int) -> tuple[Wallet, list[Wallet]]:
    """Read an already-funded treasury and its agents from a seed file.

    Mainnet's substitute for the faucet. The file is the operator's, written and
    funded by them; nothing here creates an account on a chain with real money
    on it, and nothing here writes a seed back over one that already exists.
    """
    if not path.exists():
        raise XrplAdapterError(
            f"{path} does not exist. Mainnet has no faucet: create and fund the treasury "
            "and agent accounts yourself, write their seeds into this file (0600), then "
            "run this again."
        )
    wallets = load_wallets(path)
    if "treasury" not in wallets:
        raise XrplAdapterError(f"{path} names no 'treasury' wallet")
    agents = [
        wallets[name] for name in (f"agent-{i}" for i in range(agent_count)) if name in wallets
    ]
    if len(agents) != agent_count:
        raise XrplAdapterError(
            f"{path} names {len(agents)} agent wallets, this run wants {agent_count}"
        )
    return wallets["treasury"], agents


def _require_success(result: dict[str, Any], what: str) -> None:
    code = (result.get("meta") or {}).get("TransactionResult")
    if code != "tesSUCCESS":
        raise XrplAdapterError(f"{what} failed: {code}")


async def verify_treasury(treasury: str, json_rpc_url: str = TESTNET_JSON_RPC) -> dict[str, Any]:
    """Read an existing treasury's account flags. Used by ``merkl treasury verify``."""
    client = AsyncJsonRpcClient(json_rpc_url)
    info = await client.request(
        AccountInfo(account=treasury, ledger_index="validated", signer_lists=True)
    )
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
