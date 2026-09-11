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

Mainnet is possible and deliberately awkward. There is no faucet: either an
operator's existing seed file is read, or fresh keys are generated locally and
the caller waits, watching the ledger, until somebody funds the address it
prints. The reserve arithmetic comes from the network's own numbers before
anything is submitted, and the caller must confirm in words, because step 2 is
irreversible on an account with real money in it.

The work is split in two — :func:`create_wallets` and :func:`install_signer_list`
— because something has to happen in the middle. On mainnet that is the funding
wait; with ``--enrol`` it is the call that tells the dashboard which address to
show. :func:`bootstrap_treasury` is still the one-call form for callers with
nothing to do in between.
"""

from __future__ import annotations

import asyncio
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


DROPS_PER_XRP: Final = 1_000_000

FEE_MARGIN_XRP: Final = Decimal("1")
"""What init leaves over for its own transactions, above the locked reserve.

A signer list, an ``AccountSet`` and one ``TrustSet`` per asset cost a base fee
each — tens of drops in total on a healthy network, and more when it is loaded.
One XRP is thousands of times that and still a rounding error against what a
treasury holds, so it is the margin rather than an arithmetic that would have to
be right about fee escalation to avoid stranding a half-configured account."""


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

    def minimum(self, trust_lines: int, *, fee_margin: Decimal = FEE_MARGIN_XRP) -> Decimal:
        """What the treasury must hold before init can finish: reserve plus fees.

        The signer list is one owned object, each trust line is another, and
        every one of them is locked for as long as it exists. The margin on top
        is not locked — it is what pays for the three transactions that install
        the arrangement.
        """
        return self.required(1 + trust_lines) + fee_margin

    def minimum_drops(self, trust_lines: int, *, fee_margin: Decimal = FEE_MARGIN_XRP) -> int:
        return int(self.minimum(trust_lines, fee_margin=fee_margin) * DROPS_PER_XRP)

    def explain(self, trust_lines: int, *, fee_margin: Decimal = FEE_MARGIN_XRP) -> list[str]:
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
        lines.append(f"  fees                  {fee_margin} XRP  (for setup, not locked)")
        lines.append(
            f"  fund at least         {self.minimum(trust_lines, fee_margin=fee_margin)} XRP"
        )
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


async def read_reserves(json_rpc_url: str, *, client: Any | None = None) -> Reserves:
    """The network's own base and owner reserves, in XRP."""
    client = client or AsyncJsonRpcClient(json_rpc_url)
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


@dataclasses.dataclass(frozen=True)
class TreasuryKeys:
    """The accounts a treasury is made of, before any of it is installed.

    Holds ``Wallet`` objects, which hold seeds — so this never crosses back up
    into the CLI, never appears in a printed line and never reaches the notary.
    What *does* is :meth:`addresses`, which is public in the strongest sense:
    the whole point of enrolling before the ledger work is that the page can
    show the customer an address to fund.
    """

    treasury: Wallet
    agents: tuple[Wallet, ...]
    policy_address: str
    wallet_file: Path
    network: str
    created: bool = False
    """True when this run generated the seeds, false when it read somebody's file."""

    @property
    def address(self) -> str:
        return str(self.treasury.classic_address)

    def addresses(self) -> tuple[str, ...]:
        return tuple(str(w.classic_address) for w in self.agents)


async def create_wallets(
    *,
    policy_public_key: str,
    agent_count: int = 1,
    json_rpc_url: str = TESTNET_JSON_RPC,
    wallet_file: Path | str | None = None,
    network: str = NETWORK_XRPL_TESTNET,
    client: Any | None = None,
) -> TreasuryKeys:
    """Bring the treasury and its agents into existence, and write the seed file.

    On testnet that means the faucet. On mainnet there is no faucet, so either
    the operator's own seed file is read (the flow that has always been there)
    or, when there is none, fresh keys are generated locally — an account on
    XRPL exists the moment somebody pays into it, so a key with no money is a
    perfectly good treasury waiting to be funded, and generating it here is what
    lets the dashboard print an address to send to.

    A seed file that already exists is never written over. Whichever way the
    keys arrived, the ledger work has not started: nothing is installed and
    nothing is irreversible yet.
    """
    if agent_count < 1:
        raise XrplAdapterError("a treasury needs at least one agent")
    mainnet = network == NETWORK_XRPL_MAINNET
    if not mainnet:
        _require_testnet(json_rpc_url)

    client = client or AsyncJsonRpcClient(json_rpc_url)
    path = Path(
        wallet_file
        or Path.home() / ".merkl" / (MAINNET_WALLET_FILE if mainnet else DEFAULT_WALLET_FILE)
    )
    policy_address = signer_address(policy_public_key)

    if mainnet and path.exists():
        treasury, agents = _existing_wallets(path, agent_count)
        return TreasuryKeys(
            treasury=treasury,
            agents=tuple(agents),
            policy_address=policy_address,
            wallet_file=path,
            network=network,
        )

    if mainnet:
        treasury = Wallet.create()
        agents = [Wallet.create() for _ in range(agent_count)]
    else:
        treasury = await generate_faucet_wallet(client, debug=False)
        agents = [await generate_faucet_wallet(client, debug=False) for _ in range(agent_count)]

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
    return TreasuryKeys(
        treasury=treasury,
        agents=tuple(agents),
        policy_address=policy_address,
        wallet_file=path,
        network=network,
        created=True,
    )


async def account_drops(
    address: str, json_rpc_url: str = TESTNET_JSON_RPC, *, client: Any | None = None
) -> int | None:
    """The account's validated balance in drops, or ``None`` when it does not exist.

    An unfunded XRPL address is not an error and not a zero balance: it is an
    account the ledger has never heard of. Those are different facts and the
    caller shows them differently — "send XRP here" against "keep sending, it is
    not enough yet".
    """
    client = client or AsyncJsonRpcClient(json_rpc_url)
    response = await client.request(AccountInfo(account=address, ledger_index="validated"))
    data = response.result.get("account_data") or {}
    balance = data.get("Balance")
    if balance is None:
        return None
    try:
        return int(balance)
    except (TypeError, ValueError):  # pragma: no cover - rippled sends a decimal string
        return None


async def await_funding(
    address: str,
    required_drops: int,
    json_rpc_url: str = TESTNET_JSON_RPC,
    *,
    client: Any | None = None,
    poll_seconds: float = 5.0,
    sleep: Any = None,
    on_poll: Any = None,
) -> int:
    """Watch the ledger until ``address`` holds enough, then return what it holds.

    This is the one place ``merkl treasury init`` blocks on a human. It never
    times out: the customer is at their exchange's withdrawal screen and how
    long that takes is not this program's business. A node that will not answer
    is a poll that reported nothing, not a run that gave up on a treasury whose
    keys are already on disk.
    """
    sleeper = sleep or asyncio.sleep
    while True:
        try:
            drops = await account_drops(address, json_rpc_url, client=client)
        except Exception:  # noqa: BLE001 - a node that hiccups is not a funding answer
            drops = None
        if drops is not None and drops >= required_drops:
            return drops
        if on_poll is not None:
            on_poll(drops)
        await sleeper(poll_seconds)


async def install_signer_list(
    keys: TreasuryKeys,
    *,
    json_rpc_url: str = TESTNET_JSON_RPC,
    disable_master: bool = True,
    trust_lines: Sequence[TrustLine] = (),
    client: Any | None = None,
) -> TreasurySetup:
    """The three transactions, in the order that is the security property.

    Trust lines, then the signer list, then the master key off, then the
    read-back that refuses to report success unless both held.
    """
    client = client or AsyncJsonRpcClient(json_rpc_url)
    treasury = keys.treasury
    agents = list(keys.agents)
    agent_count = len(agents)

    await _set_trust_lines(client, treasury, trust_lines)

    quorum = agent_count + 1
    entries = [SignerEntry(account=w.classic_address, signer_weight=1) for w in agents]
    entries.append(SignerEntry(account=keys.policy_address, signer_weight=agent_count))
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
        policy_address=keys.policy_address,
        quorum=quorum,
        master_disabled=master_disabled,
        regular_key=str(regular_key) if regular_key else None,
        signer_list_tx=str(signer_list_result.result.get("hash", "")),
        disable_master_tx=disable_tx,
        wallet_file=str(keys.wallet_file),
        network=keys.network,
        trust_lines=tuple(trust_lines),
    )
    if disable_master and not setup.safe:
        raise XrplAdapterError(
            "the treasury is not safe to use: "
            f"master_disabled={setup.master_disabled}, regular_key={setup.regular_key}. "
            "A RegularKey or an enabled master key can move funds without the policy key."
        )
    return setup


async def bootstrap_treasury(
    *,
    policy_public_key: str,
    agent_count: int = 1,
    json_rpc_url: str = TESTNET_JSON_RPC,
    wallet_file: Path | str | None = None,
    disable_master: bool = True,
    network: str = NETWORK_XRPL_TESTNET,
    trust_lines: Sequence[TrustLine] = (),
    client: Any | None = None,
) -> TreasurySetup:
    """Fund a treasury, install the signer list, disable the master key, verify.

    The one-call form, kept because it is what the demo rig and the testnet
    scenario have always used. ``merkl treasury init`` runs the two halves
    itself so it can enrol with the notary — and, on mainnet, wait for money —
    in between.
    """
    client = client or AsyncJsonRpcClient(json_rpc_url)
    keys = await create_wallets(
        policy_public_key=policy_public_key,
        agent_count=agent_count,
        json_rpc_url=json_rpc_url,
        wallet_file=wallet_file,
        network=network,
        client=client,
    )
    return await install_signer_list(
        keys,
        json_rpc_url=json_rpc_url,
        disable_master=disable_master,
        trust_lines=trust_lines,
        client=client,
    )


def _existing_wallets(path: Path, agent_count: int) -> tuple[Wallet, list[Wallet]]:
    """Read an already-funded treasury and its agents from a seed file.

    Mainnet's original substitute for the faucet, and still the flow an operator
    who already has accounts wants: the file is theirs, written and funded by
    them, and nothing here writes a seed back over one that already exists.
    """
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
