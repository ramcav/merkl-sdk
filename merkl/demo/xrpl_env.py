"""The five scenarios, against XRPL testnet.

Same claim as :mod:`merkl.demo.scenarios` makes about the fake rail, checked
against the network that actually settles: the story is about the *signer* and
the receipt, not about a ledger Merkl wrote itself.

Bootstrap is cached under ``~/.merkl`` — the same wallet files
``merkl treasury init`` and ``tests/scenarios/test_xrpl_testnet.py`` use — so a
second run reuses the treasury and its co-signing key instead of draining the
faucet again. Only the per-scenario signer *state* (the sliding window, the
nonce ledger) is fresh every time, in a caller-supplied temp directory: the
treasury and its policy key are one long-lived identity, the window is not.

Requires ``pip install 'merkl-sdk[xrpl,signer,signer-xrpl]'`` and a reachable
network; nothing here runs unless a caller asks for it explicitly.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Final

from merkl.core.intent import CurrencyRef
from merkl.core.policy.document import PolicyDocument
from merkl.demo.rig import (
    AGENT,
    AGENT_ID,
    FrozenClock,
    Rig,
    build_policy,
    sign_policy,
)
from merkl.demo.scenarios import Amounts

XRPL_AMOUNTS: Final = Amounts(
    ordinary="1",
    over_threshold="3.5",
    drain="50",
    per_tx_cap="5",
    human_threshold="3",
    window=("20", 3600),
    structuring_window=("2.5", 3600),
    structuring_step="1",
)
"""Small on purpose: this treasury is a real, faucet-funded testnet account."""

DEFAULT_HOME: Final = Path.home() / ".merkl"
TREASURY_FILE: Final = DEFAULT_HOME / "xrpl-testnet.wallets.json"
PARTIES_FILE: Final = DEFAULT_HOME / "xrpl-testnet-parties.wallets.json"
SIGNER_HOME: Final = DEFAULT_HOME / "testnet-signer"
PASSPHRASE: Final = "merkl-testnet-signer"

ATTACKER: Final = "rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV"
"""A real testnet address that has never appeared in this treasury's policy."""

XRP: Final[CurrencyRef] = "XRP"


@dataclasses.dataclass
class XrplEnvironment:
    """A live testnet treasury, its co-signing key, and a funded counterparty."""

    home: Path
    treasury: str
    destination: str
    agent_wallet: Any
    label: str = "xrpl-testnet"
    amounts: Amounts = XRPL_AMOUNTS
    attacker: str = ATTACKER
    asset: CurrencyRef = XRP
    bootstrap_txs: tuple[str, ...] = ()
    """Populated only on the run that actually bootstrapped the treasury."""

    def policy(self, **overrides: Any) -> PolicyDocument:
        overrides.setdefault("treasury", self.treasury)
        overrides.setdefault("destinations", (self.destination,))
        overrides.setdefault("asset", self.asset)
        overrides.setdefault("rail", "xrpl")
        overrides.setdefault("per_tx_cap", self.amounts.per_tx_cap)
        overrides.setdefault("window", self.amounts.window)
        overrides.setdefault("human_threshold", self.amounts.human_threshold)
        return build_policy(**overrides)

    def rig(self, name: str, policy: PolicyDocument | None = None) -> Rig:
        """A fresh signer state under this run's temp home; the treasury key is shared."""
        from merkl.adapters.signer_dev import LocalSignerClient
        from merkl.adapters.xrpl import XrplSettlementAdapter
        from merkl.sdk.receipts import ReceiptBuilder
        from merkl.signer.engine import SignerEngine
        from merkl.signer.keystore import DevKeystore
        from merkl.signer.risk import StaticRiskScorer
        from merkl.signer.state import SealedStateStore

        document = policy or self.policy()
        signed = sign_policy(document)
        clock = FrozenClock()
        keystore = DevKeystore(SIGNER_HOME / "keystore", passphrase=PASSPHRASE)
        state = SealedStateStore(
            self.home / name / "state", document.treasury, keystore.seal_key()
        )
        engine = SignerEngine(
            policy=signed,
            keystore=keystore,
            state=state,
            clock=clock,
            risk=StaticRiskScorer.of(()),
        )
        rail = XrplSettlementAdapter(
            treasury=document.treasury,
            agent_wallet=self.agent_wallet,
            policy_public_key=keystore.public_key(),
        )
        signer = LocalSignerClient(engine)
        builder = ReceiptBuilder(
            signer=signer,
            settlement=rail,
            agent_id=AGENT_ID,
            agent_public_key=AGENT.public_key,
            agent_sign=AGENT.sign,
            clock=clock,
        )
        return Rig(
            clock=clock,
            engine=engine,
            signer=signer,
            builder=builder,
            rail=rail,
            policy=document,
            signed_policy=signed,
            ledger=None,
        )


async def build_xrpl_environment(home: Path) -> XrplEnvironment:
    """Bootstrap a testnet treasury, or reuse the one cached under ``~/.merkl``."""
    from merkl.adapters.xrpl import (
        TESTNET_JSON_RPC,
        bootstrap_treasury,
        load_wallets,
        verify_treasury,
    )
    from merkl.signer.keystore import DevKeystore

    keystore = DevKeystore(SIGNER_HOME / "keystore", passphrase=PASSPHRASE)
    bootstrap_txs: tuple[str, ...] = ()

    reusable = False
    if TREASURY_FILE.exists():
        cached = json.loads(TREASURY_FILE.read_text())
        report = await verify_treasury(cached["wallets"]["treasury"]["address"])
        reusable = bool(report["safe"]) and bool(cached.get("policy_address"))

    if not reusable:
        setup = await bootstrap_treasury(
            policy_public_key=keystore.public_key(), agent_count=1, wallet_file=TREASURY_FILE
        )
        if not setup.safe:
            raise RuntimeError(f"testnet treasury bootstrap did not come up safe: {setup}")
        bootstrap_txs = (setup.signer_list_tx, setup.disable_master_tx)

    document = json.loads(TREASURY_FILE.read_text())
    wallets = load_wallets(TREASURY_FILE)

    if PARTIES_FILE.exists():
        destination = str(json.loads(PARTIES_FILE.read_text())["destination"]["address"])
    else:
        from xrpl.asyncio.clients import AsyncJsonRpcClient
        from xrpl.asyncio.wallet import generate_faucet_wallet

        wallet = await generate_faucet_wallet(AsyncJsonRpcClient(TESTNET_JSON_RPC), debug=False)
        PARTIES_FILE.parent.mkdir(parents=True, exist_ok=True)
        PARTIES_FILE.write_text(
            json.dumps({"destination": {"seed": wallet.seed, "address": wallet.classic_address}})
        )
        PARTIES_FILE.chmod(0o600)
        destination = str(wallet.classic_address)

    return XrplEnvironment(
        home=home,
        treasury=str(document["wallets"]["treasury"]["address"]),
        destination=destination,
        agent_wallet=wallets["agent-0"],
        bootstrap_txs=bootstrap_txs,
    )


__all__ = [
    "ATTACKER",
    "DEFAULT_HOME",
    "PARTIES_FILE",
    "TREASURY_FILE",
    "XRPL_AMOUNTS",
    "XrplEnvironment",
    "build_xrpl_environment",
]
