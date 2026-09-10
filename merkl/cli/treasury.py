"""``merkl treasury init|enrol|verify`` — set up and check the co-signing account.

Init sets the trust lines, installs the signer list, disables the master key and
then reads the account back to prove both. It refuses to report success
otherwise.

What changed in phase 17 is *where the secrets are born*. This command runs
inside the signer image, on the customer's machine, against the volume the
signer will be served from — so the keystore, the treasury's seeds and each
agent's request key are created in the place they will live and never travel.
Nothing secret is printed, returned to the notary, or written outside ``<home>``
and the agent bundle.

The order matters and it is not the obvious one:

1. keys — the treasury, its agents, and one Ed25519 request key each;
2. **enrol**, before a single transaction, so the page the customer left open
   can show them an address to fund;
3. on mainnet, wait: print the minimum the network itself says the account
   needs, and poll until it is there;
4. the sentence, because disabling a master key on an account with real money in
   it happens once;
5. trust lines, signer list, ``asfDisableMaster``, read-back;
6. **ready**, and the agent bundle.

Testnet is the same path with the faucet instead of steps 3 and 4.

Seeds are written to one ``0600`` file. Nothing here prints one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from merkl.adapters.notary.enrol import (
    AgentRecord,
    EnrolClient,
    Enrolment,
    NotaryEnrolError,
    NotaryRecord,
)
from merkl.cli.bundle import (
    LOCAL_SIGNER_URL,
    AgentBundle,
    build_bundle,
    generate_agent_key,
    read_agent_key,
)
from merkl.cli.home import (
    agent_home,
    agent_key_path,
    default_bundle_dir,
    notary_path,
    resolve_home,
    treasury_path,
    wallets_path,
)
from merkl.core.rail import NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET
from merkl.shared.errors import MerklError
from merkl.signer.keystore import DevKeystore
from merkl.signer.relay_auth import RelayTokenStore

MAINNET_CONFIRMATION = "disable the master key on mainnet"
"""What an operator types to prove they meant it. No flag bypasses this."""

NOTARY_RELAY_TOKEN_ID = "notary"
"""The relay token a managed signer hands merkl-api so it can push to it."""

EXIT_NO_EXTRA = 2
EXIT_NETWORK = 3
EXIT_UNSAFE = 4
EXIT_NOT_CONFIRMED = 5
EXIT_NOT_ENROLLED = 7
"""The treasury is installed and safe; the notary does not know about it yet.

Its own code because it is the one failure where the right next step is a single
re-run rather than anything on the ledger — and because a caller that treats
every non-zero exit as "start over" would, here, start over on an account whose
master key is already off."""


@dataclasses.dataclass(frozen=True)
class TreasuryRecord:
    """``<home>/treasury.json`` — the public facts about what init installed.

    Public in full: addresses, public keys, transaction hashes. It exists so
    ``merkl treasury enrol`` can re-send an enrolment that failed *after* the
    ledger work, without asking an operator to remember two transaction hashes,
    and so ``merkl signer token add --env`` knows which treasury it is naming.
    """

    treasury: str
    network: str
    json_rpc_url: str
    signer_public_key: str
    agents: tuple[AgentRecord, ...]
    required_drops: str
    signer_list_tx: str = ""
    disable_master_tx: str = ""
    trust_lines: tuple[dict[str, Any], ...] = ()

    @property
    def installed(self) -> bool:
        """True once the signer list is on the ledger and the master key is off."""
        return bool(self.signer_list_tx and self.disable_master_tx)

    def to_content(self) -> dict[str, Any]:
        return {
            "treasury": self.treasury,
            "network": self.network,
            "json_rpc_url": self.json_rpc_url,
            "signer_public_key": self.signer_public_key,
            "agents": [a.to_content() for a in self.agents],
            "required_drops": self.required_drops,
            "signer_list_tx": self.signer_list_tx,
            "disable_master_tx": self.disable_master_tx,
            "trust_lines": list(self.trust_lines),
        }

    @classmethod
    def from_content(cls, data: Any) -> TreasuryRecord:
        return cls(
            treasury=data["treasury"],
            network=data["network"],
            json_rpc_url=data.get("json_rpc_url", ""),
            signer_public_key=data.get("signer_public_key", ""),
            agents=tuple(AgentRecord.from_content(a) for a in data.get("agents", [])),
            required_drops=str(data.get("required_drops", "0")),
            signer_list_tx=data.get("signer_list_tx", ""),
            disable_master_tx=data.get("disable_master_tx", ""),
            trust_lines=tuple(data.get("trust_lines", [])),
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_content(), indent=2) + "\n")

    @classmethod
    def read(cls, path: Path) -> TreasuryRecord | None:
        if not path.exists():
            return None
        return cls.from_content(json.loads(path.read_text()))


def init_command(
    *,
    home: Path | None = None,
    agents: int = 1,
    wallet_file: Path | None = None,
    json_rpc_url: str | None = None,
    network: str = NETWORK_XRPL_TESTNET,
    trust: tuple[str, ...] = (),
    enrol: str | None = None,
    notary: str | None = None,
    confirm: str | None = None,
    agent_dir: Path | None = None,
    bundle_to_notary: bool = False,
    interactive: bool = True,
) -> int:
    """Bootstrap a treasury against this machine's signer key."""
    try:
        from merkl.adapters.xrpl import (
            MAINNET_JSON_RPC,
            TESTNET_JSON_RPC,
            TrustLine,
            XrplAdapterError,
            await_funding,
            create_wallets,
            install_signer_list,
            read_reserves,
        )
    except ImportError:
        print("the xrpl extra is not installed: pip install 'merkl-sdk[xrpl]'", file=sys.stderr)
        return EXIT_NO_EXTRA

    home = resolve_home(home)
    mainnet = network == NETWORK_XRPL_MAINNET
    endpoint = json_rpc_url or (MAINNET_JSON_RPC if mainnet else TESTNET_JSON_RPC)
    if enrol and not notary:
        print("--enrol needs --notary <url>", file=sys.stderr)
        return EXIT_NO_EXTRA

    try:
        lines = tuple(TrustLine.parse(entry) for entry in trust)
    except XrplAdapterError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_NO_EXTRA

    if mainnet and not interactive and confirm != MAINNET_CONFIRMATION:
        print(
            f"mainnet needs --confirm {MAINNET_CONFIRMATION!r}; there is nobody here to ask",
            file=sys.stderr,
        )
        return EXIT_NOT_CONFIRMED

    keystore = DevKeystore(home / "keystore")

    reserves = None
    required_drops = 0
    try:
        reserves = asyncio.run(read_reserves(endpoint))
        required_drops = reserves.minimum_drops(len(lines))
    except Exception as exc:  # noqa: BLE001 - a node that will not answer is a stop, not a crash
        if mainnet:
            print(f"could not read the network's reserves from {endpoint}: {exc}", file=sys.stderr)
            return EXIT_NETWORK

    if mainnet:
        print(f"XRPL MAINNET — {endpoint}")
        print()
        print("  This will permanently disable the treasury's master key. After it runs,")
        print("  nothing moves out of that account without the policy signer.")
        print()
    else:
        print(f"XRPL TESTNET — {endpoint}")
        print("  funding the treasury and its agent accounts from the faucet…")
    for asset in lines:
        print(f"  trust line            {asset.code}.{asset.issuer} limit {asset.limit}")

    # -- 1. the keys, all of them, here -------------------------------------- #
    try:
        keys = asyncio.run(
            create_wallets(
                policy_public_key=keystore.public_key(),
                agent_count=agents,
                json_rpc_url=endpoint,
                wallet_file=wallet_file or wallets_path(home),
                network=network,
            )
        )
    except XrplAdapterError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return EXIT_NETWORK

    agent_records = _agent_keys(home, keys.addresses())
    record = TreasuryRecord(
        treasury=keys.address,
        network=network,
        json_rpc_url=endpoint,
        signer_public_key=keystore.public_key(),
        agents=agent_records,
        required_drops=str(required_drops),
        trust_lines=tuple(_line_content(line) for line in lines),
    )
    record.write(treasury_path(home))

    print()
    print(f"  treasury        {record.treasury}")
    for agent in record.agents:
        print(f"  {agent.id:<15} {agent.address}  (weight 1)")
    print(f"  policy signer   {keys.policy_address}")

    # -- 2. enrol, before anything is submitted ------------------------------ #
    enrolment: Enrolment | None = None
    problem = None
    if enrol and notary:
        enrolment, problem = _enrol(EnrolClient(notary), enrol, record, home=home, network=network)
        if enrolment is not None:
            print(f"  enrolled        {enrolment.signer_id} at {notary}")
        else:
            print(f"  NOT ENROLLED    {problem}", file=sys.stderr)

    # -- 3. money -------------------------------------------------------------#
    if mainnet and reserves is not None:
        print()
        for row in reserves.explain(len(lines)):
            print(row)
        print()
        print(f"  Send at least that much XRP to {record.treasury}, then this continues.")
        try:
            balance = asyncio.run(
                await_funding(
                    record.treasury,
                    required_drops,
                    endpoint,
                    on_poll=_funding_line,
                )
            )
        except KeyboardInterrupt:  # pragma: no cover - a terminal, not a test
            print("\n  stopped waiting; nothing was submitted. Re-run this when it is funded.")
            return EXIT_NETWORK
        print(f"\n  funded          {balance} drops")

    # -- 4. the sentence ------------------------------------------------------#
    if mainnet and confirm != MAINNET_CONFIRMATION:
        if not interactive:  # pragma: no cover - checked at the top of the command
            return EXIT_NOT_CONFIRMED
        typed = input(f"Type '{MAINNET_CONFIRMATION}' to continue: ").strip()
        if typed != MAINNET_CONFIRMATION:
            print("not confirmed; nothing was submitted", file=sys.stderr)
            return EXIT_NOT_CONFIRMED

    # -- 5. the ledger work ---------------------------------------------------#
    try:
        setup = asyncio.run(install_signer_list(keys, json_rpc_url=endpoint, trust_lines=lines))
    except XrplAdapterError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return EXIT_NETWORK

    record = dataclasses.replace(
        record,
        signer_list_tx=setup.signer_list_tx,
        disable_master_tx=setup.disable_master_tx,
    )
    record.write(treasury_path(home))

    print(f"  quorum          {setup.quorum}")
    print(f"  master disabled {setup.master_disabled}")
    print(f"  regular key     {setup.regular_key or 'none'}")
    print(f"  signer list tx  {setup.signer_list_tx}")
    print(f"  disable master  {setup.disable_master_tx}")
    for asset in setup.trust_lines:
        print(f"  trust line      {asset.code}.{asset.issuer}")
    print(f"  policy.network  {setup.network}")
    print(f"  seeds           {setup.wallet_file} (0600, never commit this)")

    if not setup.safe:
        print()
        print("  NOT SAFE — see above.")
        return EXIT_UNSAFE

    # -- 6. the bundle, and ready --------------------------------------------#
    code = _finish(
        home=home,
        record=record,
        keys_wallet_file=Path(setup.wallet_file),
        enrolment=enrolment,
        notary=notary,
        agent_dir=agent_dir,
        bundle_to_notary=bundle_to_notary,
        setup_trust_lines=[_line_content(line) for line in setup.trust_lines],
        enrol_token=enrol,
    )
    if enrol and enrolment is None and code == 0:
        _explain_rerun(enrol, notary, problem)
        return EXIT_NOT_ENROLLED
    return code


def enrol_command(
    *,
    home: Path | None = None,
    enrol: str,
    notary: str,
    agent_dir: Path | None = None,
    bundle_to_notary: bool = False,
) -> int:
    """``merkl treasury enrol`` — re-send enrol and ready from what is on disk.

    The one command for the one failure this setup can have that leaves nothing
    to undo: the ledger work succeeded, the keys are safe, and the notary did not
    hear about it. Everything it sends is read back from ``<home>``, so it needs
    no arguments but the token and the URL.
    """
    home = resolve_home(home)
    record = TreasuryRecord.read(treasury_path(home))
    if record is None:
        print(
            f"no treasury at {treasury_path(home)} — run `merkl treasury init` first",
            file=sys.stderr,
        )
        return EXIT_NO_EXTRA

    enrolment, problem = _enrol(
        EnrolClient(notary), enrol, record, home=home, network=record.network
    )
    if enrolment is None:
        print(f"enrolment failed: {problem}", file=sys.stderr)
        return EXIT_NOT_ENROLLED
    print(f"  enrolled        {enrolment.signer_id} at {notary}")

    if not record.installed:
        print("  the signer list is not installed yet; `ready` will follow when it is")
        return 0

    return _finish(
        home=home,
        record=record,
        keys_wallet_file=wallets_path(home),
        enrolment=enrolment,
        notary=notary,
        agent_dir=agent_dir,
        bundle_to_notary=bundle_to_notary,
        setup_trust_lines=list(record.trust_lines),
        enrol_token=enrol,
    )


def verify_command(treasury: str, *, json_rpc_url: str | None = None) -> int:
    """Read an existing treasury's flags and signer list."""
    try:
        from merkl.adapters.xrpl import TESTNET_JSON_RPC, verify_treasury
    except ImportError:
        print("the xrpl extra is not installed: pip install 'merkl-sdk[xrpl]'", file=sys.stderr)
        return EXIT_NO_EXTRA
    report = asyncio.run(verify_treasury(treasury, json_rpc_url or TESTNET_JSON_RPC))
    print(json.dumps(report, indent=2))
    return 0 if report["safe"] else EXIT_UNSAFE


# -- the parts ---------------------------------------------------------------- #


def _agent_keys(home: Path, addresses: tuple[str, ...]) -> tuple[AgentRecord, ...]:
    """One Ed25519 request key per agent, under ``<home>/agents/<id>/``.

    Generated when absent and read when present, so a re-run against an existing
    home does not hand the policy a public key the agent no longer has.
    """
    records = []
    for index, address in enumerate(addresses):
        agent_id = f"agent-{index}"
        path = agent_key_path(home, agent_id)
        if path.exists():
            _, public = read_agent_key(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            _, public = generate_agent_key(path)
        records.append(AgentRecord(id=agent_id, public_key=public, address=address))
    return tuple(records)


def _enrol(
    client: EnrolClient,
    token: str,
    record: TreasuryRecord,
    *,
    home: Path,
    network: str,
) -> tuple[Enrolment | None, str | None]:
    """Spend the enrolment token and write ``notary.json``. Never raises."""
    try:
        enrolment = client.enrol(
            token,
            treasury=record.treasury,
            network=network,
            signer_public_key=record.signer_public_key,
            agents=record.agents,
            required_drops=record.required_drops,
        )
    except (NotaryEnrolError, MerklError) as exc:
        return None, str(exc)
    NotaryRecord(
        url=client.url,
        signer_id=enrolment.signer_id,
        signer_token=enrolment.signer_token,
        org_slug=enrolment.org_slug,
        treasury_url=enrolment.treasury_url,
        network=network,
    ).write(notary_path(home))
    return enrolment, None


def _finish(
    *,
    home: Path,
    record: TreasuryRecord,
    keys_wallet_file: Path,
    enrolment: Enrolment | None,
    notary: str | None,
    agent_dir: Path | None,
    bundle_to_notary: bool,
    setup_trust_lines: list[dict[str, Any]],
    enrol_token: str | None,
) -> int:
    """Relay tokens, the bundles, ``ready``, and the last four lines of output."""
    from merkl.adapters.xrpl import MAINNET_WEBSOCKET, TESTNET_WEBSOCKET, load_wallets

    mainnet = record.network == NETWORK_XRPL_MAINNET
    websocket = MAINNET_WEBSOCKET if mainnet else TESTNET_WEBSOCKET
    store = RelayTokenStore(home / "relay")

    seeds = load_wallets(keys_wallet_file)
    signer_url = LOCAL_SIGNER_URL
    if bundle_to_notary and enrolment is not None:
        signer_url = _public_url(notary, enrolment.signer_id)

    bundles: list[tuple[AgentBundle, Path]] = []
    for agent in record.agents:
        wallet = seeds.get(agent.id)
        if wallet is None:  # pragma: no cover - the seed file is written by create_wallets
            print(f"  {keys_wallet_file} has no wallet for {agent.id}", file=sys.stderr)
            return EXIT_NETWORK
        bundle = build_bundle(
            agent_id=agent.id,
            treasury=record.treasury,
            agent_key_pem=agent_key_path(home, agent.id).read_text(),
            agent_wallet={"seed": wallet.seed, "address": str(wallet.classic_address)},
            network=record.network,
            json_rpc_url=record.json_rpc_url,
            websocket_url=websocket,
            signer_url=signer_url,
            notary_url=notary or "https://api.merkl.ai",
            relay_token=_fresh_token(store, agent.id),
            notary_api_key=enrolment.notary_api_key if enrolment else None,
        )
        bundles.append((bundle, _bundle_dir(home, agent.id, agent_dir, len(record.agents))))

    written = [bundle.write(where) for bundle, where in bundles]

    relay_token = _fresh_token(store, NOTARY_RELAY_TOKEN_ID) if bundle_to_notary else None
    code = 0
    if enrolment is not None:
        try:
            EnrolClient(notary or "").ready(
                enrolment.signer_token,
                signer_list_tx=record.signer_list_tx,
                disable_master_tx=record.disable_master_tx,
                trust_lines=setup_trust_lines,
                relay_token=relay_token,
                agent_bundle=bundles[0][0].files if bundle_to_notary else None,
            )
            print("  ready           reported to the notary")
        except (NotaryEnrolError, MerklError) as exc:
            print(f"  NOT READY       {exc}", file=sys.stderr)
            _explain_rerun(enrol_token, notary, str(exc))
            code = EXIT_NOT_ENROLLED

    print()
    print(f"  treasury        {record.treasury}")
    print(f"  signer key      {record.signer_public_key}")
    for where in written:
        print(f"  agent bundle    {where}")
    print()
    print("  This treasury can only pay through the signer list, and no set of agent keys")
    print("  reaches quorum without the policy key.")
    if enrolment is not None:
        print()
        print(f"  Continue at {enrolment.treasury_url}")
    else:
        print()
        print("  Write a policy whose network is " + record.network + ", sign it with")
        print("  `merkl policy sign`, and point the signer at it.")
    return code


def _bundle_dir(home: Path, agent_id: str, agent_dir: Path | None, count: int) -> Path:
    """Where one agent's bundle goes.

    ``--agent-dir`` names the folder for *the* agent when there is one, which is
    the case the printed ``docker run`` line covers. With more than one, each
    gets a subdirectory of it: two agents sharing a folder would share a wallet
    file and a request key, which is the one thing the multisig arrangement
    exists to prevent.
    """
    if agent_dir is None:
        return default_bundle_dir(home, agent_id) if count == 1 else agent_home(home, agent_id)
    return agent_dir if count == 1 else agent_dir / agent_id


def _fresh_token(store: RelayTokenStore, token_id: str) -> str:
    """A relay bearer for one id, replacing any earlier one of the same name.

    Replacing rather than reusing, because only the SHA-256 of a token is on
    disk: an id that already exists is one whose secret nobody here can recover,
    and a bundle carrying a token the signer will not accept is worse than a
    revoked one.
    """
    store.revoke(token_id)
    return store.add(token_id)


def _public_url(notary: str | None, signer_id: str) -> str:
    base = (notary or "https://api.merkl.ai").rstrip("/")
    return f"{base}/signers/{signer_id}"


def _line_content(line: Any) -> dict[str, Any]:
    """A trust line in the notary's vocabulary: ``currency``, not ``code``."""
    return {"currency": line.code, "issuer": line.issuer}


def _funding_line(drops: int | None) -> None:
    if drops is None:
        print("  waiting          the account does not exist yet", end="\r")
    else:
        print(f"  waiting          {drops} drops so far", end="\r")


def _explain_rerun(token: str | None, notary: str | None, problem: str | None) -> None:
    """The treasury is safe and the notary does not know. Say the one command."""
    print(file=sys.stderr)
    print(
        "  The treasury is installed and safe — nothing on the ledger needs redoing.",
        file=sys.stderr,
    )
    if problem:
        print(f"  What failed: {problem}", file=sys.stderr)
    print("  Re-run just the enrolment when the notary is back:", file=sys.stderr)
    print(file=sys.stderr)
    print(f"    merkl treasury enrol --enrol {token} --notary {notary}", file=sys.stderr)
    print(file=sys.stderr)


__all__ = [
    "EXIT_NOT_ENROLLED",
    "MAINNET_CONFIRMATION",
    "TreasuryRecord",
    "enrol_command",
    "init_command",
    "verify_command",
]
