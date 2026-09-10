"""The trader's configuration: one TOML file, read once at start.

Everything the agent needs to exist is here, and one thing deliberately is not:
the policy. The agent is told which policy *version* its intents must name, and
nothing about what that policy says. It has no cap, no window and no threshold
written down anywhere it can read, and it never will — it finds out what it may
do by proposing something and reading the refusal. A trader that could read its
own limits would be a trader whose story about staying inside them is worth
nothing.

Secrets are named, never inlined. A key is a path to a file the operator
chmods 0600; an API token is the *name* of an environment variable. Nothing in
this module returns a secret's value except the two loaders at the bottom, and
nothing anywhere in this package prints one.
"""

from __future__ import annotations

import dataclasses
import os
import tomllib
from decimal import Decimal
from pathlib import Path
from typing import Any

WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


class ConfigError(Exception):
    """The configuration is missing something, or says something impossible."""


@dataclasses.dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    key_file: Path
    """PEM-encoded Ed25519 private key. This is the identity the signer
    authenticates; it moves no money on its own."""

    mandate: str
    """The standing instruction. Its hash is leaf 0 of every receipt."""


@dataclasses.dataclass(frozen=True)
class TreasuryConfig:
    address: str
    policy_version: str
    wallet_file: Path
    wallet_name: str


@dataclasses.dataclass(frozen=True)
class RailConfig:
    name: str
    """The settlement family named in every intent, and in the policy. ``xrpl``
    in production; the in-memory rail the tests drive calls itself ``fake``."""

    json_rpc_url: str
    websocket_url: str | None


@dataclasses.dataclass(frozen=True)
class MarketConfig:
    base: str
    """The native asset, always ``XRP`` on this rail."""

    quote_code: str
    quote_issuer: str
    depths: tuple[Decimal, ...]
    """Sizes, in the base asset, to price the book at."""

    reference_url: str
    reference_path: tuple[str, ...]
    """Dotted path to the price inside the reference endpoint's JSON."""

    reference_source: str


@dataclasses.dataclass(frozen=True)
class SignerConfig:
    url: str
    token_file: Path | None


@dataclasses.dataclass(frozen=True)
class NotaryConfig:
    url: str
    api_key_env: str | None = None
    """The *name* of an environment variable holding the API key."""

    api_key_file: Path | None = None
    """A ``0600`` file holding it instead — what ``merkl treasury init`` writes.

    A file rather than an environment variable because the bundle is a folder:
    everything else the agent needs is already a file beside this one, and a
    setup that ends by telling somebody to export a variable ends with the key
    in a shell history. Both work, and the file wins when both are set — an
    operator who put a key in the folder meant that key."""

    def api_key(self) -> str:
        """The key itself. Never logged, never echoed."""
        if self.api_key_file is not None:
            return read_secret_file(self.api_key_file)
        if self.api_key_env:
            return read_secret_env(self.api_key_env)
        raise ConfigError("notary needs either api_key_file or api_key_env")


@dataclasses.dataclass(frozen=True)
class ModelConfig:
    name: str
    api_key_env: str
    max_tokens: int
    usd_per_million_input: Decimal
    usd_per_million_output: Decimal


@dataclasses.dataclass(frozen=True)
class LoopConfig:
    interval_seconds: int
    home: Path

    @property
    def state_file(self) -> Path:
        return self.home / "state.json"

    @property
    def journal_md(self) -> Path:
        return self.home / "journal.md"

    @property
    def journal_jsonl(self) -> Path:
        return self.home / "journal.jsonl"

    @property
    def receipt_dir(self) -> Path:
        return self.home / "receipts"


@dataclasses.dataclass(frozen=True)
class BillConfig:
    bill_day: str
    operator: str


@dataclasses.dataclass(frozen=True)
class Config:
    agent: AgentConfig
    treasury: TreasuryConfig
    rail: RailConfig
    market: MarketConfig
    signer: SignerConfig
    notary: NotaryConfig
    model: ModelConfig
    loop: LoopConfig
    bill: BillConfig


# -- reading ---------------------------------------------------------------- #


def load(path: Path | str) -> Config:
    """Read and validate the whole file. Raises rather than defaulting."""
    try:
        raw = tomllib.loads(Path(path).read_text())
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    return parse(raw)


def parse(raw: dict[str, Any]) -> Config:
    """Build a :class:`Config` from an already-parsed TOML document."""
    agent = _table(raw, "agent")
    treasury = _table(raw, "treasury")
    rail = _table(raw, "rail")
    market = _table(raw, "market")
    signer = _table(raw, "signer")
    notary = _table(raw, "notary")
    model = _table(raw, "model")
    loop = _table(raw, "loop")
    bill = _table(raw, "bill")

    day = _string(bill, "bill_day", "bill").lower()
    if day not in WEEKDAYS:
        raise ConfigError(f"bill.bill_day must be one of {list(WEEKDAYS)}, got {day!r}")

    return Config(
        agent=AgentConfig(
            agent_id=_string(agent, "agent_id", "agent"),
            key_file=_path(agent, "key_file", "agent"),
            mandate=_string(agent, "mandate", "agent"),
        ),
        treasury=TreasuryConfig(
            address=_string(treasury, "address", "treasury"),
            policy_version=_string(treasury, "policy_version", "treasury"),
            wallet_file=_path(treasury, "wallet_file", "treasury"),
            wallet_name=_string(treasury, "wallet_name", "treasury"),
        ),
        rail=RailConfig(
            name=_optional_string(rail, "name") or "xrpl",
            json_rpc_url=_string(rail, "json_rpc_url", "rail"),
            websocket_url=_optional_string(rail, "websocket_url"),
        ),
        market=MarketConfig(
            base=_string(market, "base", "market"),
            quote_code=_string(market, "quote_code", "market"),
            quote_issuer=_string(market, "quote_issuer", "market"),
            depths=_decimals(market, "depths"),
            reference_url=_string(market, "reference_url", "market"),
            reference_path=tuple(_string(market, "reference_path", "market").split(".")),
            reference_source=_string(market, "reference_source", "market"),
        ),
        signer=SignerConfig(
            url=_string(signer, "url", "signer"),
            token_file=_optional_path(signer, "token_file"),
        ),
        notary=_notary(notary),
        model=ModelConfig(
            name=_string(model, "name", "model"),
            api_key_env=_string(model, "api_key_env", "model"),
            max_tokens=_int(model, "max_tokens", "model"),
            usd_per_million_input=_decimal(model, "usd_per_million_input", "model"),
            usd_per_million_output=_decimal(model, "usd_per_million_output", "model"),
        ),
        loop=LoopConfig(
            interval_seconds=_int(loop, "interval_seconds", "loop"),
            home=_path(loop, "home", "loop"),
        ),
        bill=BillConfig(bill_day=day, operator=_string(bill, "operator", "bill")),
    )


def _notary(table: dict[str, Any]) -> NotaryConfig:
    """``[notary]`` — one of the two ways of naming the API key, or a refusal."""
    api_key_file = _optional_path(table, "api_key_file")
    api_key_env = _optional_string(table, "api_key_env")
    if api_key_file is None and api_key_env is None:
        raise ConfigError(
            "notary needs api_key_file (a 0600 file, what `merkl treasury init` writes) "
            "or api_key_env (the name of an environment variable)"
        )
    return NotaryConfig(
        url=_string(table, "url", "notary"),
        api_key_env=api_key_env,
        api_key_file=api_key_file,
    )


# -- secrets ---------------------------------------------------------------- #


def read_secret_file(path: Path) -> str:
    """One line out of a 0600 file. Never logged, never echoed."""
    try:
        return path.expanduser().read_text().strip()
    except OSError as exc:
        raise ConfigError(f"cannot read the secret at {path}: {exc}") from exc


def read_secret_env(name: str) -> str:
    """The value of an environment variable, by name. Never logged, never echoed."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"${name} is not set")
    return value


# -- primitives ------------------------------------------------------------- #


def _table(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"the config needs a [{name}] table")
    return value


def _string(table: dict[str, Any], key: str, owner: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{owner}.{key} must be a non-empty string")
    return value


def _optional_string(table: dict[str, Any], key: str) -> str | None:
    value = table.get(key)
    return value if isinstance(value, str) and value else None


def _int(table: dict[str, Any], key: str, owner: str) -> int:
    value = table.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{owner}.{key} must be a positive integer")
    return value


def _decimal(table: dict[str, Any], key: str, owner: str) -> Decimal:
    """A money-ish number, written as a string. A TOML float would be a bug."""
    value = table.get(key)
    if not isinstance(value, str):
        raise ConfigError(
            f"{owner}.{key} must be a decimal *string* — money never travels as a float"
        )
    try:
        return Decimal(value)
    except ArithmeticError as exc:
        raise ConfigError(f"{owner}.{key} is not a decimal: {value!r}") from exc


def _decimals(table: dict[str, Any], key: str) -> tuple[Decimal, ...]:
    value = table.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"market.{key} must be a non-empty array of decimal strings")
    out = []
    for entry in value:
        if not isinstance(entry, str):
            raise ConfigError(f"market.{key} entries must be decimal strings")
        try:
            out.append(Decimal(entry))
        except ArithmeticError as exc:
            raise ConfigError(f"market.{key} has a non-decimal entry: {entry!r}") from exc
    return tuple(out)


def _path(table: dict[str, Any], key: str, owner: str) -> Path:
    return Path(_string(table, key, owner)).expanduser()


def _optional_path(table: dict[str, Any], key: str) -> Path | None:
    value = _optional_string(table, key)
    return None if value is None else Path(value).expanduser()


__all__ = [
    "AgentConfig",
    "BillConfig",
    "Config",
    "ConfigError",
    "LoopConfig",
    "MarketConfig",
    "ModelConfig",
    "NotaryConfig",
    "RailConfig",
    "SignerConfig",
    "TreasuryConfig",
    "load",
    "parse",
    "read_secret_env",
    "read_secret_file",
]
