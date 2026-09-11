"""The agent bundle — the five files an agent process needs, and nothing else.

``merkl treasury init`` makes the treasury, and the treasury is no use to
anybody until something can propose payments against it. That something needs
five things: a config, its own request key, the one wallet it multisigns with,
a relay bearer for the signer, and an API key for the notary. Every one of them
is created by ``init``, in the same run, on the same machine — which is the
whole argument of this phase. A setup that ends with "now generate an Ed25519
key, chmod it 600, and write a TOML file" ends, in practice, with a key in
somebody's Downloads folder.

::

    merkl-agent/
      trader.toml           the config, filled in from the shipped example
      agent-ed25519.pem     0600 — this agent's request key
      wallet.json           0600 — this agent's wallet, and no other
      relay-token.txt       0600 — the signer bearer, this agent's own
      notary-api-key.txt    0600 — the org API key minted at enrolment

Two rules about the contents:

* **paths inside ``trader.toml`` are relative**, so the folder can be moved,
  bind-mounted or downloaded from the dashboard and still describe itself. A
  managed signer's bundle never had a path on the customer's disk to begin with.
* **``wallet.json`` holds one wallet.** The seed file under ``<home>`` holds the
  treasury's seed as well, and the treasury's seed is the one thing an agent
  must never be handed: the master key is disabled, but a seed is a seed and
  ``merkl treasury init`` is not in the business of copying one into a folder it
  tells people to bind-mount.

``trader.toml`` is ``examples/trader/config.example.toml`` with values
substituted line by line, deliberately rather than regenerated: that file's
comments are half of what it teaches, and a generated config would drop them the
first time somebody read one.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from pathlib import Path
from typing import Any, Final

TRADER_CONFIG: Final = "trader.toml"
AGENT_KEY: Final = "agent-ed25519.pem"
AGENT_WALLET: Final = "wallet.json"
RELAY_TOKEN: Final = "relay-token.txt"
NOTARY_API_KEY: Final = "notary-api-key.txt"

SECRET_FILES: Final = frozenset({AGENT_KEY, AGENT_WALLET, RELAY_TOKEN, NOTARY_API_KEY})
"""Everything in a bundle but the config is a secret and is written ``0600``."""

POLICY_VERSION_PLACEHOLDER: Final = "<set this after you publish>"
"""What ``treasury.policy_version`` says until the first policy exists.

The agent has to name a version in every intent and the signer refuses one that
does not match, so a config that guessed would produce a run of denials nobody
could read. Saying so in the file is the honest form of "not yet"."""

LOCAL_SIGNER_URL: Final = "http://127.0.0.1:8787"
"""Where a self-hosted signer is, from the agent's point of view: the published
port of the container the customer just started on their own machine."""


class BundleError(Exception):
    """The bundle could not be built — usually a template that is not there."""


def template_path() -> Path:
    """``examples/trader/config.example.toml``, wherever this install put it.

    The wheel force-includes it beside this module (``pyproject.toml``), so a
    ``pip install merkl-sdk`` has it and so does the signer image. A checkout
    running from source falls back to the file itself, which is the *same* file
    — there is one copy in the repository and the build moves it, so the example
    a customer reads and the template ``init`` fills in cannot drift.
    """
    packaged = Path(__file__).with_name("trader.example.toml")
    if packaged.exists():
        return packaged
    checkout = Path(__file__).resolve().parents[2] / "examples" / "trader" / "config.example.toml"
    if checkout.exists():
        return checkout
    raise BundleError(  # pragma: no cover - a broken install, not a supported state
        "the trader config template is missing from this install; expected it at "
        f"{packaged} or {checkout}"
    )


def fill_template(template: str, values: dict[tuple[str, str], str]) -> str:
    """Substitute ``table.key = …`` lines in a TOML document, keeping everything else.

    ``values`` maps ``(table, key)`` to the *whole* replacement line, so a
    substitution may also rename the key — which is how ``api_key_env`` becomes
    ``api_key_file`` when enrolment produced one. A key the template does not
    have is a programming error here, not a silent no-op, so unmatched entries
    raise.
    """
    table = ""
    out: list[str] = []
    seen: set[tuple[str, str]] = set()
    for line in template.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            table = stripped[1:-1]
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if key and (table, key) in values:
            seen.add((table, key))
            out.append(values[(table, key)])
            continue
        out.append(line)
    missing = sorted(set(values) - seen)
    if missing:
        raise BundleError(f"the trader template has no {missing} to fill in")
    return "\n".join(out) + "\n"


@dataclasses.dataclass(frozen=True)
class AgentBundle:
    """The files, as text, before anybody decides where they go.

    A value object rather than a directory writer, because the same bundle goes
    two places: onto the customer's disk under ``--agent-dir``, or into
    ``POST /v1/signers/ready`` for a managed signer, where the dashboard hands
    it over once. One builder, two destinations, no second idea of what a bundle
    contains.
    """

    agent_id: str
    files: dict[str, str]

    def write(self, directory: Path) -> Path:
        """Write every file, secrets at ``0600``, and return the directory."""
        directory.mkdir(parents=True, exist_ok=True)
        for name, text in sorted(self.files.items()):
            path = directory / name
            if name in SECRET_FILES:
                _write_private(path, text.encode())
            else:
                path.write_text(text)
        return directory

    def secret_names(self) -> tuple[str, ...]:
        return tuple(sorted(name for name in self.files if name in SECRET_FILES))


def build_bundle(
    *,
    agent_id: str,
    treasury: str,
    agent_key_pem: str,
    agent_wallet: dict[str, Any],
    network: str,
    json_rpc_url: str,
    websocket_url: str | None,
    signer_url: str = LOCAL_SIGNER_URL,
    notary_url: str,
    relay_token: str | None = None,
    notary_api_key: str | None = None,
    mandate: str | None = None,
) -> AgentBundle:
    """Fill the template in and gather the files. Nothing is written here."""
    values: dict[tuple[str, str], str] = {
        ("agent", "agent_id"): f'agent_id = "{agent_id}"',
        ("agent", "key_file"): f'key_file = "{AGENT_KEY}"',
        ("treasury", "address"): f'address = "{treasury}"',
        ("treasury", "policy_version"): f'policy_version = "{POLICY_VERSION_PLACEHOLDER}"',
        ("treasury", "wallet_file"): f'wallet_file = "{AGENT_WALLET}"',
        ("treasury", "wallet_name"): f'wallet_name = "{agent_id}"',
        ("rail", "json_rpc_url"): f'json_rpc_url = "{json_rpc_url}"',
        ("signer", "url"): f'url = "{signer_url}"',
        ("notary", "url"): f'url = "{notary_url}"',
    }
    values[("rail", "websocket_url")] = (
        f'websocket_url = "{websocket_url}"'
        if websocket_url
        else '# websocket_url = ""  # ledger inclusion is reported unchecked without one'
    )
    values[("signer", "token_file")] = (
        f'token_file = "{RELAY_TOKEN}"'
        if relay_token
        else '# token_file = "relay-token.txt"  # this signer has no relay tokens configured'
    )
    values[("notary", "api_key_env")] = (
        f'api_key_file = "{NOTARY_API_KEY}"' if notary_api_key else 'api_key_env = "MERKL_API_KEY"'
    )
    if mandate is not None:  # pragma: no cover - reserved for a future --mandate
        values[("agent", "mandate")] = f"mandate = {json.dumps(mandate)}"

    files = {
        TRADER_CONFIG: fill_template(template_path().read_text(), values),
        AGENT_KEY: agent_key_pem,
        AGENT_WALLET: json.dumps(
            {
                "network": json_rpc_url,
                "policy_network": network,
                "wallets": {agent_id: agent_wallet},
            },
            indent=2,
        )
        + "\n",
    }
    if relay_token:
        files[RELAY_TOKEN] = relay_token + "\n"
    if notary_api_key:
        files[NOTARY_API_KEY] = notary_api_key + "\n"
    return AgentBundle(agent_id=agent_id, files=files)


def generate_agent_key(path: Path) -> tuple[str, str]:
    """A fresh Ed25519 request key at ``path`` (``0600``): its PEM, and its public hex.

    The public half is what the policy's agent section carries and what leaf 1
    of every receipt names, so it is returned; the private half is written and
    never returned as anything but the PEM the bundle copies, which the caller
    puts straight into a ``0600`` file and never prints.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    _write_private(path, pem.encode())
    return pem, public


def read_agent_key(path: Path) -> tuple[str, str]:
    """An existing agent key: its PEM and its public hex. Used by ``treasury enrol``."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = path.read_text()
    loaded = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(loaded, ed25519.Ed25519PrivateKey):
        raise BundleError(f"{path} is not an Ed25519 private key")
    public = (
        loaded.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return pem, public


def _write_private(path: Path, payload: bytes) -> None:
    """Write a file that is never briefly readable by anyone but this user."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)


__all__ = [
    "AGENT_KEY",
    "AGENT_WALLET",
    "LOCAL_SIGNER_URL",
    "NOTARY_API_KEY",
    "POLICY_VERSION_PLACEHOLDER",
    "RELAY_TOKEN",
    "SECRET_FILES",
    "TRADER_CONFIG",
    "AgentBundle",
    "BundleError",
    "build_bundle",
    "fill_template",
    "generate_agent_key",
    "read_agent_key",
    "template_path",
]
