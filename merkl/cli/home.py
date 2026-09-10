"""``$MERKL_HOME`` — the one directory a signer owns, and what is in it.

Before this phase a signer's files were scattered: the keystore under
``--home``, the seeds under ``~/.merkl/xrpl-*.wallets.json``, the relay tokens
under ``--home/relay`` and the policy wherever ``--policy`` pointed. That is
fine on a laptop and wrong in a container, where the whole argument for the
image is *the signer is the image plus one volume* — a file outside the volume
is a file that does not survive ``docker rm``, and a seed outside the volume is
a seed on somebody's host filesystem nobody meant to put there.

So: one home, named by ``$MERKL_HOME`` (the image sets it to
``/var/lib/merkl-signer``, which is the volume), falling back to
``~/.merkl/signer`` exactly as ``--home`` always defaulted. Every command reads
the same default, every file a setup writes lands under it, and the printed
``docker run`` lines need no ``--home`` at all.

The layout::

    <home>/
      keystore/                  the policy key, encrypted at rest
      state/                     the sealed rule state
      relay/relay-tokens.json    who may push at the signer
      wallets.json               0600 — the treasury and agent seeds
      treasury.json              public facts only: addresses, tx hashes, network
      agents/<id>/agent-ed25519.pem   0600 — one request key per agent
      agents/<id>/bundle/        the agent bundle, when no --agent-dir was given
      notary.json                0600 — where the notary is and who we are to it
      policy.signed.json         the policy in force, written by the follower

``treasury.json`` is the only file here that did not exist before, and it holds
nothing secret: it is what lets ``merkl treasury enrol`` re-send an enrolment
that failed after the ledger work was already done, without asking the operator
to remember two transaction hashes.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

MERKL_HOME_ENV: Final = "MERKL_HOME"
"""Names the home directory for every ``merkl`` command that has a ``--home``."""

POLICY_FILE: Final = "policy.signed.json"
NOTARY_FILE: Final = "notary.json"
WALLETS_FILE: Final = "wallets.json"
TREASURY_FILE: Final = "treasury.json"
AGENT_KEY_FILE: Final = "agent-ed25519.pem"

CONTAINER_AGENT_DIR: Final = Path("/agent")
"""Where the image expects the agent bundle to land.

``--agent-dir`` wins; otherwise this is used when it exists, which inside the
container it always does and outside it never does. That is the whole rule:
the printed ``docker run`` line bind-mounts ``./merkl-agent`` onto it, and a
laptop running ``merkl treasury init`` from a checkout falls through to
``<home>/agents/<id>/bundle/`` instead."""


def default_home() -> Path:
    """``$MERKL_HOME`` if set, else ``~/.merkl/signer``."""
    value = os.environ.get(MERKL_HOME_ENV, "").strip()
    if value:
        return Path(value).expanduser()
    return Path.home() / ".merkl" / "signer"


def resolve_home(home: Path | str | None) -> Path:
    """The home a command should use: its ``--home`` flag, else the default."""
    return Path(home) if home is not None else default_home()


def policy_path(home: Path) -> Path:
    return home / POLICY_FILE


def notary_path(home: Path) -> Path:
    return home / NOTARY_FILE


def wallets_path(home: Path) -> Path:
    return home / WALLETS_FILE


def treasury_path(home: Path) -> Path:
    return home / TREASURY_FILE


def agent_home(home: Path, agent_id: str) -> Path:
    return home / "agents" / agent_id


def agent_key_path(home: Path, agent_id: str) -> Path:
    return agent_home(home, agent_id) / AGENT_KEY_FILE


def default_bundle_dir(home: Path, agent_id: str) -> Path:
    """Where the bundle goes when nobody said: the container's ``/agent``, else home."""
    if CONTAINER_AGENT_DIR.is_dir():
        return CONTAINER_AGENT_DIR
    return agent_home(home, agent_id) / "bundle"


__all__ = [
    "AGENT_KEY_FILE",
    "CONTAINER_AGENT_DIR",
    "MERKL_HOME_ENV",
    "NOTARY_FILE",
    "POLICY_FILE",
    "TREASURY_FILE",
    "WALLETS_FILE",
    "agent_home",
    "agent_key_path",
    "default_bundle_dir",
    "default_home",
    "notary_path",
    "policy_path",
    "resolve_home",
    "treasury_path",
    "wallets_path",
]
