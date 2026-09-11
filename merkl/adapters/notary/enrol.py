"""Enrolment — the two calls that make a signer visible in its own dashboard.

``merkl treasury init`` runs on the customer's machine, and everything secret it
makes is born there: the keystore, the treasury's seeds, the agents' request
keys. None of that moves. What *does* move is a description of the public half —
the treasury address, the signer's public key, each agent's id, public key and
address — so the page the customer left open can show them the address to fund
and, later, that the signer list is installed.

Two calls, in this order, because the customer is watching:

``POST /v1/signers/enrol``   as soon as the keys exist, before a single
                             transaction is submitted. The address the page
                             prints comes from here, which is what lets a
                             mainnet init say "fund this, I will wait".
``POST /v1/signers/ready``   after the read-back proves the master key is off.

The enrolment token is spent by the first call and is worth nothing afterwards.
What comes back — the signer token, the agent's API key — is shown once by the
notary and written straight to ``0600`` files; nothing here returns it to a
caller that prints, and nothing here logs.

``P17-CONTRACT.md`` is normative for both bodies.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from merkl.adapters.notary.client import DEFAULT_TIMEOUT_SECONDS, NotaryError
from merkl.core.canonical import JSONObject

ENROLMENT_TOKEN_PREFIX: Final = "enr_"
"""What the dashboard's one-shot enrolment token looks like. Spent by ``enrol``."""

SIGNER_TOKEN_PREFIX: Final = "sgn_"
"""The signer's own bearer, issued by ``enrol`` and kept in ``notary.json``."""

ENROL_PATH: Final = "/v1/signers/enrol"
READY_PATH: Final = "/v1/signers/ready"


class NotaryEnrolError(NotaryError):
    """Enrolment did not complete. Never fatal to the treasury itself.

    A ``NotaryError`` so a caller that already handles "the notary is not
    answering" handles this too, and a distinct class so ``merkl treasury init``
    can tell the operator the one thing that matters: the ledger work is done,
    the keys are safe, and the re-run is a single command.
    """

    error_code = "notary_enrol_error"


@dataclasses.dataclass(frozen=True)
class AgentRecord:
    """One agent, as the notary needs to know it. Public values only."""

    id: str
    public_key: str
    """The raw Ed25519 request key, hex — the same value the policy will carry."""

    address: str
    """The rail account that agent multisigns with."""

    def to_content(self) -> JSONObject:
        return {"id": self.id, "public_key": self.public_key, "address": self.address}

    @classmethod
    def from_content(cls, data: Any) -> AgentRecord:
        return cls(id=data["id"], public_key=data["public_key"], address=data["address"])


@dataclasses.dataclass(frozen=True)
class Enrolment:
    """What the notary answered. Two of these five are secrets shown exactly once."""

    signer_id: str
    org_slug: str
    treasury_url: str
    signer_token: str
    notary_api_key: str

    @classmethod
    def from_content(cls, data: Mapping[str, Any]) -> Enrolment:
        missing = [
            key
            for key in ("signer_id", "org_slug", "treasury_url", "signer_token")
            if not data.get(key)
        ]
        if missing:
            raise NotaryEnrolError(f"the notary's enrolment answer is missing {missing}")
        return cls(
            signer_id=str(data["signer_id"]),
            org_slug=str(data["org_slug"]),
            treasury_url=str(data["treasury_url"]),
            signer_token=str(data["signer_token"]),
            notary_api_key=str(data.get("notary_api_key") or ""),
        )


@dataclasses.dataclass(frozen=True)
class NotaryRecord:
    """``<home>/notary.json`` — where the notary is, and who this signer is to it.

    Written ``0600`` because ``signer_token`` is in it. ``network`` is not in the
    contract's list of members and is written anyway: it is the only thing on
    disk that lets ``merkl signer serve`` refuse a policy for the wrong chain
    when nobody passed ``--rail-endpoint``, and the file is the signer's own.
    """

    url: str
    signer_id: str
    signer_token: str
    org_slug: str
    treasury_url: str
    network: str | None = None

    def to_content(self) -> JSONObject:
        content: JSONObject = {
            "url": self.url,
            "signer_id": self.signer_id,
            "signer_token": self.signer_token,
            "org_slug": self.org_slug,
            "treasury_url": self.treasury_url,
        }
        if self.network is not None:
            content["network"] = self.network
        return content

    @classmethod
    def from_content(cls, data: Any) -> NotaryRecord:
        if not isinstance(data, dict):
            raise NotaryEnrolError("notary.json must hold an object")
        missing = [k for k in ("url", "signer_id", "signer_token") if not data.get(k)]
        if missing:
            raise NotaryEnrolError(f"notary.json is missing {missing}")
        return cls(
            url=str(data["url"]),
            signer_id=str(data["signer_id"]),
            signer_token=str(data["signer_token"]),
            org_slug=str(data.get("org_slug") or ""),
            treasury_url=str(data.get("treasury_url") or ""),
            network=data.get("network") or None,
        )

    @classmethod
    def read(cls, path: Path) -> NotaryRecord | None:
        """The record at ``path``, or ``None`` when this signer follows nobody."""
        if not path.exists():
            return None
        try:
            return cls.from_content(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            raise NotaryEnrolError(f"{path} is not valid JSON: {exc}") from exc

    def write(self, path: Path) -> None:
        """One ``0600`` file, created atomically. It holds a bearer token."""
        write_private(path, json.dumps(self.to_content(), indent=2).encode() + b"\n")


def write_private(path: Path, payload: bytes) -> None:
    """Write a file that is never briefly readable by anyone but this user."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class EnrolClient:
    """The two enrolment calls, synchronous, over ``httpx``.

    Synchronous because its caller is a terminal command that has nothing else
    to do while it waits, and an async client there would be an event loop
    wrapped around one request. ``transport`` exists so the suite can answer
    with an ``httpx.MockTransport`` instead of a socket.
    """

    def __init__(
        self,
        notary_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Any | None = None,
    ) -> None:
        self._url = notary_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    @property
    def url(self) -> str:
        return self._url

    def enrol(
        self,
        enrolment_token: str,
        *,
        treasury: str,
        network: str,
        signer_public_key: str,
        agents: Sequence[AgentRecord],
        required_drops: str,
    ) -> Enrolment:
        """Spend the enrolment token. The address the page shows comes from here."""
        body: JSONObject = {
            "treasury": treasury,
            "network": network,
            "signer_public_key": signer_public_key,
            "agents": [agent.to_content() for agent in agents],
            "required_drops": required_drops,
        }
        return Enrolment.from_content(self._post(ENROL_PATH, body, enrolment_token))

    def ready(
        self,
        signer_token: str,
        *,
        signer_list_tx: str,
        disable_master_tx: str,
        trust_lines: Sequence[JSONObject] = (),
        relay_token: str | None = None,
        agent_bundle: Mapping[str, str] | None = None,
    ) -> JSONObject:
        """Report the read-back: the signer list is installed, the master key is off."""
        body: JSONObject = {
            "signer_list_tx": signer_list_tx,
            "disable_master_tx": disable_master_tx,
            "trust_lines": list(trust_lines),
            "relay_token": relay_token,
            "agent_bundle": {"files": dict(agent_bundle)} if agent_bundle is not None else None,
        }
        return self._post(READY_PATH, body, signer_token)

    # -- wire -------------------------------------------------------------- #

    def _post(self, path: str, body: JSONObject, bearer: str) -> JSONObject:
        import httpx

        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                response = client.post(
                    f"{self._url}{path}",
                    json=body,
                    headers={"Authorization": f"Bearer {bearer}"},
                )
        except httpx.HTTPError as exc:
            raise NotaryEnrolError(
                f"the notary at {self._url} could not be reached: {exc}"
            ) from exc
        if not response.is_success:
            raise NotaryEnrolError(
                f"the notary answered {response.status_code} to POST {path}: "
                f"{_detail(response.text)}"
            )
        try:
            answer = response.json()
        except ValueError as exc:
            raise NotaryEnrolError(f"the notary's answer to POST {path} is not JSON") from exc
        if not isinstance(answer, dict):
            raise NotaryEnrolError(f"the notary's answer to POST {path} is not an object")
        return answer


def _detail(text: str) -> str:
    """A server's complaint, bounded. Never the request we sent, which had a token in it."""
    return text[:200]


__all__ = [
    "ENROLMENT_TOKEN_PREFIX",
    "ENROL_PATH",
    "READY_PATH",
    "SIGNER_TOKEN_PREFIX",
    "AgentRecord",
    "EnrolClient",
    "Enrolment",
    "NotaryEnrolError",
    "NotaryRecord",
    "write_private",
]
