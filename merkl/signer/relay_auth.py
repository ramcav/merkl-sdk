"""Relay bearer tokens — who may call anything on the signer but ``propose``.

``propose`` carries its own authentication: an agent-signed request the signer
checks against the key in the policy document (plan D15, ``merkl.signer.auth``).
Every other method — ``approve``, ``reject``, ``policy_update``, ``settle``,
``release``, even ``health`` — has no signature of its own, and today anything
that can reach the socket or the URL can call them. That is a real access
control when the transport is a Unix socket at mode ``0600``, and nothing at all
the moment the signer is reachable any other way — a loopback TCP port, or the
Nitro parent's HTTP relay.

A relay token is **not a fund-moving secret**. Nobody can authorize a payment by
holding one: that is what leaf 1's agent signature and the policy's admin
signature are for. What a relay token bounds is who may *push* things at the
signer — resolve escalations, replace the policy, ask it to settle or release a
reservation — and it stops an unauthenticated caller from flooding the RPC with
those calls. Losing one is an availability incident, not a theft.

Only the SHA-256 of each token is ever stored, so a stolen config file does not
hand over a usable credential. A token is ``"<id>:<secret>"`` — the id is a
plain label the operator chose (``"ci"``, ``"dashboard-relay"``) and is not
secret; carrying it in the clear is what lets a failure name the id
("the 'ci' token did not verify") without ever naming the token itself.

**The signer writes to no stream, this module included** (``tests/signer/test_signer_purity.py``
enforces it across ``merkl/signer/``) — a process that holds a key does not log,
because anywhere it could format a message is somewhere a secret could leak, and
that holds whether or not this particular message would have been safe. So a
failure here is *raised*, not logged: :class:`RelayAuthError`'s message names the
token id, and it travels back to the caller as the RPC error response exactly
like any other failure the signer reports — the same mechanism
``docs/SIGNER-RPC.md`` already documents for ``signer_auth_error``. Whether
*that* gets written to a log is a decision for whatever is on the other end of
the socket, which is outside this boundary.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Final

from merkl.core.canonical import ContentError, JSONObject, token
from merkl.shared.errors import MerklError

RELAY_TOKENS_FILE: Final = "relay-tokens.json"
RELAY_TOKENS_FORMAT: Final = "merkl-relay-tokens-v1"
TOKEN_SECRET_BYTES: Final = 24
"""192 bits of secret, hex-encoded — plenty for a bearer credential."""


class RelayAuthError(MerklError):
    """Raised when a relay call is not authenticated.

    Same error code as an agent-request auth failure (``signer_auth_error``,
    HTTP 401) — a caller of the RPC has one thing to catch either way — but a
    distinct class, because the two are checking different things: this is
    "may you call this method at all", not "does the payload's decision hold".
    """

    error_code = "signer_auth_error"


@dataclasses.dataclass(frozen=True)
class RelayToken:
    """One credential a signer will accept as a relay caller.

    ``token_sha256`` is the SHA-256 of the *whole* bearer token
    (``"<id>:<secret>"``, hex, lowercase) — never the secret alone and never
    reversible, so the config file on disk is a list of things to check a
    presented token against, not a list of credentials.
    """

    id: str
    token_sha256: str

    def __post_init__(self) -> None:
        token(self.id, "relay_token.id", max_length=128)
        if ":" in self.id:
            raise ContentError("relay_token.id must not contain ':' — it prefixes the token")
        digest = self.token_sha256
        is_hex = digest == digest.lower() and all(c in "0123456789abcdef" for c in digest)
        if len(digest) != 64 or not is_hex:
            raise ContentError("relay_token.token_sha256 must be 64 lowercase hex characters")

    def to_content(self) -> JSONObject:
        return {"id": self.id, "token_sha256": self.token_sha256}

    @classmethod
    def from_content(cls, data: Any) -> RelayToken:
        if not isinstance(data, dict):
            raise ContentError(f"a relay token must be an object, got {type(data).__name__}")
        unknown = sorted(set(data) - {"id", "token_sha256"})
        if unknown:
            raise ContentError(f"relay_token has unknown members: {unknown}")
        for key in ("id", "token_sha256"):
            if key not in data:
                raise ContentError(f"relay_token requires {key}")
        return cls(id=data["id"], token_sha256=data["token_sha256"])


def bearer_from_authorization(header: str | None) -> str | None:
    """Pull the token out of an ``Authorization: Bearer <token>`` header value.

    Shared by the dev signer's HTTP handler and the Nitro parent proxy, so the
    two transports parse the same header the same way — and so the proxy can
    lift the token back out to forward it, unchanged, over vsock (see
    ``nitro/parent/proxy.py``).
    """
    if header is None:
        return None
    scheme, sep, token_value = header.partition(" ")
    if not sep or scheme.lower() != "bearer" or not token_value:
        return None
    return token_value


def hash_token(bearer: str) -> str:
    """SHA-256 of the whole bearer string, lowercase hex."""
    return hashlib.sha256(bearer.encode()).hexdigest()


def generate_token(token_id: str) -> str:
    """A fresh ``"<id>:<secret>"`` bearer token. Shown to the operator exactly once."""
    return f"{token_id}:{secrets.token_hex(TOKEN_SECRET_BYTES)}"


def find_token_id(bearer: str, tokens: tuple[RelayToken, ...]) -> str | None:
    """The id of the configured token this bearer matches, or ``None``.

    Looked up by the id prefix of the bearer itself rather than by scanning
    every configured hash, and checked with :func:`hmac.compare_digest` so a
    wrong secret for the right id takes the same time as a right one — the
    only comparison an attacker who already knows a valid id could time.
    """
    candidate_id, sep, _secret = bearer.partition(":")
    if not sep:
        return None
    digest = hash_token(bearer)
    for entry in tokens:
        if entry.id == candidate_id:
            return entry.id if hmac.compare_digest(entry.token_sha256, digest) else None
    return None


def require_relay_bearer(tokens: tuple[RelayToken, ...], bearer: str | None, method: str) -> None:
    """Enforce the relay credential for one RPC method, or raise.

    Configuring no relay tokens at all leaves the signer exactly as it behaved
    before this phase — open to anything that can reach the transport, bounded
    only by socket file permissions or the caller's network. That is a
    deliberate downgrade path (a signer upgraded from an earlier phase keeps
    working unmodified) rather than a silent hole: the moment an operator adds
    one token, every method but ``propose`` starts requiring a bearer.
    """
    if not tokens:
        return
    if bearer is None:
        raise RelayAuthError(f"{method!r} requires Authorization: Bearer <token>")
    if find_token_id(bearer, tokens) is None:
        candidate_id = bearer.partition(":")[0] or "(malformed)"
        raise RelayAuthError(
            f"the {candidate_id!r} bearer token does not match a relay credential this "
            "signer holds"
        )


def _write_private(path: Path, payload: bytes) -> None:
    """Write a file that is never briefly readable by anyone but this user."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class RelayTokenStore:
    """The relay token config, on disk as SHA-256 digests only.

    Backs ``merkl signer token add|revoke|list``. A directory rather than a bare
    file, so it sits beside the keystore and state directories a signer already
    owns (``~/.merkl/signer`` by default).
    """

    def __init__(self, directory: Path | str) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / RELAY_TOKENS_FILE

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> tuple[RelayToken, ...]:
        if not self._path.exists():
            return ()
        try:
            document = json.loads(self._path.read_text())
        except json.JSONDecodeError as exc:
            raise ContentError(f"{self._path} is not valid JSON") from exc
        if document.get("format") != RELAY_TOKENS_FORMAT:
            raise ContentError(f"unknown relay token file format {document.get('format')!r}")
        return tuple(RelayToken.from_content(t) for t in document.get("tokens", []))

    def _save(self, tokens: tuple[RelayToken, ...]) -> None:
        payload = (
            json.dumps(
                {"format": RELAY_TOKENS_FORMAT, "tokens": [t.to_content() for t in tokens]},
                indent=2,
            )
            + "\n"
        )
        _write_private(self._path, payload.encode())

    def add(self, token_id: str) -> str:
        """Register a new id and return the bearer token — printed exactly once."""
        existing = self.load()
        if any(t.id == token_id for t in existing):
            raise ContentError(f"a relay token named {token_id!r} already exists; revoke it first")
        bearer = generate_token(token_id)
        self._save((*existing, RelayToken(id=token_id, token_sha256=hash_token(bearer))))
        return bearer

    def revoke(self, token_id: str) -> bool:
        """Remove one id. True if it existed."""
        existing = self.load()
        remaining = tuple(t for t in existing if t.id != token_id)
        if len(remaining) == len(existing):
            return False
        self._save(remaining)
        return True

    def list(self) -> tuple[RelayToken, ...]:
        return self.load()
