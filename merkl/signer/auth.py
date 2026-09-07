"""Agent-signed requests (plan D15).

Every call an agent makes to the signer is signed by the agent's Ed25519 key and
carries a nonce and an expiry. The signer looks the key up **in the policy
document**, never in the request: a request that supplies its own public key is a
request that authenticates itself.

```
pre_image = "merkl-signer-request-v1" || NUL || method || NUL || agent_id
            || NUL || nonce || NUL || expires_at || NUL || canonical_bytes(params)
signature = Ed25519(agent_key, pre_image)
```

Ed25519 hashes internally, so the pre-image is signed whole rather than
pre-hashed — one fewer place for two implementations to disagree.

Three things make a replay useless: the nonce is recorded in signer state and
refused a second time, the expiry bounds how long a captured request is worth
anything, and the params are inside the signature, so nothing in the request can
be edited in transit.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any, Final

from merkl.core.canonical import JSONObject, instant, parse_instant, token
from merkl.core.crypto import ed25519_verify, tagged
from merkl.core.policy.document import AgentSection, PolicyDocument
from merkl.shared.errors import MerklError
from merkl.shared.hashing import canonical_bytes

REQUEST_TAG: Final = b"merkl-signer-request-v1"


class AuthError(MerklError):
    """Raised when a request is not authentic, has expired, or is a replay."""

    error_code = "signer_auth_error"


@dataclasses.dataclass(frozen=True)
class SignedRequest:
    """One authenticated call from an agent to the signer."""

    method: str
    agent_id: str
    nonce: str
    expires_at: str
    params: JSONObject
    signature: str
    agent_public_key: str

    def __post_init__(self) -> None:
        token(self.method, "request.method", max_length=64)
        token(self.agent_id, "request.agent_id", max_length=128)
        token(self.nonce, "request.nonce", max_length=128)
        instant(self.expires_at, "request.expires_at")
        token(self.signature, "request.signature", max_length=256)
        token(self.agent_public_key, "request.agent_public_key", max_length=256)
        if not isinstance(self.params, dict):
            raise AuthError("request.params must be an object")

    def pre_image(self) -> bytes:
        return tagged(
            REQUEST_TAG,
            self.method.encode(),
            self.agent_id.encode(),
            self.nonce.encode(),
            self.expires_at.encode(),
            canonical_bytes(self.params),
        )

    def to_content(self) -> JSONObject:
        return {
            "method": self.method,
            "agent_id": self.agent_id,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
            "params": self.params,
            "agent_public_key": self.agent_public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_content(cls, data: Any) -> SignedRequest:
        if not isinstance(data, Mapping):
            raise AuthError(f"a signed request must be an object, got {type(data).__name__}")
        allowed = {
            "method",
            "agent_id",
            "nonce",
            "expires_at",
            "params",
            "agent_public_key",
            "signature",
        }
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise AuthError(f"signed request has unknown members: {unknown}")
        missing = sorted(allowed - set(data) - {"params"})
        if missing:
            raise AuthError(f"signed request requires {missing}")
        return cls(
            method=data["method"],
            agent_id=data["agent_id"],
            nonce=data["nonce"],
            expires_at=data["expires_at"],
            params=data.get("params", {}),
            agent_public_key=data["agent_public_key"],
            signature=data["signature"],
        )


def sign_request(
    *,
    method: str,
    agent_id: str,
    nonce: str,
    expires_at: str,
    params: JSONObject,
    agent_public_key: str,
    sign: Any,
) -> SignedRequest:
    """Build a signed request. ``sign`` takes bytes and returns hex.

    Lives here so the caller and the verifier build the same pre-image from the
    same code; an agent that assembled its own bytes would be the second
    implementation of an encoding that has to match exactly.
    """
    unsigned = SignedRequest(
        method=method,
        agent_id=agent_id,
        nonce=nonce,
        expires_at=expires_at,
        params=params,
        signature="0" * 128,
        agent_public_key=agent_public_key,
    )
    return dataclasses.replace(unsigned, signature=sign(unsigned.pre_image()))


def verify_request(
    request: SignedRequest,
    policy: PolicyDocument,
    *,
    now: str,
    seen_nonces: frozenset[str],
    expected_method: str | None = None,
) -> AgentSection:
    """Authenticate a request and return the agent section that authorized it.

    Raises rather than returning a verdict: an unauthenticated request is not a
    policy decision and must never become one. A *denied* payment produces a
    receipt; a forged request produces an error and nothing else.
    """
    if expected_method is not None and request.method != expected_method:
        raise AuthError(f"request is for {request.method!r}, not {expected_method!r}")
    section = policy.agent(request.agent_id)
    if section is None:
        raise AuthError(f"policy has no agent {request.agent_id!r}")
    if section.public_key != request.agent_public_key:
        raise AuthError(
            f"request for {request.agent_id!r} is signed by a key the policy does not hold"
        )
    if parse_instant(now, "now") > parse_instant(request.expires_at, "request.expires_at"):
        raise AuthError(f"request expired at {request.expires_at}")
    if request.nonce in seen_nonces:
        raise AuthError(f"nonce {request.nonce!r} has already been used by {request.agent_id}")
    if not ed25519_verify(section.public_key, request.signature, request.pre_image()):
        raise AuthError("request signature does not verify")
    return section
