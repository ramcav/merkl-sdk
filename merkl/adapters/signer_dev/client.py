"""Clients for the signer's RPC — one over a socket, one in-process.

Both speak the contract in ``docs/SIGNER-RPC.md``, and phase 3's Nitro client
speaks the same one over vsock. The orchestration in ``merkl.sdk`` cannot tell
which it is holding, which is the point: swapping a dev signer for an attested
one is a constructor change and nothing else.

``LocalSignerClient`` wraps an in-process :class:`~merkl.signer.engine.SignerEngine`
so tests and single-process deployments skip the socket without skipping the
contract. It is not a stub — it is the same engine, reached differently.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

import httpx

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.policy.approvals import ApprovalAssertion
from merkl.shared.errors import TransportError
from merkl.signer.engine import SignerEngine

DEFAULT_TIMEOUT: Final = 30.0


class SignerRpcError(TransportError):
    """The signer answered, and the answer was an error.

    Carries the signer's own error code so a caller can tell an authentication
    failure from a malformed request without matching on message text.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.signer_message = message


class LocalSignerClient:
    """The signer engine, in this process, behind the async port."""

    def __init__(self, engine: SignerEngine) -> None:
        self._engine = engine

    async def public_key(self) -> str:
        result = self._engine.public_key()
        return str(result["public_key"])

    async def attestation(self) -> JSONValue:
        return self._engine.attestation()

    async def health(self) -> JSONObject:
        return self._engine.health()

    async def propose(self, request: Any) -> JSONObject:
        return self._engine.propose(request)

    async def approve(
        self,
        challenge: str,
        assertions: Sequence[ApprovalAssertion],
        prepared_tx: JSONObject | None = None,
    ) -> JSONObject:
        return self._engine.approve(
            challenge, [a.to_content() for a in assertions], prepared_tx
        )

    async def reject(
        self,
        challenge: str,
        assertions: Sequence[ApprovalAssertion],
    ) -> JSONObject:
        return self._engine.reject(challenge, [a.to_content() for a in assertions])

    async def settle(self, reservation_id: str, settlement_ref: str) -> JSONObject:
        return self._engine.settle(reservation_id, settlement_ref)

    async def release(self, reservation_id: str) -> JSONObject:
        return self._engine.release(reservation_id)

    async def policy_update(self, signed_policy: JSONObject) -> JSONObject:
        return self._engine.policy_update(signed_policy)


class DevSignerClient:
    """A :class:`~merkl.core.ports.SignerPort` over the dev signer's HTTP RPC.

    Prefers a Unix socket, because file permissions are real access control and a
    listening TCP port is not. ``httpx`` is already an SDK dependency and speaks
    both.
    """

    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if socket_path is not None:
            transport = httpx.AsyncHTTPTransport(uds=str(socket_path))
            self._client = httpx.AsyncClient(
                transport=transport, base_url="http://signer.local", timeout=timeout
            )
        elif base_url is not None:
            self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)
        else:
            raise ValueError("a signer client needs either a socket_path or a base_url")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> DevSignerClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def _call(self, method: str, params: JSONObject | None = None) -> JSONObject:
        try:
            response = await self._client.post(
                "/", json={"method": method, "params": params or {}}
            )
        except httpx.HTTPError as exc:
            raise TransportError(f"cannot reach the signer: {exc}") from exc
        try:
            body = response.json()
        except json.JSONDecodeError as exc:  # pragma: no cover - the server sends JSON
            raise TransportError(
                f"signer sent a non-JSON response: {response.text[:200]}"
            ) from exc
        if "error" in body:
            error = body["error"]
            raise SignerRpcError(error.get("code", "signer_error"), error.get("message", ""))
        result = body.get("result")
        if not isinstance(result, dict):  # pragma: no cover - contract violation
            raise TransportError("signer response has no result object")
        return result

    async def public_key(self) -> str:
        return str((await self._call("public_key"))["public_key"])

    async def attestation(self) -> JSONValue:
        return (await self._call("attestation")).get("attestation")

    async def health(self) -> JSONObject:
        return await self._call("health")

    async def propose(self, request: Any) -> JSONObject:
        return await self._call("propose", {"request": request})

    async def approve(
        self,
        challenge: str,
        assertions: Sequence[ApprovalAssertion],
        prepared_tx: JSONObject | None = None,
    ) -> JSONObject:
        params: JSONObject = {
            "challenge": challenge,
            "assertions": [a.to_content() for a in assertions],
        }
        if prepared_tx is not None:
            params["prepared_tx"] = prepared_tx
        return await self._call("approve", params)

    async def reject(
        self,
        challenge: str,
        assertions: Sequence[ApprovalAssertion],
    ) -> JSONObject:
        """Refuse an escalation with signed rejections (plan D11)."""
        return await self._call(
            "reject",
            {"challenge": challenge, "assertions": [a.to_content() for a in assertions]},
        )

    async def settle(self, reservation_id: str, settlement_ref: str) -> JSONObject:
        return await self._call(
            "settle", {"reservation_id": reservation_id, "settlement_ref": settlement_ref}
        )

    async def release(self, reservation_id: str) -> JSONObject:
        return await self._call("release", {"reservation_id": reservation_id})

    async def policy_update(self, signed_policy: JSONObject) -> JSONObject:
        return await self._call("policy_update", {"signed_policy": signed_policy})
