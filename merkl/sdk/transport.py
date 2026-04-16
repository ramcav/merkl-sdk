"""Async HTTP transport to the Merkl API with retry and local buffering."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from merkl.shared.errors import TransportError

logger = logging.getLogger(__name__)

_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF = 1.0

__all__ = ["AsyncTransport", "ApiError", "TransportError"]


class ApiError(Exception):
    """Raised for 4xx responses from the Merkl API.

    Carries the server's structured error body so callers can branch on
    `error_code` without re-parsing messages. Not retried by the transport —
    client errors mean our request was wrong, retrying won't fix it.
    """

    def __init__(self, status: int, error_code: str, detail: str) -> None:
        super().__init__(f"{status} {error_code}: {detail}")
        self.status = status
        self.error_code = error_code
        self.detail = detail


class AsyncTransport:
    """Async HTTP transport with exponential backoff retry and local buffer.

    If the Merkl API is unavailable, actions are buffered locally and
    flushed when connectivity is restored.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        max_retries: int = _DEFAULT_RETRIES,
        backoff_factor: float = _DEFAULT_BACKOFF,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._timeout = timeout
        self._buffer: list[tuple[str, str, dict[str, Any]]] = []
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
            )
        return self._client

    async def post(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        """Send a POST request with retry logic."""
        return await self._request("POST", path, json)

    async def get(self, path: str) -> dict[str, Any]:
        """Send a GET request with retry logic."""
        return await self._request("GET", path, {})

    async def _request(
        self, method: str, path: str, json: dict[str, Any]
    ) -> dict[str, Any]:
        client = await self._get_client()
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                if method == "POST":
                    resp = await client.post(path, json=json)
                else:
                    resp = await client.get(path)
                # 4xx: client error. Don't retry, surface as ApiError with
                # the structured body so callers can branch on error_code.
                if 400 <= resp.status_code < 500:
                    body: dict[str, Any] = {}
                    try:
                        body = resp.json()
                    except Exception:
                        pass
                    raise ApiError(
                        status=resp.status_code,
                        error_code=str(body.get("error_code") or body.get("error") or ""),
                        detail=str(body.get("detail") or resp.text),
                    )
                resp.raise_for_status()
                result: dict[str, Any] = resp.json()
                return result
            except ApiError:
                raise
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                last_exc = e
                if attempt < self._max_retries:
                    wait = self._backoff_factor * (2**attempt)
                    logger.warning(
                        "Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                        path, attempt + 1, self._max_retries + 1, wait, e,
                    )
                    await asyncio.sleep(wait)

        self._buffer.append((method, path, json))
        raise TransportError(
            f"All {self._max_retries + 1} attempts failed for {method} {path}: {last_exc}"
        )

    async def flush_buffer(self) -> int:
        """Attempt to flush buffered requests. Returns number flushed."""
        flushed = 0
        remaining: list[tuple[str, str, dict[str, Any]]] = []
        for method, path, json in self._buffer:
            try:
                await self._request(method, path, json)
                flushed += 1
            except TransportError:
                remaining.append((method, path, json))
        self._buffer = remaining
        return flushed

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
