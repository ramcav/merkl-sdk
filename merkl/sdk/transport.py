"""Async HTTP transport to the notary with retry and local buffering."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF = 1.0


class TransportError(Exception):
    """Raised when all transport retries are exhausted."""


class AsyncTransport:
    """Async HTTP transport with exponential backoff retry and local buffer.

    If the notary is unavailable, actions are buffered locally and
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
                resp.raise_for_status()
                result: dict[str, Any] = resp.json()
                return result
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                last_exc = e
                if attempt < self._max_retries:
                    wait = self._backoff_factor * (2**attempt)
                    logger.warning(
                        "Request to %s failed (attempt %d/%d), retrying in %.1fs: %s",
                        path, attempt + 1, self._max_retries + 1, wait, e,
                    )
                    await asyncio.sleep(wait)

        # Buffer the request for later flush
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
