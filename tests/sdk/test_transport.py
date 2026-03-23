"""Tests for AsyncTransport — retry logic and buffering."""

from __future__ import annotations

import pytest

from merkl.sdk.transport import AsyncTransport, TransportError


class TestAsyncTransport:
    def test_creates_with_config(self) -> None:
        transport = AsyncTransport(
            base_url="http://localhost:8000",
            api_key="mk_test",
            max_retries=2,
        )
        assert transport._base_url == "http://localhost:8000"
        assert transport._max_retries == 2

    def test_strips_trailing_slash(self) -> None:
        transport = AsyncTransport(
            base_url="http://localhost:8000/",
            api_key="key",
        )
        assert transport._base_url == "http://localhost:8000"

    def test_buffer_starts_empty(self) -> None:
        transport = AsyncTransport(base_url="http://x", api_key="k")
        assert transport.buffer_size == 0

    @pytest.mark.asyncio
    async def test_post_to_unreachable_buffers(self) -> None:
        transport = AsyncTransport(
            base_url="http://127.0.0.1:1",  # unreachable
            api_key="key",
            max_retries=0,
            timeout=0.1,
        )
        with pytest.raises(TransportError):
            await transport.post("/test", json={"key": "value"})
        assert transport.buffer_size == 1
        await transport.close()

    @pytest.mark.asyncio
    async def test_get_to_unreachable_buffers(self) -> None:
        transport = AsyncTransport(
            base_url="http://127.0.0.1:1",
            api_key="key",
            max_retries=0,
            timeout=0.1,
        )
        with pytest.raises(TransportError):
            await transport.get("/test")
        assert transport.buffer_size == 1
        await transport.close()

    @pytest.mark.asyncio
    async def test_close_idempotent(self) -> None:
        transport = AsyncTransport(base_url="http://x", api_key="k")
        await transport.close()
        await transport.close()  # should not raise
