"""HTTP client wrapper."""

from typing import Any

import httpx

from argus.core.config import get_settings


class HTTPClient:
    """Async HTTP client wrapper."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HTTPClient":
        self._client = httpx.AsyncClient(
            timeout=self.settings.http_timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make GET request."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with.")
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make POST request."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with.")
        return await self._client.post(url, **kwargs)
