"""Rate limiting implementation."""

import asyncio
from typing import Any

from aiolimiter import AsyncLimiter


class RateLimiter:
    """Rate limiter using token bucket algorithm."""

    def __init__(
        self,
        rate: float,
        time_period: float = 1.0,
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            rate: Maximum number of operations
            time_period: Time period in seconds (default: 1.0)
        """
        self._limiter = AsyncLimiter(rate, time_period)

    async def acquire(self) -> None:
        """Acquire a token (wait if necessary)."""
        await self._limiter.acquire()

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


class MultiRateLimiter:
    """Multiple rate limiters for different operations."""

    def __init__(self) -> None:
        from argus.core.config import get_settings

        settings = get_settings()

        self._limiters = {
            "dns": RateLimiter(settings.dns_queries_per_second),
            "whois": RateLimiter(settings.whois_queries_per_minute, 60.0),
            "ports": RateLimiter(settings.port_scans_per_second),
        }

    def get(self, name: str) -> RateLimiter | None:
        """Get rate limiter by name."""
        return self._limiters.get(name)

    async def acquire(self, name: str) -> None:
        """Acquire token from named limiter."""
        limiter = self._limiters.get(name)
        if limiter:
            await limiter.acquire()
