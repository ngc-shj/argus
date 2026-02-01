"""Caching implementation."""

import time
from typing import Any

from argus.core.interfaces import ICache


class MemoryCache(ICache):
    """In-memory cache with TTL support."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[Any, float]] = {}

    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
        if key not in self._cache:
            return None

        value, expiry = self._cache[key]
        if expiry and time.time() > expiry:
            del self._cache[key]
            return None

        return value

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set value in cache with TTL."""
        expiry = time.time() + ttl if ttl > 0 else 0
        self._cache[key] = (value, expiry)

    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        self._cache.pop(key, None)

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        return await self.get(key) is not None

    async def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()

    async def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiry) in self._cache.items()
            if expiry and current_time > expiry
        ]

        for key in expired_keys:
            del self._cache[key]

        return len(expired_keys)
