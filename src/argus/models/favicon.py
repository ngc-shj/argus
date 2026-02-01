"""Favicon fingerprinting models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class FaviconMatch(BaseSchema):
    """Matched technology from favicon hash."""

    technology: str
    description: str
    category: Literal[
        "cms", "server", "security", "remote", "devops",
        "database", "router", "storage", "panel", "cloud",
        "microsoft", "framework", "other"
    ]
    confidence: Literal["high", "medium", "low"] = "high"
    hash_matched: int | None = None


class FaviconResult(BaseSchema):
    """Favicon fingerprinting scan result."""

    target: str
    found: bool = False

    url: str | None = None
    content_type: str | None = None
    size: int | None = None

    # Hashes
    md5_hash: str | None = None
    sha256_hash: str | None = None
    mmh3_hash: int | None = None  # MurmurHash3 (Shodan-style)

    # Matched technologies
    matches: list[FaviconMatch] = Field(default_factory=list)

    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def shodan_query(self) -> str | None:
        """Get Shodan query for this favicon."""
        if self.mmh3_hash is not None:
            return f"http.favicon.hash:{self.mmh3_hash}"
        return None
