"""Wayback Machine URL extraction models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class WaybackURL(BaseSchema):
    """URL found in Wayback Machine."""

    url: str
    timestamp: str | None = None  # YYYYMMDDHHMMSS format
    status_code: str | None = None
    mimetype: str | None = None
    length: int | None = None

    categories: list[str] = Field(default_factory=list)
    is_interesting: bool = False
    parameters: list[str] = Field(default_factory=list)

    @property
    def archive_url(self) -> str | None:
        """Get Wayback Machine archive URL."""
        if self.timestamp:
            return f"https://web.archive.org/web/{self.timestamp}/{self.url}"
        return None

    @property
    def year(self) -> int | None:
        """Extract year from timestamp."""
        if self.timestamp and len(self.timestamp) >= 4:
            try:
                return int(self.timestamp[:4])
            except ValueError:
                pass
        return None


class ParameterInfo(BaseSchema):
    """Information about a discovered parameter."""

    name: str
    count: int = 0
    is_sensitive: bool = False


class WaybackResult(BaseSchema):
    """Complete Wayback Machine scan result."""

    target: str

    # All discovered URLs
    urls: list[WaybackURL] = Field(default_factory=list)
    total_urls: int = 0

    # Interesting findings
    interesting_urls: list[WaybackURL] = Field(default_factory=list)
    sensitive_files: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    admin_paths: list[str] = Field(default_factory=list)

    # Parameter analysis
    parameters: list[ParameterInfo] = Field(default_factory=list)

    # Statistics
    file_extensions: dict[str, int] = Field(default_factory=dict)
    unique_paths: int = 0

    errors: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def sensitive_params(self) -> list[ParameterInfo]:
        """Get potentially sensitive parameters."""
        return [p for p in self.parameters if p.is_sensitive]
