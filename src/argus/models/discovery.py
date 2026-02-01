"""Discovery models (robots.txt, sitemap.xml, etc.)."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class DisallowedPath(BaseSchema):
    """Disallowed path from robots.txt."""

    path: str
    user_agent: str = "*"
    is_interesting: bool = False


class RobotsTxtResult(BaseSchema):
    """robots.txt parsing result."""

    url: str | None = None
    found: bool = False
    raw_content: str | None = None

    user_agents: list[str] = Field(default_factory=list)
    disallowed_paths: list[DisallowedPath] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    sitemaps: list[str] = Field(default_factory=list)
    crawl_delay: int | None = None

    # Analysis
    blocks_all: bool = False
    interesting_disallows: list[DisallowedPath] = Field(default_factory=list)

    error: str | None = None


class SitemapURL(BaseSchema):
    """URL entry from sitemap.xml."""

    loc: str
    lastmod: str | None = None
    priority: str | None = None
    changefreq: str | None = None
    is_interesting: bool = False


class SitemapResult(BaseSchema):
    """sitemap.xml parsing result."""

    url: str | None = None
    found: bool = False
    raw_content: str | None = None

    is_index: bool = False
    nested_sitemaps: list[str] = Field(default_factory=list)

    urls: list[SitemapURL] = Field(default_factory=list)
    total_urls: int = 0

    parse_error: str | None = None


class SecurityTxtResult(BaseSchema):
    """security.txt parsing result."""

    url: str | None = None
    found: bool = False
    raw_content: str | None = None

    # RFC 9116 fields
    contacts: list[str] = Field(default_factory=list)
    expires: str | None = None
    encryption: str | None = None
    acknowledgments: str | None = None
    preferred_languages: str | None = None
    canonical: str | None = None
    policy: str | None = None
    hiring: str | None = None


class HumansTxtResult(BaseSchema):
    """humans.txt parsing result."""

    url: str | None = None
    found: bool = False
    raw_content: str | None = None
    is_standard_format: bool = False


class DiscoveryResult(BaseSchema):
    """Complete discovery scan result."""

    target: str

    robots: RobotsTxtResult | None = None
    sitemap: SitemapResult | None = None
    security_txt: SecurityTxtResult | None = None
    humans_txt: HumansTxtResult | None = None

    # Aggregated data
    discovered_paths: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)

    scanned_at: datetime = Field(default_factory=datetime.utcnow)
