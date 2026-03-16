"""Subdomain recursive scan models."""

from dataclasses import dataclass, field

from pydantic import Field

from argus.models.base import BaseSchema
from argus.models.discovery import DiscoveryResult
from argus.models.dns import DNSScanResult
from argus.models.favicon import FaviconResult
from argus.models.graphql import GraphQLResult
from argus.models.headers import SecurityHeadersResult
from argus.models.ports import PortScanResult
from argus.models.security import SecurityScanResult
from argus.models.ssl import SSLScanResult
from argus.models.webtech import WebTechResult

ALLOWED_SUBDOMAIN_MODULES: list[str] = [
    "dns",
    "ssl",
    "ports",
    "headers",
    "webtech",
    "security",
    "discovery",
    "graphql",
    "favicon",
]


@dataclass
class SubdomainCandidate:
    domain: str
    cert_count: int = 0
    source: str = "unknown"
    resolved_ips: list[str] = field(default_factory=list)


class SubdomainScanResult(BaseSchema):
    """Per-subdomain scan result."""

    domain: str
    status: str
    resolved_ips: list[str] = Field(default_factory=list)
    error: str | None = None

    dns_result: DNSScanResult | None = None
    ssl_result: SSLScanResult | None = None
    port_result: PortScanResult | None = None
    webtech_result: WebTechResult | None = None
    security_result: SecurityScanResult | None = None
    headers_result: SecurityHeadersResult | None = None
    discovery_result: DiscoveryResult | None = None
    graphql_result: GraphQLResult | None = None
    favicon_result: FaviconResult | None = None

    duration_seconds: float = 0.0
    modules_run: list[str] = Field(default_factory=list)


class SubdomainScanSummary(BaseSchema):
    """Aggregated summary of subdomain scan results."""

    total_subdomains: int = 0
    scanned: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    timed_out: int = 0
    wildcard_groups_merged: int = 0
