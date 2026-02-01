"""Scan session models."""

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field

from argus.models.base import BaseSchema, ScanStatus
from argus.models.target import ScanTarget, ScanOptions
from argus.models.dns import DNSScanResult
from argus.models.whois import WHOISResult, RDAPResult
from argus.models.ports import PortScanResult
from argus.models.webtech import WebTechResult
from argus.models.crtsh import CrtshResult
from argus.models.vuln import VulnScanResult
from argus.models.ssl import SSLScanResult
from argus.models.email import EmailSecurityResult
from argus.models.security import SecurityScanResult
from argus.models.headers import SecurityHeadersResult
from argus.models.discovery import DiscoveryResult
from argus.models.favicon import FaviconResult
from argus.models.asn import ASNResult
from argus.models.wayback import WaybackResult
from argus.models.graphql import GraphQLResult


class ModuleProgress(BaseSchema):
    """Progress for individual scan module."""

    module: str
    status: ScanStatus = ScanStatus.PENDING
    progress_percent: int = Field(default=0, ge=0, le=100)
    message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ScanSession(BaseSchema):
    """Complete scan session with all results."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    target: ScanTarget
    options: ScanOptions = Field(default_factory=ScanOptions)

    status: ScanStatus = ScanStatus.PENDING
    progress: list[ModuleProgress] = Field(default_factory=list)

    # Results from each module
    dns_result: DNSScanResult | None = None
    whois_result: WHOISResult | None = None
    rdap_result: RDAPResult | None = None
    port_result: PortScanResult | None = None
    webtech_result: WebTechResult | None = None
    crtsh_result: CrtshResult | None = None
    vuln_result: VulnScanResult | None = None
    ssl_result: SSLScanResult | None = None
    email_result: EmailSecurityResult | None = None
    security_result: SecurityScanResult | None = None

    # Extended scan results
    headers_result: SecurityHeadersResult | None = None
    discovery_result: DiscoveryResult | None = None
    favicon_result: FaviconResult | None = None
    asn_result: ASNResult | None = None
    wayback_result: WaybackResult | None = None
    graphql_result: GraphQLResult | None = None

    # Extended results (not always included)
    kev_matches: list[dict] | None = None
    takeover_results: list[dict] | None = None
    js_analysis: dict | None = None
    subdomain_enum: dict | None = None

    # AI analysis (defined in report.py, referenced here)
    ai_analysis: dict | None = None

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Errors
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_completed(self) -> bool:
        return self.status == ScanStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        return self.status == ScanStatus.FAILED

    def to_json_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        return self.model_dump(mode="json")
