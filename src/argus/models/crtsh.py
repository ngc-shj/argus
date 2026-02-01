"""Certificate Transparency Log result models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class CertificateEntry(BaseSchema):
    """Individual certificate entry from CT logs."""

    id: int | None = None
    issuer_ca_id: int | None = None
    issuer_name: str | None = None
    common_name: str | None = None
    name_values: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    is_expired: bool = False


class DiscoveredSubdomain(BaseSchema):
    """Subdomain discovered from certificate data."""

    subdomain: str
    full_domain: str
    source: str = "crt.sh"
    certificate_ids: list[int] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_wildcard: bool = False


class CrtshResult(BaseSchema):
    """Certificate Transparency log scan result."""

    target: str
    certificates: list[CertificateEntry] = Field(default_factory=list)
    discovered_subdomains: list[DiscoveredSubdomain] = Field(default_factory=list)
    unique_subdomains: list[str] = Field(default_factory=list)
    wildcard_domains: list[str] = Field(default_factory=list)
    total_certificates: int = 0
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0

    @property
    def subdomain_count(self) -> int:
        return len(self.unique_subdomains)
