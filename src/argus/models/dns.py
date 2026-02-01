"""DNS scan result models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class DNSRecord(BaseSchema):
    """Single DNS record."""

    record_type: str
    name: str
    value: str
    ttl: int
    priority: int | None = None  # For MX records


class SubdomainResult(BaseSchema):
    """Discovered subdomain."""

    subdomain: str
    full_domain: str
    resolved_ips: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    status: str = "active"  # active, inactive, wildcard


class DNSScanResult(BaseSchema):
    """Complete DNS scan results."""

    target: str
    records: dict[str, list[DNSRecord]] = Field(default_factory=dict)
    subdomains: list[SubdomainResult] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    zone_transfer_vulnerable: bool = False
    dnssec_enabled: bool = False
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0

    @property
    def total_records(self) -> int:
        return sum(len(records) for records in self.records.values())

    @property
    def total_subdomains(self) -> int:
        return len(self.subdomains)
