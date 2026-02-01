"""Email security models (SPF, DKIM, DMARC)."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class SPFRecord(BaseSchema):
    """SPF (Sender Policy Framework) record."""

    raw_record: str | None = None
    version: str | None = None
    mechanisms: list[str] = Field(default_factory=list)
    qualifiers: dict[str, str] = Field(default_factory=dict)
    includes: list[str] = Field(default_factory=list)
    all_mechanism: str | None = None  # +all, -all, ~all, ?all

    is_valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Security assessment
    is_restrictive: bool = False  # True if -all or ~all
    allows_any_sender: bool = False  # True if +all
    too_many_lookups: bool = False  # SPF has 10 DNS lookup limit


class DKIMRecord(BaseSchema):
    """DKIM (DomainKeys Identified Mail) record."""

    selector: str
    raw_record: str | None = None

    version: str | None = None
    key_type: str | None = None
    public_key: str | None = None
    key_size: int | None = None
    hash_algorithms: list[str] = Field(default_factory=list)
    service_type: str | None = None
    flags: list[str] = Field(default_factory=list)

    is_valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Security assessment
    key_strength: Literal["strong", "acceptable", "weak"] | None = None


class DMARCRecord(BaseSchema):
    """DMARC (Domain-based Message Authentication) record."""

    raw_record: str | None = None
    version: str | None = None

    # Policy
    policy: Literal["none", "quarantine", "reject"] | None = None
    subdomain_policy: Literal["none", "quarantine", "reject"] | None = None
    percentage: int = 100

    # Reporting
    rua: list[str] = Field(default_factory=list)  # Aggregate report URIs
    ruf: list[str] = Field(default_factory=list)  # Forensic report URIs
    report_format: str | None = None
    report_interval: int | None = None

    # Alignment
    aspf: Literal["r", "s"] = "r"  # relaxed or strict
    adkim: Literal["r", "s"] = "r"  # relaxed or strict

    is_valid: bool = False
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Security assessment
    is_enforcing: bool = False  # True if policy is quarantine or reject


class MTASTSRecord(BaseSchema):
    """MTA-STS (Mail Transfer Agent Strict Transport Security) record."""

    version: str | None = None
    id: str | None = None
    is_valid: bool = False

    # Policy (from /.well-known/mta-sts.txt)
    policy_mode: Literal["enforce", "testing", "none"] | None = None
    policy_mx: list[str] = Field(default_factory=list)
    policy_max_age: int | None = None

    errors: list[str] = Field(default_factory=list)


class TLSRPTRecord(BaseSchema):
    """TLS-RPT (TLS Reporting) record."""

    version: str | None = None
    rua: list[str] = Field(default_factory=list)
    is_valid: bool = False
    errors: list[str] = Field(default_factory=list)


class BIMIRecord(BaseSchema):
    """BIMI (Brand Indicators for Message Identification) record."""

    version: str | None = None
    location: str | None = None  # SVG logo URL
    authority: str | None = None  # VMC certificate URL
    is_valid: bool = False
    errors: list[str] = Field(default_factory=list)


class EmailSecurityResult(BaseSchema):
    """Complete email security scan result."""

    target: str

    # Records
    spf: SPFRecord | None = None
    dkim_records: list[DKIMRecord] = Field(default_factory=list)
    dmarc: DMARCRecord | None = None
    mta_sts: MTASTSRecord | None = None
    tls_rpt: TLSRPTRecord | None = None
    bimi: BIMIRecord | None = None

    # MX records
    mx_records: list[str] = Field(default_factory=list)
    mx_supports_starttls: dict[str, bool] = Field(default_factory=dict)

    # Overall assessment
    security_score: int = Field(default=0, ge=0, le=100)
    security_grade: Literal["A", "B", "C", "D", "F"] | None = None
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def has_spf(self) -> bool:
        return self.spf is not None and self.spf.is_valid

    @property
    def has_dkim(self) -> bool:
        return len([d for d in self.dkim_records if d.is_valid]) > 0

    @property
    def has_dmarc(self) -> bool:
        return self.dmarc is not None and self.dmarc.is_valid

    @property
    def is_dmarc_enforcing(self) -> bool:
        return self.dmarc is not None and self.dmarc.is_enforcing
