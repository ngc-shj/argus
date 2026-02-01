"""Report and AI analysis models."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from argus.models.base import BaseSchema, Severity
from argus.models.dns import DNSScanResult
from argus.models.whois import WHOISResult, RDAPResult
from argus.models.ports import PortScanResult
from argus.models.webtech import WebTechResult


class Finding(BaseSchema):
    """Security finding from analysis."""

    title: str
    description: str
    severity: Severity
    category: str  # dns, network, web, infrastructure
    affected_asset: str
    evidence: str | None = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)


class RiskScore(BaseSchema):
    """Calculated risk assessment."""

    overall: int = Field(default=0, ge=0, le=100)
    dns_security: int = Field(default=0, ge=0, le=100)
    network_exposure: int = Field(default=0, ge=0, le=100)
    web_security: int = Field(default=0, ge=0, le=100)
    infrastructure: int = Field(default=0, ge=0, le=100)

    @property
    def risk_level(self) -> str:
        """Return human-readable risk level."""
        if self.overall >= 80:
            return "Critical"
        elif self.overall >= 60:
            return "High"
        elif self.overall >= 40:
            return "Medium"
        elif self.overall >= 20:
            return "Low"
        return "Minimal"


class AIAnalysisResult(BaseSchema):
    """AI-powered analysis results."""

    summary: str
    key_findings: list[str] = Field(default_factory=list)
    risk_score: RiskScore = Field(default_factory=RiskScore)
    findings: list[Finding] = Field(default_factory=list)
    attack_vectors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    executive_summary: str = ""
    technical_details: str = ""
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    model_used: str = ""
    provider: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanReport(BaseSchema):
    """Final exportable scan report."""

    scan_id: UUID
    target: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    # Summary
    executive_summary: str = ""
    risk_score: RiskScore = Field(default_factory=RiskScore)

    # Findings by severity
    critical_findings: list[Finding] = Field(default_factory=list)
    high_findings: list[Finding] = Field(default_factory=list)
    medium_findings: list[Finding] = Field(default_factory=list)
    low_findings: list[Finding] = Field(default_factory=list)
    info_findings: list[Finding] = Field(default_factory=list)

    # Raw results
    dns: DNSScanResult | None = None
    whois: WHOISResult | None = None
    rdap: RDAPResult | None = None
    ports: PortScanResult | None = None
    webtech: WebTechResult | None = None

    # AI analysis
    ai_analysis: AIAnalysisResult | None = None

    # Metadata
    scan_duration_seconds: float = 0.0
    modules_executed: list[str] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return (
            len(self.critical_findings)
            + len(self.high_findings)
            + len(self.medium_findings)
            + len(self.low_findings)
            + len(self.info_findings)
        )

    def to_json(self) -> str:
        """Export report as JSON string."""
        return self.model_dump_json(indent=2)
