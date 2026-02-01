"""Vulnerability scan result models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class VulnerabilityInfo(BaseSchema):
    """Information about a known vulnerability."""

    cve_id: str
    description: str | None = None
    severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    cvss_score: float | None = None
    cvss_version: str | None = None
    published_date: datetime | None = None
    last_modified: datetime | None = None
    references: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)


class TechnologyVulnerability(BaseSchema):
    """Vulnerabilities associated with a detected technology."""

    technology: str
    version: str | None = None
    category: str | None = None
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0


class VulnScanResult(BaseSchema):
    """Vulnerability cross-reference scan result."""

    target: str
    technology_vulnerabilities: list[TechnologyVulnerability] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0
    data_sources: list[str] = Field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def risk_level(self) -> str:
        if self.critical_count > 0:
            return "critical"
        if self.high_count > 0:
            return "high"
        if self.medium_count > 0:
            return "medium"
        if self.low_count > 0:
            return "low"
        return "none"
