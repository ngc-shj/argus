"""HTTP Security Headers models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class HeaderFinding(BaseSchema):
    """Security header finding."""

    header_name: str
    header_key: str
    present: bool
    value: str | None = None
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    description: str | None = None
    recommendation: str | None = None


class CSPAnalysis(BaseSchema):
    """Content-Security-Policy analysis."""

    present: bool = False
    raw_value: str | None = None
    report_only: bool = False

    directives: dict[str, list[str]] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)
    missing_directives: list[str] = Field(default_factory=list)

    score: int = Field(default=0, ge=0, le=100)


class HSTSAnalysis(BaseSchema):
    """HSTS (Strict-Transport-Security) analysis."""

    present: bool = False
    raw_value: str | None = None

    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False

    score: int = Field(default=0, ge=0, le=100)
    recommendations: list[str] = Field(default_factory=list)


class CookieFinding(BaseSchema):
    """Cookie security finding."""

    name: str
    has_secure: bool = False
    has_httponly: bool = False
    has_samesite: bool = False
    samesite_value: str | None = None

    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"


class SecurityHeadersResult(BaseSchema):
    """Complete security headers scan result."""

    target: str

    # All response headers
    all_headers: dict[str, str] = Field(default_factory=dict)

    # Security headers analysis
    present_headers: list[HeaderFinding] = Field(default_factory=list)
    missing_headers: list[HeaderFinding] = Field(default_factory=list)

    # Information disclosure
    info_disclosure: list[HeaderFinding] = Field(default_factory=list)

    # Detailed analysis
    csp: CSPAnalysis | None = None
    hsts: HSTSAnalysis | None = None

    # Cookie analysis
    cookies: list[CookieFinding] = Field(default_factory=list)

    # Overall score
    score: int = Field(default=0, ge=0, le=100)
    grade: Literal["A+", "A", "B", "C", "D", "F"] | None = None

    errors: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def has_csp(self) -> bool:
        return self.csp is not None and self.csp.present

    @property
    def has_hsts(self) -> bool:
        return self.hsts is not None and self.hsts.present
