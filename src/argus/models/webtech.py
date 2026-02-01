"""Web technology scan result models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class Technology(BaseSchema):
    """Detected web technology."""

    name: str
    categories: list[str] = Field(default_factory=list)
    version: str | None = None
    confidence: int = Field(default=100, ge=0, le=100)
    website: str | None = None
    cpe: str | None = None  # Common Platform Enumeration


class HTTPHeader(BaseSchema):
    """Analyzed HTTP header."""

    name: str
    value: str
    security_relevant: bool = False
    findings: list[str] = Field(default_factory=list)


class SecurityHeader(BaseSchema):
    """Security header analysis."""

    name: str
    present: bool
    value: str | None = None
    recommendation: str | None = None
    severity: str = "info"


# Expected security headers
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


class WebTechResult(BaseSchema):
    """Complete web technology scan results."""

    target: str
    url: str

    # HTTP details
    status_code: int
    response_time_ms: float = 0.0
    final_url: str  # After redirects
    redirect_chain: list[str] = Field(default_factory=list)

    # Technologies
    technologies: list[Technology] = Field(default_factory=list)

    # Headers analysis
    headers: list[HTTPHeader] = Field(default_factory=list)
    security_headers: list[SecurityHeader] = Field(default_factory=list)

    # Server info
    server: str | None = None
    powered_by: str | None = None

    # CMS specific
    cms: str | None = None
    cms_version: str | None = None

    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0

    @property
    def missing_security_headers(self) -> list[str]:
        """Return list of missing security headers."""
        present = {h.name.lower() for h in self.security_headers if h.present}
        return [h for h in SECURITY_HEADERS if h.lower() not in present]

    @property
    def technology_names(self) -> list[str]:
        """Return list of detected technology names."""
        return [t.name for t in self.technologies]
