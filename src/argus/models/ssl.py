"""SSL/TLS Certificate models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class CertificateInfo(BaseSchema):
    """SSL/TLS Certificate information."""

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    version: int | None = None

    # Validity
    not_before: datetime | None = None
    not_after: datetime | None = None
    is_expired: bool = False
    days_until_expiry: int | None = None

    # Subject Alternative Names
    san_domains: list[str] = Field(default_factory=list)
    san_ips: list[str] = Field(default_factory=list)

    # Key information
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    signature_algorithm: str | None = None

    # Fingerprints
    fingerprint_sha256: str | None = None
    fingerprint_sha1: str | None = None

    # Chain info
    is_self_signed: bool = False
    chain_length: int = 0
    chain_valid: bool = True
    chain_errors: list[str] = Field(default_factory=list)


class TLSInfo(BaseSchema):
    """TLS connection information."""

    protocol_version: str | None = None
    cipher_suite: str | None = None
    cipher_bits: int | None = None

    # Protocol support
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False
    supports_tls10: bool = False
    supports_ssl3: bool = False
    supports_ssl2: bool = False

    # Security features
    supports_ocsp_stapling: bool = False
    supports_hsts: bool = False
    hsts_max_age: int | None = None
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False


class SSLVulnerability(BaseSchema):
    """SSL/TLS vulnerability."""

    name: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str
    recommendation: str | None = None


class SSLScanResult(BaseSchema):
    """SSL/TLS scan result."""

    target: str
    port: int = 443
    hostname: str | None = None

    # Connection status
    ssl_enabled: bool = False
    connection_error: str | None = None

    # Certificate
    certificate: CertificateInfo | None = None

    # TLS info
    tls_info: TLSInfo | None = None

    # Security assessment
    vulnerabilities: list[SSLVulnerability] = Field(default_factory=list)
    grade: Literal["A+", "A", "B", "C", "D", "F", "T"] | None = None  # T = Trust issues
    grade_reasons: list[str] = Field(default_factory=list)

    # Warnings
    warnings: list[str] = Field(default_factory=list)

    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def is_secure(self) -> bool:
        """Check if the SSL/TLS configuration is considered secure."""
        if not self.ssl_enabled or not self.certificate:
            return False
        if self.certificate.is_expired:
            return False
        if self.grade and self.grade in ("D", "F", "T"):
            return False
        return len([v for v in self.vulnerabilities if v.severity in ("critical", "high")]) == 0

    @property
    def critical_issues(self) -> list[SSLVulnerability]:
        """Get critical vulnerabilities."""
        return [v for v in self.vulnerabilities if v.severity == "critical"]

    @property
    def high_issues(self) -> list[SSLVulnerability]:
        """Get high severity vulnerabilities."""
        return [v for v in self.vulnerabilities if v.severity == "high"]
