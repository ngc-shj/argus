"""Security scanning models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class ExposedFile(BaseSchema):
    """Exposed sensitive file or directory."""

    path: str
    file_type: Literal[
        "git", "svn", "hg", "env", "backup", "config", "log",
        "database", "archive", "source", "admin", "api", "other"
    ]
    url: str
    status_code: int
    content_length: int | None = None
    content_snippet: str | None = None  # First few bytes if accessible
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str


class CORSMisconfiguration(BaseSchema):
    """CORS misconfiguration finding."""

    url: str
    issue_type: Literal[
        "wildcard_origin",
        "null_origin_allowed",
        "origin_reflection",
        "credentials_with_wildcard",
        "internal_origin_allowed"
    ]
    tested_origin: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    exploitable: bool = False


class OpenRedirect(BaseSchema):
    """Open redirect vulnerability."""

    url: str
    parameter: str
    payload: str
    redirect_url: str
    severity: Literal["high", "medium", "low"]
    description: str


class HTTPMethodFinding(BaseSchema):
    """HTTP method enumeration finding."""

    url: str
    allowed_methods: list[str] = Field(default_factory=list)
    dangerous_methods: list[str] = Field(default_factory=list)  # PUT, DELETE, TRACE, etc.
    severity: Literal["high", "medium", "low", "info"]
    description: str


class SubdomainTakeover(BaseSchema):
    """Subdomain takeover vulnerability."""

    subdomain: str
    cname: str | None = None
    service: str | None = None  # GitHub, AWS S3, Heroku, etc.
    fingerprint: str | None = None
    is_vulnerable: bool = False
    severity: Literal["critical", "high", "medium"]
    description: str
    remediation: str | None = None


class WAFDetection(BaseSchema):
    """WAF (Web Application Firewall) detection."""

    detected: bool = False
    waf_name: str | None = None
    confidence: Literal["high", "medium", "low"] | None = None
    detection_method: str | None = None
    headers_found: dict[str, str] = Field(default_factory=dict)
    notes: str | None = None


class CloudProvider(BaseSchema):
    """Cloud provider detection."""

    provider: Literal["aws", "azure", "gcp", "digitalocean", "cloudflare", "heroku", "netlify", "vercel", "other"] | None = None
    confidence: Literal["high", "medium", "low"] | None = None
    region: str | None = None
    service: str | None = None  # S3, CloudFront, App Engine, etc.
    detection_method: str | None = None


class S3BucketFinding(BaseSchema):
    """S3 bucket discovery."""

    bucket_name: str
    url: str
    is_public: bool = False
    allows_listing: bool = False
    allows_write: bool = False
    region: str | None = None
    severity: Literal["critical", "high", "medium", "low"]
    description: str


class CloudStorageFinding(BaseSchema):
    """Generic cloud storage bucket/container finding (S3, Azure Blob, GCS)."""

    provider: Literal["aws_s3", "azure_blob", "gcp_storage"]
    bucket_name: str
    url: str
    is_public: bool = False
    allows_listing: bool = False
    allows_write: bool = False
    allows_delete: bool = False
    region: str | None = None
    container_type: str | None = None  # e.g., "blob container", "bucket"
    sensitive_files_found: list[str] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str


class ActuatorFinding(BaseSchema):
    """Spring Boot Actuator endpoint finding."""

    endpoint: str
    url: str
    status_code: int
    is_accessible: bool = False
    framework: Literal["spring_boot", "spring_boot_legacy", "management"] = "spring_boot"
    content_type: str | None = None
    response_preview: str | None = None  # First 200 chars of response
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str


class SourceMapFinding(BaseSchema):
    """JavaScript source map exposure finding."""

    js_file: str
    source_map_url: str
    is_accessible: bool = False
    file_size: int | None = None
    sources_exposed: list[str] = Field(default_factory=list)  # List of original source files
    severity: Literal["high", "medium", "low"]
    description: str


class DockerK8sFinding(BaseSchema):
    """Docker/Kubernetes API exposure finding."""

    path: str
    url: str
    service_type: Literal["docker_api", "kubernetes_api", "docker_registry"]
    is_accessible: bool = False
    requires_auth: bool = False
    response_preview: str | None = None
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str


class HostHeaderInjectionFinding(BaseSchema):
    """Host Header Injection vulnerability finding."""

    url: str
    injection_type: Literal[
        "reflection_in_body",
        "reflection_in_headers",
        "cache_poisoning",
        "password_reset_poisoning",
        "redirect",
    ]
    injected_host: str
    evidence: str | None = None
    response_location: str | None = None  # Where injection was reflected
    severity: Literal["critical", "high", "medium", "low"]
    description: str


class DefaultCredentialFinding(BaseSchema):
    """Default credential finding."""

    url: str
    service_type: str  # e.g., "phpMyAdmin", "Tomcat", "Jenkins"
    username: str
    password_hint: str  # Don't store actual passwords, just hints like "admin/admin"
    login_successful: bool = False
    severity: Literal["critical", "high", "medium"]
    description: str


class CMSFinding(BaseSchema):
    """CMS-specific finding (WordPress, Drupal, Joomla, etc.)."""

    url: str
    cms_type: str  # e.g., "WordPress", "Drupal", "Joomla"
    path: str
    finding_type: Literal[
        "version_disclosure",
        "user_enumeration",
        "config_exposure",
        "debug_exposure",
        "directory_listing",
        "sensitive_endpoint",
        "admin_panel",
        "dev_environment",
    ]
    version: str | None = None  # Detected version if available
    evidence: str | None = None
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str


class JSSecretFinding(BaseSchema):
    """Secret found in JavaScript."""

    url: str
    secret_type: Literal[
        "api_key", "aws_key", "oauth_token", "jwt", "password",
        "private_key", "connection_string", "webhook_url", "other"
    ]
    pattern_matched: str
    value_snippet: str  # Partial value for safety
    line_number: int | None = None
    severity: Literal["critical", "high", "medium", "low"]
    description: str


class JSEndpoint(BaseSchema):
    """API endpoint discovered in JavaScript."""

    url: str
    source_file: str
    endpoint_type: Literal["api", "graphql", "websocket", "internal", "external", "unknown"]
    method: str | None = None
    parameters: list[str] = Field(default_factory=list)


class SecurityScanResult(BaseSchema):
    """Complete security scan result."""

    target: str

    # Exposed files/directories
    exposed_files: list[ExposedFile] = Field(default_factory=list)

    # CORS issues
    cors_misconfigurations: list[CORSMisconfiguration] = Field(default_factory=list)

    # Open redirects
    open_redirects: list[OpenRedirect] = Field(default_factory=list)

    # HTTP methods
    http_method_findings: list[HTTPMethodFinding] = Field(default_factory=list)

    # Subdomain takeover
    takeover_vulnerabilities: list[SubdomainTakeover] = Field(default_factory=list)

    # WAF detection
    waf: WAFDetection | None = None

    # Cloud detection
    cloud_providers: list[CloudProvider] = Field(default_factory=list)

    # S3 buckets
    s3_buckets: list[S3BucketFinding] = Field(default_factory=list)

    # Cloud storage findings (S3, Azure Blob, GCS)
    cloud_storage_findings: list["CloudStorageFinding"] = Field(default_factory=list)

    # Spring Boot Actuator findings
    actuator_findings: list["ActuatorFinding"] = Field(default_factory=list)

    # Source map exposures
    source_map_findings: list["SourceMapFinding"] = Field(default_factory=list)

    # Docker/Kubernetes exposures
    docker_k8s_findings: list["DockerK8sFinding"] = Field(default_factory=list)

    # Host Header Injection
    host_header_findings: list["HostHeaderInjectionFinding"] = Field(default_factory=list)

    # Default credentials
    default_credential_findings: list["DefaultCredentialFinding"] = Field(default_factory=list)

    # CMS-specific findings
    cms_findings: list["CMSFinding"] = Field(default_factory=list)

    # JavaScript analysis
    js_secrets: list[JSSecretFinding] = Field(default_factory=list)
    js_endpoints: list[JSEndpoint] = Field(default_factory=list)

    # Summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    def calculate_counts(self) -> None:
        """Calculate severity counts from all findings."""
        all_findings = []

        for finding in self.exposed_files:
            all_findings.append(finding.severity)
        for finding in self.cors_misconfigurations:
            all_findings.append(finding.severity)
        for finding in self.open_redirects:
            all_findings.append(finding.severity)
        for finding in self.http_method_findings:
            all_findings.append(finding.severity)
        for finding in self.takeover_vulnerabilities:
            all_findings.append(finding.severity)
        for finding in self.s3_buckets:
            all_findings.append(finding.severity)
        for finding in self.cloud_storage_findings:
            all_findings.append(finding.severity)
        for finding in self.actuator_findings:
            all_findings.append(finding.severity)
        for finding in self.source_map_findings:
            all_findings.append(finding.severity)
        for finding in self.docker_k8s_findings:
            all_findings.append(finding.severity)
        for finding in self.host_header_findings:
            all_findings.append(finding.severity)
        for finding in self.default_credential_findings:
            all_findings.append(finding.severity)
        for finding in self.cms_findings:
            all_findings.append(finding.severity)
        for finding in self.js_secrets:
            all_findings.append(finding.severity)

        self.total_findings = len(all_findings)
        self.critical_count = all_findings.count("critical")
        self.high_count = all_findings.count("high")
        self.medium_count = all_findings.count("medium")
        self.low_count = all_findings.count("low")
