"""Target and scan options models."""

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import Literal

from pydantic import Field, field_validator, model_validator

from argus.models.base import BaseSchema

# SSRF protection: blocked IP ranges
BLOCKED_IP_RANGES = [
    IPv4Network("0.0.0.0/8"),       # Current network
    IPv4Network("10.0.0.0/8"),      # Private (Class A)
    IPv4Network("127.0.0.0/8"),     # Loopback
    IPv4Network("169.254.0.0/16"),  # Link-local (includes cloud metadata)
    IPv4Network("172.16.0.0/12"),   # Private (Class B)
    IPv4Network("192.168.0.0/16"),  # Private (Class C)
    IPv4Network("224.0.0.0/4"),     # Multicast
    IPv4Network("240.0.0.0/4"),     # Reserved
]

# Cloud metadata endpoints (explicit block)
CLOUD_METADATA_IPS = [
    "169.254.169.254",  # AWS, GCP, Azure metadata
    "169.254.170.2",    # AWS ECS metadata
    "100.100.100.200",  # Alibaba Cloud metadata
]

# Forbidden domain patterns (SSRF protection)
FORBIDDEN_DOMAINS = [
    "localhost",
    "localhost.localdomain",
    "internal",
    "intranet",
    "corp",
    "local",
]

# Forbidden domain suffixes
FORBIDDEN_DOMAIN_SUFFIXES = [
    ".internal",
    ".local",
    ".localhost",
    ".corp",
    ".intranet",
]


class ScanTarget(BaseSchema):
    """Target specification for scanning."""

    domain: str | None = Field(default=None, description="Target domain name")
    ip_address: str | None = Field(default=None, description="Target IP address")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str | None) -> str | None:
        if v is None:
            return v

        # Length check
        if len(v) > 253:
            raise ValueError("Domain too long (max 253 characters)")

        # Pattern validation
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid domain format: {v}")

        domain_lower = v.lower()

        # Prevent internal/localhost scanning
        if domain_lower in FORBIDDEN_DOMAINS:
            raise ValueError(f"Cannot scan internal domain: {v}")

        # Check forbidden suffixes
        for suffix in FORBIDDEN_DOMAIN_SUFFIXES:
            if domain_lower.endswith(suffix):
                raise ValueError(f"Cannot scan internal domain: {v}")

        return domain_lower

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v

        try:
            # Try parsing as IPv4 or IPv6
            ip = IPv4Address(v) if "." in v else IPv6Address(v)

            # Block private/reserved/loopback ranges (built-in checks)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                raise ValueError(f"Cannot scan private/reserved IP: {v}")

            # Additional SSRF protection for IPv4
            if isinstance(ip, IPv4Address):
                # Block link-local addresses
                if ip.is_link_local:
                    raise ValueError(f"Cannot scan link-local IP: {v}")

                # Block multicast addresses
                if ip.is_multicast:
                    raise ValueError(f"Cannot scan multicast IP: {v}")

                # Block unspecified address
                if ip.is_unspecified:
                    raise ValueError(f"Cannot scan unspecified IP: {v}")

                # Explicit cloud metadata check
                if str(ip) in CLOUD_METADATA_IPS:
                    raise ValueError(f"Cannot scan cloud metadata IP: {v}")

                # Check against blocked ranges
                for network in BLOCKED_IP_RANGES:
                    if ip in network:
                        raise ValueError(f"Cannot scan blocked IP range: {v}")

            return str(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {v}") from e

    @model_validator(mode="after")
    def validate_target(self) -> "ScanTarget":
        if not self.domain and not self.ip_address:
            raise ValueError("Either domain or ip_address must be provided")
        return self

    @property
    def identifier(self) -> str:
        """Return primary target identifier."""
        return self.domain or self.ip_address or "unknown"


class ScanOptions(BaseSchema):
    """Configuration options for a scan."""

    # DNS options
    dns_enabled: bool = True
    dns_subdomain_enum: bool = True
    dns_record_types: list[str] = Field(
        default=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    )
    dns_wordlist: Literal["small", "medium", "large"] = "small"

    # WHOIS/RDAP options
    whois_enabled: bool = True
    rdap_enabled: bool = True

    # Port scan options
    port_scan_enabled: bool = True
    port_scan_profile: Literal["top_20", "top_100", "top_1000", "custom"] = "top_100"
    port_scan_custom_ports: list[int] = Field(default_factory=list)

    # Web tech options
    webtech_enabled: bool = True

    # Certificate Transparency options
    crtsh_enabled: bool = True

    # Vulnerability scan options
    vuln_scan_enabled: bool = True

    # SSL/TLS scan options
    ssl_scan_enabled: bool = True

    # Email security scan options
    email_scan_enabled: bool = True

    # Security scan options (exposed files, CORS, redirects, etc.)
    security_scan_enabled: bool = True

    # JavaScript analysis options
    js_analysis_enabled: bool = True

    # Subdomain takeover detection
    takeover_scan_enabled: bool = True

    # Extended subdomain enumeration (20+ sources)
    subdomain_enum_extended: bool = False

    # CISA KEV check
    kev_check_enabled: bool = True

    # HTTP Security Headers scan
    headers_scan_enabled: bool = True

    # Discovery scan (robots.txt, sitemap.xml, etc.)
    discovery_scan_enabled: bool = True

    # Favicon fingerprinting
    favicon_scan_enabled: bool = True

    # ASN/IP range lookup
    asn_scan_enabled: bool = True

    # Wayback Machine URL extraction
    wayback_scan_enabled: bool = False  # Disabled by default (can be slow)

    # GraphQL introspection
    graphql_scan_enabled: bool = True

    # AI options
    ai_analysis_enabled: bool = True
    ai_provider: Literal["anthropic", "openai", "ollama"] = "anthropic"

    # General options
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_concurrent: int = Field(default=50, ge=1, le=500)

    @field_validator("port_scan_custom_ports")
    @classmethod
    def validate_ports(cls, v: list[int]) -> list[int]:
        for port in v:
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port number: {port}")
        return v
