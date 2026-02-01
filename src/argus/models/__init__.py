"""Pydantic data models for Argus."""

from argus.models.base import BaseSchema, ScanStatus, Severity
from argus.models.target import ScanTarget, ScanOptions
from argus.models.dns import DNSRecord, SubdomainResult, DNSScanResult
from argus.models.whois import (
    RegistrarInfo,
    ContactInfo,
    WHOISResult,
    RDAPResult,
)
from argus.models.ports import ServiceInfo, PortResult, PortScanResult
from argus.models.webtech import (
    Technology,
    HTTPHeader,
    SecurityHeader,
    WebTechResult,
)
from argus.models.scan import ModuleProgress, ScanSession
from argus.models.report import Finding, RiskScore, AIAnalysisResult, ScanReport
from argus.models.crtsh import CertificateEntry, DiscoveredSubdomain, CrtshResult
from argus.models.vuln import VulnerabilityInfo, TechnologyVulnerability, VulnScanResult
from argus.models.ssl import CertificateInfo, TLSInfo, SSLVulnerability, SSLScanResult
from argus.models.email import (
    SPFRecord,
    DKIMRecord,
    DMARCRecord,
    MTASTSRecord,
    TLSRPTRecord,
    BIMIRecord,
    EmailSecurityResult,
)
from argus.models.security import (
    ExposedFile,
    CORSMisconfiguration,
    OpenRedirect,
    HTTPMethodFinding,
    SubdomainTakeover,
    WAFDetection,
    CloudProvider,
    S3BucketFinding,
    CloudStorageFinding,
    ActuatorFinding,
    SourceMapFinding,
    DockerK8sFinding,
    HostHeaderInjectionFinding,
    DefaultCredentialFinding,
    CMSFinding,
    JSSecretFinding,
    JSEndpoint,
    SecurityScanResult,
)
from argus.models.headers import (
    HeaderFinding,
    CSPAnalysis,
    HSTSAnalysis,
    CookieFinding,
    SecurityHeadersResult,
)
from argus.models.discovery import (
    DisallowedPath,
    RobotsTxtResult,
    SitemapURL,
    SitemapResult,
    SecurityTxtResult,
    HumansTxtResult,
    DiscoveryResult,
)
from argus.models.favicon import FaviconMatch, FaviconResult
from argus.models.asn import ASNInfo, IPRange, BGPPeer, GeoLocation, ASNResult
from argus.models.wayback import WaybackURL, ParameterInfo, WaybackResult
from argus.models.graphql import (
    GraphQLEndpoint,
    GraphQLField,
    GraphQLType,
    GraphQLQuery,
    GraphQLMutation,
    GraphQLResult,
)

__all__ = [
    # Base
    "BaseSchema",
    "ScanStatus",
    "Severity",
    # Target
    "ScanTarget",
    "ScanOptions",
    # DNS
    "DNSRecord",
    "SubdomainResult",
    "DNSScanResult",
    # WHOIS
    "RegistrarInfo",
    "ContactInfo",
    "WHOISResult",
    "RDAPResult",
    # Ports
    "ServiceInfo",
    "PortResult",
    "PortScanResult",
    # Web Tech
    "Technology",
    "HTTPHeader",
    "SecurityHeader",
    "WebTechResult",
    # Scan
    "ModuleProgress",
    "ScanSession",
    # Report
    "Finding",
    "RiskScore",
    "AIAnalysisResult",
    "ScanReport",
    # Certificate Transparency
    "CertificateEntry",
    "DiscoveredSubdomain",
    "CrtshResult",
    # Vulnerability
    "VulnerabilityInfo",
    "TechnologyVulnerability",
    "VulnScanResult",
    # SSL/TLS
    "CertificateInfo",
    "TLSInfo",
    "SSLVulnerability",
    "SSLScanResult",
    # Email Security
    "SPFRecord",
    "DKIMRecord",
    "DMARCRecord",
    "MTASTSRecord",
    "TLSRPTRecord",
    "BIMIRecord",
    "EmailSecurityResult",
    # Security Scanning
    "ExposedFile",
    "CORSMisconfiguration",
    "OpenRedirect",
    "HTTPMethodFinding",
    "SubdomainTakeover",
    "WAFDetection",
    "CloudProvider",
    "S3BucketFinding",
    "CloudStorageFinding",
    "ActuatorFinding",
    "SourceMapFinding",
    "DockerK8sFinding",
    "HostHeaderInjectionFinding",
    "DefaultCredentialFinding",
    "CMSFinding",
    "JSSecretFinding",
    "JSEndpoint",
    "SecurityScanResult",
    # HTTP Security Headers
    "HeaderFinding",
    "CSPAnalysis",
    "HSTSAnalysis",
    "CookieFinding",
    "SecurityHeadersResult",
    # Discovery
    "DisallowedPath",
    "RobotsTxtResult",
    "SitemapURL",
    "SitemapResult",
    "SecurityTxtResult",
    "HumansTxtResult",
    "DiscoveryResult",
    # Favicon
    "FaviconMatch",
    "FaviconResult",
    # ASN
    "ASNInfo",
    "IPRange",
    "BGPPeer",
    "GeoLocation",
    "ASNResult",
    # Wayback
    "WaybackURL",
    "ParameterInfo",
    "WaybackResult",
    # GraphQL
    "GraphQLEndpoint",
    "GraphQLField",
    "GraphQLType",
    "GraphQLQuery",
    "GraphQLMutation",
    "GraphQLResult",
]
