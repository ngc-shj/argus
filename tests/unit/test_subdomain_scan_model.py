"""Unit tests for subdomain scan models and target validation."""

import pytest
from pydantic import ValidationError

from argus.models.subdomain_scan import (
    ALLOWED_SUBDOMAIN_MODULES,
    SubdomainCandidate,
    SubdomainScanResult,
)
from argus.models.target import ScanOptions, ScanTarget


class TestSubdomainScanResult:
    def test_default_values(self):
        result = SubdomainScanResult(domain="sub.example.com", status="pending")
        assert result.domain == "sub.example.com"
        assert result.status == "pending"
        assert result.resolved_ips == []
        assert result.error is None
        assert result.dns_result is None
        assert result.ssl_result is None
        assert result.port_result is None
        assert result.webtech_result is None
        assert result.security_result is None
        assert result.headers_result is None
        assert result.discovery_result is None
        assert result.graphql_result is None
        assert result.favicon_result is None
        assert result.duration_seconds == 0.0
        assert result.modules_run == []

    def test_serialization_roundtrip(self):
        result = SubdomainScanResult(
            domain="api.example.com",
            status="completed",
            resolved_ips=["1.2.3.4", "5.6.7.8"],
            duration_seconds=1.5,
            modules_run=["dns", "ssl"],
        )
        data = result.model_dump()
        restored = SubdomainScanResult(**data)
        assert restored.domain == result.domain
        assert restored.status == result.status
        assert restored.resolved_ips == result.resolved_ips
        assert restored.duration_seconds == result.duration_seconds
        assert restored.modules_run == result.modules_run

    def test_with_error(self):
        result = SubdomainScanResult(
            domain="broken.example.com",
            status="failed",
            error="Connection refused",
        )
        assert result.status == "failed"
        assert result.error == "Connection refused"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            SubdomainScanResult(
                domain="sub.example.com",
                status="pending",
                nonexistent_field="value",
            )


class TestScanOptionsSubdomainModules:
    def test_valid_modules_accepted(self):
        opts = ScanOptions(subdomain_modules=["dns", "ssl", "headers"])
        assert opts.subdomain_modules == ["dns", "ssl", "headers"]

    def test_all_allowed_modules_accepted(self):
        opts = ScanOptions(subdomain_modules=ALLOWED_SUBDOMAIN_MODULES)
        assert opts.subdomain_modules == ALLOWED_SUBDOMAIN_MODULES

    def test_unknown_module_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ScanOptions(subdomain_modules=["dns", "invalid_module"])
        assert "invalid_module" in str(exc_info.value)

    def test_multiple_unknown_modules_rejected(self):
        with pytest.raises(ValidationError):
            ScanOptions(subdomain_modules=["whois", "rdap", "asn"])

    def test_empty_modules_list_accepted(self):
        opts = ScanOptions(subdomain_modules=[])
        assert opts.subdomain_modules == []


class TestScanOptionsMaxSubdomains:
    def test_default_value(self):
        opts = ScanOptions()
        assert opts.max_subdomains == 50

    def test_min_boundary(self):
        opts = ScanOptions(max_subdomains=1)
        assert opts.max_subdomains == 1

    def test_max_boundary(self):
        opts = ScanOptions(max_subdomains=200)
        assert opts.max_subdomains == 200

    def test_below_min_rejected(self):
        with pytest.raises(ValidationError):
            ScanOptions(max_subdomains=0)

    def test_above_max_rejected(self):
        with pytest.raises(ValidationError):
            ScanOptions(max_subdomains=201)

    def test_midrange_accepted(self):
        opts = ScanOptions(max_subdomains=100)
        assert opts.max_subdomains == 100


class TestSubdomainCandidateNormalization:
    def test_default_cert_count_zero(self):
        candidate = SubdomainCandidate(domain="sub.example.com", source="subdomain_enum")
        assert candidate.cert_count == 0

    def test_cert_count_set_from_crtsh(self):
        # cert_count represents len(certificate_ids) for crtsh sources
        candidate = SubdomainCandidate(
            domain="sub.example.com",
            cert_count=3,
            source="crtsh",
        )
        assert candidate.cert_count == 3

    def test_subdomain_enum_source_cert_count_zero(self):
        candidate = SubdomainCandidate(domain="api.example.com", source="subdomain_enum")
        assert candidate.cert_count == 0
        assert candidate.source == "subdomain_enum"

    def test_resolved_ips_default_empty(self):
        candidate = SubdomainCandidate(domain="sub.example.com")
        assert candidate.resolved_ips == []

    def test_resolved_ips_can_be_set(self):
        candidate = SubdomainCandidate(
            domain="sub.example.com",
            resolved_ips=["1.2.3.4"],
        )
        assert candidate.resolved_ips == ["1.2.3.4"]

    def test_default_source_unknown(self):
        candidate = SubdomainCandidate(domain="sub.example.com")
        assert candidate.source == "unknown"


class TestValidateIPv6SSRF:
    """Tests for IPv6 SSRF protection in ScanTarget.validate_ip()."""

    def test_link_local_ipv6_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ScanTarget(ip_address="fe80::1")
        assert "fe80::1" in str(exc_info.value)

    def test_multicast_ipv6_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ScanTarget(ip_address="ff02::1")
        assert "ff02::1" in str(exc_info.value)

    def test_unspecified_ipv6_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ScanTarget(ip_address="::")
        assert "::" in str(exc_info.value)

    def test_ipv4_mapped_cloud_metadata_rejected(self):
        # ::ffff:169.254.169.254 - IPv4-mapped cloud metadata address
        # Python may parse this as IPv4 since it contains "." - test the actual behavior
        with pytest.raises(ValidationError):
            ScanTarget(ip_address="::ffff:169.254.169.254")

    def test_ipv4_mapped_private_rejected(self):
        # ::ffff:10.0.0.1 - IPv4-mapped private address
        # Python may parse this as IPv4 since it contains "." - test the actual behavior
        with pytest.raises(ValidationError):
            ScanTarget(ip_address="::ffff:10.0.0.1")

    def test_valid_public_ipv4_accepted(self):
        target = ScanTarget(ip_address="8.8.8.8")
        assert target.ip_address == "8.8.8.8"

    def test_valid_public_ipv6_accepted(self):
        # 2606:4700:4700::1111 is Cloudflare's public DNS IPv6 address
        target = ScanTarget(ip_address="2606:4700:4700::1111")
        assert target.ip_address is not None

    def test_loopback_ipv4_rejected(self):
        with pytest.raises(ValidationError):
            ScanTarget(ip_address="127.0.0.1")

    def test_private_ipv4_rejected(self):
        with pytest.raises(ValidationError):
            ScanTarget(ip_address="192.168.1.1")

    def test_ipv6_loopback_rejected(self):
        with pytest.raises(ValidationError):
            ScanTarget(ip_address="::1")
