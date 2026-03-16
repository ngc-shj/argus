"""Pytest configuration and fixtures."""

import pytest

from argus.models import ScanTarget, ScanOptions


@pytest.fixture
def sample_target() -> ScanTarget:
    """Sample scan target for testing."""
    return ScanTarget(domain="example.com")


@pytest.fixture
def sample_options() -> ScanOptions:
    """Sample scan options for testing."""
    return ScanOptions(
        dns_enabled=True,
        whois_enabled=True,
        port_scan_enabled=False,
        webtech_enabled=False,
        ai_analysis_enabled=False,
    )


@pytest.fixture
def subdomain_scan_options() -> ScanOptions:
    """Scan options with subdomain scanning enabled for testing."""
    return ScanOptions(
        subdomain_scan_enabled=True,
        subdomain_modules=["dns", "ssl"],
        max_subdomain_concurrency=2,
        subdomain_scan_timeout=10,
        max_subdomains=5,
        ai_analysis_enabled=False,
    )
