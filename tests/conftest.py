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
