"""Integration tests for subdomain scan flow with mocked scanners."""

from unittest.mock import AsyncMock, MagicMock, patch

from argus.models.scan import ScanSession, ScanStatus
from argus.models.subdomain_scan import SubdomainCandidate, SubdomainScanResult
from argus.models.target import ScanOptions, ScanTarget
from argus.orchestration.subdomain_coordinator import SubdomainScanCoordinator


def make_options(**kwargs) -> ScanOptions:
    defaults = dict(
        subdomain_scan_enabled=True,
        subdomain_modules=["dns", "ssl"],
        max_subdomain_concurrency=3,
        subdomain_scan_timeout=30,
        max_subdomains=10,
        ai_analysis_enabled=False,
    )
    defaults.update(kwargs)
    return ScanOptions(**defaults)


def make_mock_dns_scanner(ip="1.2.3.4"):
    scanner = MagicMock()
    dns_result = MagicMock()
    dns_result.records = {"A": [MagicMock(value=ip)]}
    scanner.scan = AsyncMock(return_value=dns_result)
    return scanner


def make_mock_ssl_scanner():
    scanner = MagicMock()
    scanner.scan = AsyncMock(return_value=MagicMock())
    return scanner


class TestFullScanFlowWithMockedScanners:
    async def test_scan_returns_results_for_all_unique_subdomains(self):
        dns_scanner = make_mock_dns_scanner()
        ssl_scanner = make_mock_ssl_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner, "ssl": ssl_scanner})

        candidates = [
            SubdomainCandidate(domain="api.example.com", cert_count=2, source="crtsh"),
            SubdomainCandidate(domain="www.example.com", cert_count=1, source="crtsh"),
            SubdomainCandidate(domain="mail.example.com", cert_count=0, source="subdomain_enum"),
        ]
        opts = make_options()

        ip_map = {
            "api.example.com": ["1.1.1.1"],
            "www.example.com": ["2.2.2.2"],
            "mail.example.com": ["3.3.3.3"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns", "ssl"], options=opts)

        assert len(results) == 3
        domains = {r.domain for r in results}
        assert domains == {"api.example.com", "www.example.com", "mail.example.com"}

    async def test_all_results_stored_in_scan_session(self):
        """Integration test: verify results can be stored on ScanSession."""
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        candidates = [
            SubdomainCandidate(domain="sub.example.com", cert_count=1, source="crtsh"),
        ]
        opts = make_options(subdomain_modules=["dns"])

        with patch.object(coord, "_resolve_subdomain", return_value=["1.2.3.4"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        # Verify results can be assigned to a ScanSession
        session = ScanSession(
            target=ScanTarget(domain="example.com"),
            options=opts,
            status=ScanStatus.COMPLETED,
            subdomain_scan_results=results,
        )
        assert session.subdomain_scan_results is not None
        assert len(session.subdomain_scan_results) == 1
        assert session.subdomain_scan_results[0].domain == "sub.example.com"

    async def test_session_json_serialization_includes_subdomain_results(self):
        """Integration test: JSON output contains subdomain_scan_results."""
        result = SubdomainScanResult(
            domain="sub.example.com",
            status="completed",
            resolved_ips=["1.2.3.4"],
            modules_run=["dns"],
        )
        session = ScanSession(
            target=ScanTarget(domain="example.com"),
            status=ScanStatus.COMPLETED,
            subdomain_scan_results=[result],
        )
        data = session.to_json_dict()
        assert "subdomain_scan_results" in data
        assert data["subdomain_scan_results"] is not None
        assert len(data["subdomain_scan_results"]) == 1
        assert data["subdomain_scan_results"][0]["domain"] == "sub.example.com"


class TestSubdomainDeduplicationFromMultipleSources:
    async def test_crtsh_and_subdomain_enum_combined_dedup(self):
        """Test that overlapping subdomains from crtsh and subdomain_enum are deduped."""
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        # Simulate overlap: "www" appears in both sources
        candidates = [
            SubdomainCandidate(domain="www.example.com", cert_count=3, source="crtsh"),
            SubdomainCandidate(domain="www.example.com", cert_count=0, source="subdomain_enum"),
            SubdomainCandidate(domain="api.example.com", cert_count=1, source="crtsh"),
        ]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=5)

        ip_map = {
            "www.example.com": ["1.1.1.1"],
            "api.example.com": ["2.2.2.2"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        # www resolves to same IP in both entries → deduped to 1
        # api has unique IP → 1 more
        # Total: 2 (not 3)
        assert len(results) == 2

    async def test_cert_count_ordering_for_max_subdomains_cap(self):
        """When cap applied, higher cert_count subdomains are preferred."""
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        # 5 candidates but max_subdomains=3
        candidates = [
            SubdomainCandidate(domain="low.example.com", cert_count=1, source="crtsh"),
            SubdomainCandidate(domain="high1.example.com", cert_count=10, source="crtsh"),
            SubdomainCandidate(domain="mid.example.com", cert_count=5, source="crtsh"),
            SubdomainCandidate(domain="zero.example.com", cert_count=0, source="subdomain_enum"),
            SubdomainCandidate(domain="high2.example.com", cert_count=8, source="crtsh"),
        ]
        opts = make_options(
            subdomain_modules=["dns"],
            max_subdomains=3,
            max_subdomain_concurrency=5,
        )

        ip_map = {
            "high1.example.com": ["1.1.1.1"],
            "high2.example.com": ["2.2.2.2"],
            "mid.example.com": ["3.3.3.3"],
            "low.example.com": ["4.4.4.4"],
            "zero.example.com": ["5.5.5.5"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 3
        scanned_domains = {r.domain for r in results}
        # high1 (10), high2 (8), mid (5) should be selected
        assert "high1.example.com" in scanned_domains
        assert "high2.example.com" in scanned_domains
        assert "mid.example.com" in scanned_domains


class TestEmptySubdomainList:
    async def test_empty_candidates_returns_empty_list(self):
        coord = SubdomainScanCoordinator(scanners={})
        opts = make_options()

        results = await coord.scan_subdomains([], modules=["dns"], options=opts)

        assert results == []

    async def test_all_candidates_ssrf_filtered_returns_empty(self):
        coord = SubdomainScanCoordinator(scanners={})
        candidates = [
            SubdomainCandidate(domain="internal.example.com"),
            SubdomainCandidate(domain="meta.example.com"),
        ]
        opts = make_options(subdomain_modules=["dns"])

        # All resolve to blocked IPs
        async def mock_resolve(domain):
            return ["10.0.0.1"]  # Private IP

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert results == []
