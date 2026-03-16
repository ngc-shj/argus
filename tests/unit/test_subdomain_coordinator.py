"""Unit tests for SubdomainScanCoordinator."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus.models.subdomain_scan import SubdomainCandidate, SubdomainScanResult
from argus.models.target import ScanOptions
from argus.orchestration.subdomain_coordinator import SubdomainScanCoordinator


def make_options(**kwargs) -> ScanOptions:
    defaults = dict(
        subdomain_scan_enabled=True,
        subdomain_modules=["dns", "ssl"],
        max_subdomain_concurrency=2,
        subdomain_scan_timeout=10,
        max_subdomains=50,
        ai_analysis_enabled=False,
    )
    defaults.update(kwargs)
    return ScanOptions(**defaults)


def make_mock_dns_scanner(records=None):
    """Create a mock DNS scanner that returns a minimal result."""
    scanner = MagicMock()
    result = MagicMock()
    result.records = records or {"A": []}
    scanner.scan = AsyncMock(return_value=result)
    return scanner


def make_mock_ssl_scanner():
    scanner = MagicMock()
    scanner.scan = AsyncMock(return_value=MagicMock())
    return scanner


def make_candidates(*domains, cert_count=0, source="subdomain_enum") -> list[SubdomainCandidate]:
    return [SubdomainCandidate(domain=d, cert_count=cert_count, source=source) for d in domains]


class TestModuleValidation:
    async def test_unknown_module_raises_value_error(self):
        coord = SubdomainScanCoordinator(scanners={})
        candidates = make_candidates("sub.example.com")
        opts = make_options(subdomain_modules=["dns"])

        with pytest.raises(ValueError, match="Unknown subdomain module"):
            await coord.scan_subdomains(
                candidates,
                modules=["dns", "nonexistent_module"],
                options=opts,
            )

    async def test_valid_modules_proceed(self):
        dns_scanner = make_mock_dns_scanner()
        ssl_scanner = make_mock_ssl_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner, "ssl": ssl_scanner})

        candidates = [SubdomainCandidate(domain="sub.example.com", resolved_ips=["1.2.3.4"])]

        with patch.object(coord, "_resolve_subdomain", return_value=["1.2.3.4"]):
            results = await coord.scan_subdomains(
                candidates,
                modules=["dns", "ssl"],
                options=make_options(),
            )
        assert isinstance(results, list)


class TestMaxSubdomainsBoundary:
    @pytest.mark.parametrize(
        "num_candidates,max_subdomains,expected_scanned",
        [
            (0, 50, 0),
            (10, 50, 10),
            (50, 50, 50),
            (51, 50, 50),
            (1, 1, 1),
        ],
    )
    async def test_max_subdomains_cap(self, num_candidates, max_subdomains, expected_scanned):
        coord = SubdomainScanCoordinator(scanners={})

        candidates = [
            SubdomainCandidate(
                domain=f"sub{i}.example.com",
                cert_count=i,
                source="crtsh",
            )
            for i in range(num_candidates)
        ]
        opts = make_options(
            subdomain_modules=["dns"],
            max_subdomains=max_subdomains,
            max_subdomain_concurrency=10,
            subdomain_scan_timeout=10,
        )

        async def mock_scan_single(candidate, modules, options):
            return SubdomainScanResult(
                domain=candidate.domain,
                status="completed",
                resolved_ips=candidate.resolved_ips,
            )

        # Each candidate resolves to a unique IP to prevent wildcard dedup collapsing
        # the count. This isolates the max_subdomains cap logic.
        call_index = [0]

        async def mock_resolve(domain):
            idx = call_index[0]
            call_index[0] += 1
            # Generate unique IPs using idx modulo to stay in valid IPv4 range
            a = (idx // (256 * 256)) % 256
            b = (idx // 256) % 256
            c = idx % 256
            return [
                f"10.{a}.{b}.{c}"
            ]  # Private IPs, but SSRF validation is patched to isolate cap logic

        # Patch _validate_resolved_ips to accept all IPs (isolate cap logic)
        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            with patch.object(coord, "_validate_resolved_ips", side_effect=lambda ips: ips):
                with patch.object(coord, "_scan_single_subdomain", side_effect=mock_scan_single):
                    results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == expected_scanned


class TestWildcardDNSDeduplication:
    async def test_all_same_ip_scans_only_one(self):
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        candidates = make_candidates("a.example.com", "b.example.com", "c.example.com")
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=5)

        # All resolve to the same IP → wildcard dedup → only 1 scanned
        with patch.object(coord, "_resolve_subdomain", return_value=["1.2.3.4"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 1

    async def test_different_ips_all_scanned(self):
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        candidates = make_candidates("a.example.com", "b.example.com", "c.example.com")
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=5)

        ip_map = {
            "a.example.com": ["1.1.1.1"],
            "b.example.com": ["2.2.2.2"],
            "c.example.com": ["3.3.3.3"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 3

    async def test_partial_same_ip_correct_grouping(self):
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        # a and b share an IP, c has a different IP → 2 scanned
        candidates = make_candidates("a.example.com", "b.example.com", "c.example.com")
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=5)

        ip_map = {
            "a.example.com": ["1.1.1.1"],
            "b.example.com": ["1.1.1.1"],
            "c.example.com": ["2.2.2.2"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 2


class TestDNSFirstGating:
    async def test_no_aaaa_records_skips_other_modules(self):
        dns_scanner = make_mock_dns_scanner()
        ssl_scanner = make_mock_ssl_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner, "ssl": ssl_scanner})

        # No IPs resolved → dns-first gating should skip ssl
        candidates = [SubdomainCandidate(domain="nxdomain.example.com", resolved_ips=[])]
        opts = make_options(subdomain_modules=["dns", "ssl"])

        with patch.object(coord, "_resolve_subdomain", return_value=[]):
            results = await coord.scan_subdomains(candidates, modules=["dns", "ssl"], options=opts)

        # dns module was invoked; ssl scanner should not be called
        assert dns_scanner.scan.called
        ssl_scanner.scan.assert_not_called()

    async def test_no_dns_module_and_no_ips_skips_entirely(self):
        ssl_scanner = make_mock_ssl_scanner()
        coord = SubdomainScanCoordinator(scanners={"ssl": ssl_scanner})

        # No dns module, no resolved IPs → should be skipped entirely
        candidates = [SubdomainCandidate(domain="nxdomain.example.com", resolved_ips=[])]
        opts = make_options(subdomain_modules=["ssl"])

        with patch.object(coord, "_resolve_subdomain", return_value=[]):
            results = await coord.scan_subdomains(candidates, modules=["ssl"], options=opts)

        assert len(results) == 1
        assert results[0].status == "skipped"

    async def test_with_resolved_ips_calls_all_modules(self):
        dns_scanner = make_mock_dns_scanner()
        ssl_scanner = make_mock_ssl_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner, "ssl": ssl_scanner})

        candidates = [SubdomainCandidate(domain="sub.example.com", resolved_ips=["1.2.3.4"])]
        opts = make_options(subdomain_modules=["dns", "ssl"])

        with patch.object(coord, "_resolve_subdomain", return_value=["1.2.3.4"]):
            results = await coord.scan_subdomains(candidates, modules=["dns", "ssl"], options=opts)

        assert len(results) == 1
        ssl_scanner.scan.assert_called_once()


class TestDNSFailureHandling:
    async def test_dns_exception_remaining_modules_skipped(self):
        dns_scanner = MagicMock()
        dns_scanner.scan = AsyncMock(side_effect=RuntimeError("DNS lookup failed"))
        ssl_scanner = make_mock_ssl_scanner()

        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner, "ssl": ssl_scanner})

        candidates = [SubdomainCandidate(domain="sub.example.com", resolved_ips=["1.2.3.4"])]
        opts = make_options(subdomain_modules=["dns", "ssl"])

        with patch.object(coord, "_resolve_subdomain", return_value=["1.2.3.4"]):
            results = await coord.scan_subdomains(candidates, modules=["dns", "ssl"], options=opts)

        # Result should be returned with error info; ssl may or may not be called
        # but the scan should not propagate the exception
        assert len(results) == 1
        assert results[0].domain == "sub.example.com"


class TestErrorIsolation:
    async def test_one_failure_does_not_affect_others(self):
        call_count = 0

        async def mock_scan_single(candidate, modules, options):
            nonlocal call_count
            call_count += 1
            if candidate.domain == "broken.example.com":
                raise RuntimeError("Simulated failure")
            return SubdomainScanResult(
                domain=candidate.domain,
                status="completed",
                resolved_ips=candidate.resolved_ips,
            )

        coord = SubdomainScanCoordinator(scanners={})

        candidates = [
            SubdomainCandidate(domain="ok1.example.com", resolved_ips=["1.1.1.1"]),
            SubdomainCandidate(domain="broken.example.com", resolved_ips=["2.2.2.2"]),
            SubdomainCandidate(domain="ok2.example.com", resolved_ips=["3.3.3.3"]),
        ]
        opts = make_options(
            subdomain_modules=["dns"],
            max_subdomain_concurrency=3,
        )

        ip_map = {
            "ok1.example.com": ["1.1.1.1"],
            "broken.example.com": ["2.2.2.2"],
            "ok2.example.com": ["3.3.3.3"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            with patch.object(coord, "_scan_single_subdomain", side_effect=mock_scan_single):
                results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        # broken subdomain raises but others still succeed
        # gather(return_exceptions=True) handles the failure
        completed = [r for r in results if r.status == "completed"]
        assert len(completed) == 2
        domains = {r.domain for r in completed}
        assert "ok1.example.com" in domains
        assert "ok2.example.com" in domains
        assert "broken.example.com" not in {r.domain for r in results}


class TestTimeoutEnforcement:
    async def test_timeout_returns_partial_results(self):
        """Verify that partial results are collected when some scans exceed the timeout."""
        fast_result = SubdomainScanResult(
            domain="fast.example.com",
            status="completed",
            resolved_ips=["1.1.1.1"],
        )

        async def mock_scan_single(candidate, modules, options):
            if candidate.domain == "fast.example.com":
                # Returns immediately
                return fast_result
            else:
                # Blocks indefinitely; will be cancelled by the timeout
                await asyncio.sleep(999)
                return SubdomainScanResult(domain=candidate.domain, status="completed")

        coord = SubdomainScanCoordinator(scanners={})
        candidates = [
            SubdomainCandidate(domain="fast.example.com", resolved_ips=["1.1.1.1"]),
            SubdomainCandidate(domain="slow.example.com", resolved_ips=["2.2.2.2"]),
        ]
        opts = make_options(
            subdomain_modules=["dns"],
            max_subdomain_concurrency=2,
            subdomain_scan_timeout=10,
        )

        ip_map = {
            "fast.example.com": ["1.1.1.1"],
            "slow.example.com": ["2.2.2.2"],
        }

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        # Replace asyncio.wait_for with a version that lets fast tasks run first,
        # then raises TimeoutError so the partial-result collection path is exercised.
        original_wait_for = asyncio.wait_for

        async def selective_wait_for(coro, timeout):
            # Give already-scheduled tasks a chance to start and the fast one to finish
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            raise TimeoutError("simulated timeout after fast task completed")

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            with patch.object(coord, "_scan_single_subdomain", side_effect=mock_scan_single):
                with patch(
                    "argus.orchestration.subdomain_coordinator.asyncio.wait_for",
                    side_effect=selective_wait_for,
                ):
                    # Pre-create the scan tasks so they can run before wait_for is called.
                    # We need the fast task's future to be done when the TimeoutError fires.
                    # Schedule the actual gather with a real short wait_for, then patch raises.
                    #
                    # Simpler approach: run the coordinator and verify it returns a list
                    # (the fast task result is captured via task.result() in the TimeoutError handler).
                    results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        # At minimum, the scan returns a list without raising.
        # fast.example.com's task may or may not have been picked up depending on
        # event-loop scheduling; assert partial results are returned (not an exception).
        assert isinstance(results, list)
        assert len(results) >= 1
        assert "fast.example.com" in {r.domain for r in results}


class TestSSRFIPValidation:
    async def test_cloud_metadata_ip_skipped(self):
        coord = SubdomainScanCoordinator(scanners={})

        candidates = [SubdomainCandidate(domain="meta.example.com")]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=2)

        # Resolves to cloud metadata IP → should be excluded
        with patch.object(coord, "_resolve_subdomain", return_value=["169.254.169.254"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        # Subdomain resolving to blocked IP should be skipped
        assert len(results) == 0

    async def test_private_ip_skipped(self):
        coord = SubdomainScanCoordinator(scanners={})

        candidates = [SubdomainCandidate(domain="internal.example.com")]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=2)

        with patch.object(coord, "_resolve_subdomain", return_value=["10.0.0.1"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 0

    async def test_link_local_ipv6_skipped(self):
        coord = SubdomainScanCoordinator(scanners={})

        candidates = [SubdomainCandidate(domain="linklocal.example.com")]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=2)

        with patch.object(coord, "_resolve_subdomain", return_value=["fe80::1"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 0

    async def test_public_ip_not_skipped(self):
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        candidates = [SubdomainCandidate(domain="pub.example.com")]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=2)

        with patch.object(coord, "_resolve_subdomain", return_value=["8.8.8.8"]):
            results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == 1


class TestConcurrencyControl:
    async def test_semaphore_limits_parallelism(self):
        """Verify that at most max_subdomain_concurrency tasks run concurrently."""
        active = 0
        max_active = 0
        lock = asyncio.Lock()

        async def mock_scan_single(candidate, modules, options):
            nonlocal active, max_active
            async with lock:
                active += 1
                if active > max_active:
                    max_active = active
            await asyncio.sleep(0.05)
            async with lock:
                active -= 1
            return SubdomainScanResult(
                domain=candidate.domain,
                status="completed",
                resolved_ips=candidate.resolved_ips,
            )

        coord = SubdomainScanCoordinator(scanners={})
        num_candidates = 6
        candidates = [
            SubdomainCandidate(domain=f"sub{i}.example.com", resolved_ips=[f"1.2.3.{i + 1}"])
            for i in range(num_candidates)
        ]
        opts = make_options(
            subdomain_modules=["dns"],
            max_subdomain_concurrency=2,
        )

        ip_map = {f"sub{i}.example.com": [f"1.2.3.{i + 1}"] for i in range(num_candidates)}

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            with patch.object(coord, "_scan_single_subdomain", side_effect=mock_scan_single):
                results = await coord.scan_subdomains(candidates, modules=["dns"], options=opts)

        assert len(results) == num_candidates
        assert max_active <= 2


class TestProgressCallback:
    async def test_progress_callback_receives_correct_args(self):
        dns_scanner = make_mock_dns_scanner()
        coord = SubdomainScanCoordinator(scanners={"dns": dns_scanner})

        calls = []

        def progress_callback(subdomain: str, current: int, total: int):
            calls.append((subdomain, current, total))

        ip_map = {
            "a.example.com": ["1.1.1.1"],
            "b.example.com": ["2.2.2.2"],
            "c.example.com": ["3.3.3.3"],
        }
        candidates = [SubdomainCandidate(domain=d, resolved_ips=ips) for d, ips in ip_map.items()]
        opts = make_options(subdomain_modules=["dns"], max_subdomain_concurrency=3)

        async def mock_resolve(domain):
            return ip_map.get(domain, [])

        with patch.object(coord, "_resolve_subdomain", side_effect=mock_resolve):
            results = await coord.scan_subdomains(
                candidates,
                modules=["dns"],
                options=opts,
                progress_callback=progress_callback,
            )

        assert len(results) == 3
        assert len(calls) == 3
        # Each call receives the subdomain, a 1-based index, and the total count
        totals = {c[2] for c in calls}
        assert totals == {3}
        indices = {c[1] for c in calls}
        assert indices == {1, 2, 3}
        domains_called = {c[0] for c in calls}
        assert domains_called == {"a.example.com", "b.example.com", "c.example.com"}
