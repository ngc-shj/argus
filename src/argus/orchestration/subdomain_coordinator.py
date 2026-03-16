"""Subdomain scan coordinator for orchestrating recursive subdomain scanning."""

import asyncio
import time
from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network, IPv6Address

from pydantic import ValidationError

from argus.core.logging import get_logger
from argus.infrastructure.ratelimit import MultiRateLimiter
from argus.models.subdomain_scan import (
    ALLOWED_SUBDOMAIN_MODULES,
    SubdomainCandidate,
    SubdomainScanResult,
)
from argus.models.target import BLOCKED_IP_RANGES, CLOUD_METADATA_IPS, ScanOptions, ScanTarget

# HTTP-based modules that require rate limiter acquisition
_HTTP_MODULES = {"ssl", "headers", "webtech", "security", "discovery", "favicon", "graphql"}


class SubdomainScanCoordinator:
    """Coordinates scanning of discovered subdomains."""

    def __init__(self, scanners: dict | None = None) -> None:
        self.logger = get_logger("subdomain_coordinator")
        self._rate_limiter = MultiRateLimiter()

        if scanners is not None:
            self._scanners = scanners
        else:
            self._scanners = self._build_default_scanners()

    def _build_default_scanners(self) -> dict:
        from argus.scanners.discovery import DiscoveryScanner
        from argus.scanners.dns import DNSScanner
        from argus.scanners.favicon import FaviconScanner
        from argus.scanners.graphql import GraphQLScanner
        from argus.scanners.headers import SecurityHeadersScanner
        from argus.scanners.ports import PortScanner
        from argus.scanners.security import SecurityScanner
        from argus.scanners.ssl import SSLScanner
        from argus.scanners.webtech import WebTechScanner

        return {
            "dns": DNSScanner(),
            "ssl": SSLScanner(),
            "ports": PortScanner(),
            "headers": SecurityHeadersScanner(),
            "webtech": WebTechScanner(),
            "security": SecurityScanner(),
            "discovery": DiscoveryScanner(),
            "favicon": FaviconScanner(),
            "graphql": GraphQLScanner(),
        }

    async def scan_subdomains(
        self,
        candidates: list[SubdomainCandidate],
        modules: list[str],
        options: ScanOptions,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> list[SubdomainScanResult]:
        """Scan a list of subdomain candidates using the specified modules."""
        # Validate modules against allowed list
        unknown = [m for m in modules if m not in ALLOWED_SUBDOMAIN_MODULES]
        if unknown:
            raise ValueError(
                f"Unknown subdomain module(s): {unknown}. Allowed: {ALLOWED_SUBDOMAIN_MODULES}"
            )

        # Apply max_subdomains cap: prioritize by cert_count descending
        candidates = sorted(candidates, key=lambda c: c.cert_count, reverse=True)
        if len(candidates) > options.max_subdomains:
            self.logger.warning(
                "subdomain_cap_applied",
                total=len(candidates),
                cap=options.max_subdomains,
            )
            candidates = candidates[: options.max_subdomains]

        # DNS pre-resolution: resolve all candidates, populate resolved_ips
        self.logger.info("subdomain_pre_resolution_started", count=len(candidates))
        resolve_tasks = [self._resolve_subdomain(c.domain) for c in candidates]
        resolved_results = await asyncio.gather(*resolve_tasks, return_exceptions=True)

        for candidate, result in zip(candidates, resolved_results, strict=True):
            if isinstance(result, Exception):
                self.logger.debug(
                    "subdomain_resolution_failed",
                    domain=candidate.domain,
                    error=str(result),
                )
                candidate.resolved_ips = []
            else:
                candidate.resolved_ips = result  # type: ignore[assignment]

        # SSRF IP validation: exclude subdomains resolving to private/blocked IPs
        safe_candidates: list[SubdomainCandidate] = []
        for candidate in candidates:
            if not candidate.resolved_ips:
                safe_candidates.append(candidate)
                continue
            valid_ips = self._validate_resolved_ips(candidate.resolved_ips)
            if len(valid_ips) < len(candidate.resolved_ips):
                blocked = set(candidate.resolved_ips) - set(valid_ips)
                self.logger.warning(
                    "subdomain_ssrf_excluded",
                    domain=candidate.domain,
                    blocked_ips=list(blocked),
                )
                if not valid_ips:
                    # All IPs blocked — skip this subdomain entirely
                    continue
                candidate.resolved_ips = valid_ips
            safe_candidates.append(candidate)

        # Wildcard deduplication: keep one representative per unique resolved IP set
        deduped = self._deduplicate_wildcards(safe_candidates)
        merged_count = len(safe_candidates) - len(deduped)
        if merged_count > 0:
            self.logger.info(
                "subdomain_wildcard_dedup",
                before=len(safe_candidates),
                after=len(deduped),
                merged=merged_count,
            )

        total = len(deduped)
        self.logger.info("subdomain_scan_started", total=total, modules=modules)

        results: list[SubdomainScanResult] = []

        async def _scan_with_semaphore(
            semaphore: asyncio.Semaphore,
            candidate: SubdomainCandidate,
            index: int,
        ) -> SubdomainScanResult | None:
            async with semaphore:
                if progress_callback:
                    try:
                        progress_callback(candidate.domain, index, total)
                    except Exception:  # noqa: S110
                        pass  # Progress callback failure should not block scanning
                return await self._scan_single_subdomain(candidate, modules, options)

        semaphore = asyncio.Semaphore(options.max_subdomain_concurrency)
        scan_tasks = [
            asyncio.ensure_future(_scan_with_semaphore(semaphore, candidate, idx + 1))
            for idx, candidate in enumerate(deduped)
        ]

        # Enforce global timeout; return partial results on timeout
        try:
            completed = await asyncio.wait_for(
                asyncio.gather(*scan_tasks, return_exceptions=True),
                timeout=options.subdomain_scan_timeout,
            )
            for item in completed:
                if isinstance(item, Exception):
                    self.logger.debug("subdomain_task_error", error=str(item))
                elif item is not None:
                    results.append(item)
        except TimeoutError:
            self.logger.warning(
                "subdomain_scan_timeout",
                timeout=options.subdomain_scan_timeout,
                completed=len(results),
                total=total,
            )
            for task in scan_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*scan_tasks, return_exceptions=True)
            for task in scan_tasks:
                if task.done() and not task.cancelled():
                    try:
                        item = task.result()
                        if isinstance(item, SubdomainScanResult):
                            results.append(item)
                    except Exception:
                        pass

        return results

    async def _resolve_subdomain(self, domain: str) -> list[str]:
        """Resolve A and AAAA records for a subdomain."""
        ips: list[str] = []
        loop = asyncio.get_running_loop()

        try:
            infos = await loop.getaddrinfo(domain, None)
            for info in infos:
                ip_str = info[4][0]
                if ip_str not in ips:
                    ips.append(ip_str)
        except OSError:
            pass

        return ips

    def _validate_resolved_ips(self, ips: list[str]) -> list[str]:
        """Filter out private, reserved, or blocked IPs."""
        valid: list[str] = []
        for ip_str in ips:
            try:
                if "." in ip_str:
                    ip = IPv4Address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_reserved:
                        continue
                    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                        continue
                    if ip_str in CLOUD_METADATA_IPS:
                        continue
                    blocked = any(
                        ip in net for net in BLOCKED_IP_RANGES if isinstance(net, IPv4Network)
                    )
                    if blocked:
                        continue
                else:
                    ip6 = IPv6Address(ip_str)
                    if ip6.is_private or ip6.is_loopback or ip6.is_reserved:
                        continue
                    if ip6.is_link_local or ip6.is_multicast or ip6.is_unspecified:
                        continue
                    if ip6.ipv4_mapped is not None:
                        mapped = ip6.ipv4_mapped
                        if mapped.is_link_local or mapped.is_multicast or mapped.is_unspecified:
                            continue
                        if str(mapped) in CLOUD_METADATA_IPS:
                            continue
                        if any(
                            mapped in net
                            for net in BLOCKED_IP_RANGES
                            if isinstance(net, IPv4Network)
                        ):
                            continue
                valid.append(ip_str)
            except ValueError:
                self.logger.debug("invalid_ip_skipped", ip=ip_str)
        return valid

    def _deduplicate_wildcards(
        self, candidates: list[SubdomainCandidate]
    ) -> list[SubdomainCandidate]:
        """Deduplicate subdomains that share the same resolved IP set (wildcard DNS)."""
        seen_ip_sets: dict[frozenset, SubdomainCandidate] = {}
        unique: list[SubdomainCandidate] = []

        for candidate in candidates:
            if not candidate.resolved_ips:
                # No IPs resolved — keep as-is (DNS-first gating will skip later)
                unique.append(candidate)
                continue

            ip_key = frozenset(candidate.resolved_ips)
            if ip_key not in seen_ip_sets:
                seen_ip_sets[ip_key] = candidate
                unique.append(candidate)
            else:
                self.logger.debug(
                    "subdomain_wildcard_merged",
                    kept=seen_ip_sets[ip_key].domain,
                    discarded=candidate.domain,
                    ips=list(ip_key),
                )

        return unique

    async def _scan_single_subdomain(
        self,
        candidate: SubdomainCandidate,
        modules: list[str],
        options: ScanOptions,
    ) -> SubdomainScanResult:
        """Scan a single subdomain, isolating errors per module."""
        start_time = time.time()
        result = SubdomainScanResult(
            domain=candidate.domain,
            status="pending",
            resolved_ips=list(candidate.resolved_ips),
        )
        modules_run: list[str] = []

        # DNS-first gating: skip if no A/AAAA resolved
        if not candidate.resolved_ips and "dns" not in modules:
            result.status = "skipped"
            result.error = "No A/AAAA records resolved"
            result.duration_seconds = time.time() - start_time
            result.modules_run = modules_run
            self.logger.debug("subdomain_skipped_no_dns", domain=candidate.domain)
            return result

        # Create ScanTarget — catch ValidationError and skip
        try:
            scan_target = ScanTarget(domain=candidate.domain)
        except ValidationError as e:
            result.status = "skipped"
            result.error = f"Invalid target: {e}"
            result.duration_seconds = time.time() - start_time
            result.modules_run = modules_run
            self.logger.warning(
                "subdomain_target_validation_failed",
                domain=candidate.domain,
                error=str(e),
            )
            return result

        try:
            for module in modules:
                # DNS-first gating for non-DNS modules
                if module != "dns" and not candidate.resolved_ips:
                    self.logger.debug(
                        "subdomain_module_skipped_no_dns",
                        domain=candidate.domain,
                        module=module,
                    )
                    continue

                # Acquire rate limiter before HTTP-based modules
                if module in _HTTP_MODULES:
                    await self._rate_limiter.acquire("http")

                try:
                    await self._run_module(result, scan_target, module, options)
                    modules_run.append(module)
                except Exception as e:
                    self.logger.warning(
                        "subdomain_module_failed",
                        domain=candidate.domain,
                        module=module,
                        error=str(e),
                    )
                    if result.error is None:
                        result.error = f"{module}: {e}"

            result.status = "completed"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            self.logger.error(
                "subdomain_scan_failed",
                domain=candidate.domain,
                error=str(e),
            )
        finally:
            result.duration_seconds = time.time() - start_time
            result.modules_run = modules_run

        return result

    async def _run_module(
        self,
        result: SubdomainScanResult,
        target: ScanTarget,
        module: str,
        options: ScanOptions,
    ) -> None:
        """Run a single scanner module and store the result."""
        scanner = self._scanners.get(module)
        if scanner is None:
            self.logger.warning("subdomain_scanner_not_found", module=module)
            return

        hostname = target.domain or target.ip_address

        if module == "dns":
            await self._rate_limiter.acquire("dns")
            scan_result = await scanner.scan(target, options)
            result.dns_result = scan_result
            # Update resolved_ips from actual DNS scan if we have results
            if scan_result and scan_result.records.get("A"):
                ips = [r.value for r in scan_result.records["A"]]
                if ips:
                    result.resolved_ips = ips

        elif module == "ssl":
            scan_result = await scanner.scan(target)
            result.ssl_result = scan_result

        elif module == "ports":
            await self._rate_limiter.acquire("ports")
            scan_result = await scanner.scan(target, options)
            result.port_result = scan_result

        elif module == "headers":
            scan_result = await scanner.scan(hostname)
            result.headers_result = scan_result

        elif module == "webtech":
            scan_result = await scanner.scan(target, options)
            result.webtech_result = scan_result

        elif module == "security":
            scan_result = await scanner.scan(hostname)
            result.security_result = scan_result

        elif module == "discovery":
            scan_result = await scanner.scan(hostname)
            result.discovery_result = scan_result

        elif module == "favicon":
            scan_result = await scanner.scan(hostname)
            result.favicon_result = scan_result

        elif module == "graphql":
            scan_result = await scanner.scan(hostname)
            result.graphql_result = scan_result

        else:
            self.logger.warning("subdomain_unknown_module", module=module)
