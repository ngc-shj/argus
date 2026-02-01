"""DNS Scanner implementation."""

import asyncio
import time
from datetime import datetime

import dns.asyncresolver
import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.xfr
import dns.zone

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.dns import DNSRecord, DNSScanResult, SubdomainResult
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "secure", "vpn", "api", "dev", "staging", "test", "blog", "shop",
    "app", "m", "mobile", "portal", "cdn", "static", "assets", "img", "images",
    "media", "video", "docs", "support", "help", "status", "monitor", "grafana",
    "prometheus", "jenkins", "gitlab", "git", "svn", "wiki", "jira", "confluence",
]


@ScannerRegistry.register
class DNSScanner(BaseScanner[DNSScanResult]):
    """DNS information scanner."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS record enumeration and subdomain discovery"

    def get_capabilities(self) -> list[str]:
        return [
            "A/AAAA record lookup",
            "MX record lookup",
            "NS record lookup",
            "TXT record lookup",
            "CNAME record lookup",
            "SOA record lookup",
            "Subdomain enumeration",
            "DNSSEC detection",
            "Zone transfer check",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate that target has a domain."""
        return target.domain is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> DNSScanResult:
        """Execute DNS scan."""
        if not target.domain:
            raise ScanError("Domain is required for DNS scan", scanner=self.name)

        options = options or ScanOptions()
        settings = get_settings()
        start_time = time.time()

        self.logger.info("dns_scan_started", target=target.domain)

        # Configure resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.dns_timeout
        resolver.lifetime = settings.dns_timeout

        try:
            # Gather DNS records
            records = await self._gather_records(
                resolver, target.domain, options.dns_record_types
            )

            # Get nameservers
            nameservers = await self._get_nameservers(resolver, target.domain)

            # Check DNSSEC
            dnssec_enabled = await self._check_dnssec(resolver, target.domain)

            # Check zone transfer
            zone_transfer_vulnerable = await self._check_zone_transfer(
                target.domain, nameservers
            )

            # Subdomain enumeration
            subdomains = []
            if options.dns_subdomain_enum:
                subdomains = await self._enumerate_subdomains(
                    resolver, target.domain, options
                )

            duration = time.time() - start_time

            result = DNSScanResult(
                target=target.domain,
                records=records,
                subdomains=subdomains,
                nameservers=nameservers,
                zone_transfer_vulnerable=zone_transfer_vulnerable,
                dnssec_enabled=dnssec_enabled,
                scanned_at=datetime.utcnow(),
                duration_seconds=duration,
            )

            self.logger.info(
                "dns_scan_completed",
                target=target.domain,
                total_records=result.total_records,
                subdomains=len(subdomains),
                duration=duration,
            )

            return result

        except Exception as e:
            self.logger.error("dns_scan_failed", target=target.domain, error=str(e))
            raise ScanError(
                f"DNS scan failed: {e}",
                scanner=self.name,
                target=target.domain,
            ) from e

    async def _gather_records(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
        record_types: list[str],
    ) -> dict[str, list[DNSRecord]]:
        """Gather DNS records for all specified types."""
        records: dict[str, list[DNSRecord]] = {}

        async def fetch_record(rtype: str) -> tuple[str, list[DNSRecord]]:
            try:
                rdtype = dns.rdatatype.from_text(rtype)
                answer = await resolver.resolve(domain, rdtype)

                recs = []
                for rdata in answer:
                    value = str(rdata)
                    priority = None

                    if rtype == "MX":
                        priority = rdata.preference
                        value = str(rdata.exchange)

                    recs.append(
                        DNSRecord(
                            record_type=rtype,
                            name=domain,
                            value=value,
                            ttl=answer.ttl,
                            priority=priority,
                        )
                    )
                return rtype, recs
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                return rtype, []
            except Exception as e:
                self.logger.debug("dns_record_error", rtype=rtype, error=str(e))
                return rtype, []

        # Fetch all record types concurrently
        tasks = [fetch_record(rtype) for rtype in record_types]
        results = await asyncio.gather(*tasks)

        for rtype, recs in results:
            if recs:
                records[rtype] = recs

        return records

    async def _get_nameservers(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
    ) -> list[str]:
        """Get nameservers for domain."""
        try:
            answer = await resolver.resolve(domain, "NS")
            return [str(ns).rstrip(".") for ns in answer]
        except Exception:
            return []

    async def _check_dnssec(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
    ) -> bool:
        """Check if DNSSEC is enabled."""
        try:
            await resolver.resolve(domain, "DNSKEY")
            return True
        except Exception:
            return False

    async def _check_zone_transfer(
        self,
        domain: str,
        nameservers: list[str],
    ) -> bool:
        """Check if zone transfer (AXFR) is possible (critical security issue)."""
        if not nameservers:
            return False

        async def try_zone_transfer(ns: str) -> bool:
            """Try zone transfer against a single nameserver."""
            try:
                # Resolve the nameserver hostname to IP
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5.0
                resolver.lifetime = 5.0

                try:
                    ns_ips = resolver.resolve(ns, "A")
                    ns_ip = str(ns_ips[0])
                except Exception:
                    # If we can't resolve the NS, skip it
                    return False

                # Attempt zone transfer (synchronous operation wrapped in asyncio)
                def do_transfer() -> bool:
                    try:
                        # Try AXFR (full zone transfer)
                        xfr = dns.query.xfr(ns_ip, domain, timeout=5.0)
                        zone = dns.zone.from_xfr(xfr)

                        # If we get here without exception, zone transfer succeeded
                        # Check if zone has records
                        if zone and len(list(zone.nodes)) > 0:
                            self.logger.warning(
                                "zone_transfer_vulnerable",
                                domain=domain,
                                nameserver=ns,
                                records_count=len(list(zone.nodes)),
                            )
                            return True
                    except dns.xfr.TransferError:
                        # Transfer was refused - this is the expected secure behavior
                        pass
                    except dns.exception.FormError:
                        # Malformed response - transfer not supported properly
                        pass
                    except Exception as e:
                        # Other errors (timeout, connection refused, etc.)
                        self.logger.debug(
                            "zone_transfer_check_error",
                            nameserver=ns,
                            error=str(e),
                        )
                    return False

                # Run the synchronous zone transfer in a thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, do_transfer)

            except Exception as e:
                self.logger.debug("zone_transfer_error", ns=ns, error=str(e))
                return False

        # Check zone transfer against all nameservers (limit to 3)
        tasks = [try_zone_transfer(ns) for ns in nameservers[:3]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Return True if any nameserver allows zone transfer
        for result in results:
            if result is True:
                return True

        return False

    async def _enumerate_subdomains(
        self,
        resolver: dns.asyncresolver.Resolver,
        domain: str,
        options: ScanOptions,
    ) -> list[SubdomainResult]:
        """Enumerate subdomains using wordlist."""
        subdomains: list[SubdomainResult] = []
        settings = get_settings()

        # Get wordlist based on options
        wordlist = COMMON_SUBDOMAINS
        if options.dns_wordlist == "medium":
            wordlist = COMMON_SUBDOMAINS * 2  # Simplified for now
        elif options.dns_wordlist == "large":
            wordlist = COMMON_SUBDOMAINS * 3

        # Limit concurrency
        semaphore = asyncio.Semaphore(settings.dns_queries_per_second)

        async def check_subdomain(subdomain: str) -> SubdomainResult | None:
            async with semaphore:
                full_domain = f"{subdomain}.{domain}"
                try:
                    answer = await resolver.resolve(full_domain, "A")
                    ips = [str(rdata) for rdata in answer]

                    # Check for CNAME
                    cname_chain = []
                    try:
                        cname_answer = await resolver.resolve(full_domain, "CNAME")
                        cname_chain = [str(rdata).rstrip(".") for rdata in cname_answer]
                    except Exception:
                        # CNAME lookup failures are expected for most subdomains
                        cname_chain = []

                    return SubdomainResult(
                        subdomain=subdomain,
                        full_domain=full_domain,
                        resolved_ips=ips,
                        cname_chain=cname_chain,
                        status="active",
                    )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    return None
                except Exception:
                    return None

        # Check all subdomains concurrently
        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                subdomains.append(result)

        return subdomains
