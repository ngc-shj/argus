"""Scan coordinator for orchestrating multiple scanners."""

import asyncio
from datetime import datetime
from typing import Any

from argus.core.logging import get_logger
from argus.models import ScanTarget, ScanOptions, ScanSession
from argus.models.base import ScanStatus
from argus.models.scan import ModuleProgress
from argus.scanners.dns import DNSScanner
from argus.scanners.whois.scanner import WHOISScanner, RDAPScanner
from argus.scanners.ports import PortScanner
from argus.scanners.webtech import WebTechScanner
from argus.scanners.crtsh import CrtshScanner
from argus.scanners.vuln import VulnScanner
from argus.scanners.ssl import SSLScanner
from argus.scanners.email import EmailSecurityScanner
from argus.scanners.security import SecurityScanner
from argus.scanners.js import JSAnalysisScanner
from argus.scanners.takeover import TakeoverScanner
from argus.scanners.subdomain import SubdomainEnumerator
from argus.scanners.kev import KEVChecker
from argus.scanners.headers import SecurityHeadersScanner
from argus.scanners.discovery import DiscoveryScanner
from argus.scanners.favicon import FaviconScanner
from argus.scanners.asn import ASNScanner
from argus.scanners.wayback import WaybackScanner
from argus.scanners.graphql import GraphQLScanner


class ScanCoordinator:
    """Coordinates multiple scanners for a complete reconnaissance."""

    def __init__(self) -> None:
        self.logger = get_logger("coordinator")
        self._scanners = {
            "dns": DNSScanner(),
            "whois": WHOISScanner(),
            "rdap": RDAPScanner(),
            "ports": PortScanner(),
            "webtech": WebTechScanner(),
            "crtsh": CrtshScanner(),
        }
        self._vuln_scanner = VulnScanner()
        self._ssl_scanner = SSLScanner()
        self._email_scanner = EmailSecurityScanner()
        self._security_scanner = SecurityScanner()
        self._js_scanner = JSAnalysisScanner()
        self._takeover_scanner = TakeoverScanner()
        self._subdomain_enum = SubdomainEnumerator()
        self._kev_checker = KEVChecker()
        self._headers_scanner = SecurityHeadersScanner()
        self._discovery_scanner = DiscoveryScanner()
        self._favicon_scanner = FaviconScanner()
        self._asn_scanner = ASNScanner()
        self._wayback_scanner = WaybackScanner()
        self._graphql_scanner = GraphQLScanner()

    async def run_scan(
        self,
        target: ScanTarget,
        options: ScanOptions,
    ) -> ScanSession:
        """Run a complete scan with all enabled modules."""
        session = ScanSession(
            target=target,
            options=options,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self.logger.info(
            "scan_started",
            scan_id=str(session.id),
            target=target.identifier,
        )

        # Determine which modules to run
        modules_to_run = self._get_enabled_modules(options)

        # Initialize progress tracking
        for module in modules_to_run:
            session.progress.append(
                ModuleProgress(
                    module=module,
                    status=ScanStatus.PENDING,
                )
            )

        # Run all enabled scanners concurrently
        tasks = []
        for module in modules_to_run:
            task = self._run_scanner(session, module, target, options)
            tasks.append(task)

        # Wait for all scanners to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Run post-processing scans that depend on other results
        await self._run_post_scans(session, options)

        # Run AI analysis if enabled
        if options.ai_analysis_enabled:
            await self._run_ai_analysis(session)

        # Mark session as complete
        session.status = ScanStatus.COMPLETED
        session.completed_at = datetime.utcnow()

        self.logger.info(
            "scan_completed",
            scan_id=str(session.id),
            target=target.identifier,
            duration=session.duration_seconds,
        )

        return session

    def _get_enabled_modules(self, options: ScanOptions) -> list[str]:
        """Get list of enabled modules based on options."""
        modules = []
        if options.dns_enabled:
            modules.append("dns")
        if options.whois_enabled:
            modules.append("whois")
        if options.rdap_enabled:
            modules.append("rdap")
        if options.port_scan_enabled:
            modules.append("ports")
        if options.webtech_enabled:
            modules.append("webtech")
        if options.crtsh_enabled:
            modules.append("crtsh")
        if options.ssl_scan_enabled:
            modules.append("ssl")
        if options.email_scan_enabled:
            modules.append("email")
        if options.security_scan_enabled:
            modules.append("security")
        if options.js_analysis_enabled:
            modules.append("js")
        if options.headers_scan_enabled:
            modules.append("headers")
        if options.discovery_scan_enabled:
            modules.append("discovery")
        if options.favicon_scan_enabled:
            modules.append("favicon")
        if options.asn_scan_enabled:
            modules.append("asn")
        if options.graphql_scan_enabled:
            modules.append("graphql")
        return modules

    async def _run_scanner(
        self,
        session: ScanSession,
        module: str,
        target: ScanTarget,
        options: ScanOptions,
    ) -> None:
        """Run a single scanner module."""
        # Handle specialized scanners that don't follow the standard interface
        if module == "ssl":
            await self._run_ssl_scan(session, target)
            return
        elif module == "email":
            await self._run_email_scan(session, target)
            return
        elif module == "security":
            await self._run_security_scan(session, target)
            return
        elif module == "js":
            await self._run_js_scan(session, target)
            return
        elif module == "headers":
            await self._run_headers_scan(session, target)
            return
        elif module == "discovery":
            await self._run_discovery_scan(session, target)
            return
        elif module == "favicon":
            await self._run_favicon_scan(session, target)
            return
        elif module == "asn":
            await self._run_asn_scan(session, target)
            return
        elif module == "graphql":
            await self._run_graphql_scan(session, target)
            return

        scanner = self._scanners.get(module)
        if not scanner:
            self.logger.warning("scanner_not_found", module=module)
            return

        # Update progress to running
        progress = self._get_progress(session, module)
        if progress:
            progress.status = ScanStatus.RUNNING
            progress.started_at = datetime.utcnow()

        try:
            # Validate target
            if not await scanner.validate_target(target):
                self.logger.info(
                    "scanner_skipped",
                    module=module,
                    reason="invalid_target",
                )
                if progress:
                    progress.status = ScanStatus.COMPLETED
                    progress.message = "Skipped - invalid target"
                    progress.completed_at = datetime.utcnow()
                return

            # Run scan
            result = await scanner.scan(target, options)

            # Store result
            self._store_result(session, module, result)

            # Update progress
            if progress:
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100
                progress.completed_at = datetime.utcnow()

        except Exception as e:
            self.logger.error(
                "scanner_failed",
                module=module,
                error=str(e),
            )

            if progress:
                progress.status = ScanStatus.FAILED
                progress.error = str(e)
                progress.completed_at = datetime.utcnow()

            session.errors.append(f"{module}: {e}")

    def _get_progress(self, session: ScanSession, module: str) -> ModuleProgress | None:
        """Get progress object for a module."""
        for progress in session.progress:
            if progress.module == module:
                return progress
        return None

    def _store_result(self, session: ScanSession, module: str, result: Any) -> None:
        """Store scanner result in session."""
        if module == "dns":
            session.dns_result = result
        elif module == "whois":
            session.whois_result = result
        elif module == "rdap":
            session.rdap_result = result
        elif module == "ports":
            session.port_result = result
        elif module == "webtech":
            session.webtech_result = result
        elif module == "crtsh":
            session.crtsh_result = result
        elif module == "vuln":
            session.vuln_result = result
        elif module == "ssl":
            session.ssl_result = result
        elif module == "email":
            session.email_result = result
        elif module == "security":
            session.security_result = result
        elif module == "headers":
            session.headers_result = result
        elif module == "discovery":
            session.discovery_result = result
        elif module == "favicon":
            session.favicon_result = result
        elif module == "asn":
            session.asn_result = result
        elif module == "graphql":
            session.graphql_result = result

    async def _run_post_scans(self, session: ScanSession, options: ScanOptions) -> None:
        """Run scans that depend on results from other modules."""
        tasks = []

        # Vulnerability scan (depends on webtech)
        if options.vuln_scan_enabled and session.webtech_result:
            tasks.append(self._run_vuln_scan(session, options))

        # KEV check (depends on vuln scan)
        if options.kev_check_enabled:
            tasks.append(self._run_kev_check(session))

        # Subdomain takeover (depends on DNS/crtsh results)
        if options.takeover_scan_enabled:
            tasks.append(self._run_takeover_scan(session))

        # Extended subdomain enumeration
        if options.subdomain_enum_extended and session.target.domain:
            tasks.append(self._run_extended_subdomain_enum(session))

        # Wayback Machine URL extraction (disabled by default, can be slow)
        if options.wayback_scan_enabled and session.target.domain:
            tasks.append(self._run_wayback_scan(session))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_ssl_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run SSL/TLS certificate scan."""
        progress = ModuleProgress(
            module="ssl",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            if target.domain or target.ip_address:
                result = await self._ssl_scanner.scan(target)
                session.ssl_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "ssl_scan_completed",
                    target=target.identifier,
                    grade=result.grade,
                )
        except Exception as e:
            self.logger.error("ssl_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"ssl: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_email_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run email security scan."""
        if not target.domain:
            return

        progress = ModuleProgress(
            module="email",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._email_scanner.scan(target)
            session.email_result = result
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100

            self.logger.info(
                "email_scan_completed",
                target=target.domain,
                score=result.security_score,
                grade=result.security_grade,
            )
        except Exception as e:
            self.logger.error("email_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"email: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_security_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run security scan (exposed files, CORS, etc.)."""
        progress = ModuleProgress(
            module="security",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._security_scanner.scan(hostname)
                session.security_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "security_scan_completed",
                    target=hostname,
                    findings=result.total_findings,
                    critical=result.critical_count,
                )
        except Exception as e:
            self.logger.error("security_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"security: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_js_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run JavaScript analysis scan."""
        progress = ModuleProgress(
            module="js",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._js_scanner.scan(hostname)
                session.js_analysis = {
                    "target": result.target,
                    "js_files_analyzed": result.js_files_analyzed,
                    "secrets_found": len(result.secrets),
                    "endpoints_found": len(result.endpoints),
                    "secrets": [s.model_dump() for s in result.secrets],
                    "endpoints": [e.model_dump() for e in result.endpoints],
                }
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "js_scan_completed",
                    target=hostname,
                    secrets_found=len(result.secrets),
                    endpoints_found=len(result.endpoints),
                )
        except Exception as e:
            self.logger.error("js_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"js: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_headers_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run HTTP security headers scan."""
        progress = ModuleProgress(
            module="headers",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._headers_scanner.scan(hostname)
                session.headers_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "headers_scan_completed",
                    target=hostname,
                    score=result.score,
                    grade=result.grade,
                )
        except Exception as e:
            self.logger.error("headers_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"headers: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_discovery_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run discovery scan (robots.txt, sitemap.xml, etc.)."""
        progress = ModuleProgress(
            module="discovery",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._discovery_scanner.scan(hostname)
                session.discovery_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "discovery_scan_completed",
                    target=hostname,
                    robots_found=result.robots is not None and result.robots.found,
                    sitemap_found=result.sitemap is not None and result.sitemap.found,
                )
        except Exception as e:
            self.logger.error("discovery_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"discovery: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_favicon_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run favicon fingerprinting scan."""
        progress = ModuleProgress(
            module="favicon",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._favicon_scanner.scan(hostname)
                session.favicon_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "favicon_scan_completed",
                    target=hostname,
                    found=result.found,
                    matches=len(result.matches),
                )
        except Exception as e:
            self.logger.error("favicon_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"favicon: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_asn_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run ASN/IP range lookup scan."""
        progress = ModuleProgress(
            module="asn",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._asn_scanner.scan(hostname)
                session.asn_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "asn_scan_completed",
                    target=hostname,
                    asn=result.asn.asn if result.asn else None,
                    ip_ranges=len(result.ip_ranges),
                )
        except Exception as e:
            self.logger.error("asn_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"asn: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_graphql_scan(self, session: ScanSession, target: ScanTarget) -> None:
        """Run GraphQL introspection scan."""
        progress = ModuleProgress(
            module="graphql",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            hostname = target.domain or target.ip_address
            if hostname:
                result = await self._graphql_scanner.scan(hostname)
                session.graphql_result = result
                progress.status = ScanStatus.COMPLETED
                progress.progress_percent = 100

                self.logger.info(
                    "graphql_scan_completed",
                    target=hostname,
                    endpoints_found=len(result.endpoints),
                    introspection=result.has_introspection,
                )
        except Exception as e:
            self.logger.error("graphql_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"graphql: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_wayback_scan(self, session: ScanSession) -> None:
        """Run Wayback Machine URL extraction."""
        if not session.target.domain:
            return

        progress = ModuleProgress(
            module="wayback",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._wayback_scanner.scan(session.target.domain)
            session.wayback_result = result
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100

            self.logger.info(
                "wayback_scan_completed",
                target=session.target.domain,
                total_urls=result.total_urls,
                interesting=len(result.interesting_urls),
            )
        except Exception as e:
            self.logger.error("wayback_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"wayback: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_vuln_scan(self, session: ScanSession, options: ScanOptions) -> None:
        """Run vulnerability scan on detected technologies."""
        progress = ModuleProgress(
            module="vuln",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._vuln_scanner.scan_technologies(
                session.webtech_result,  # type: ignore
                options,
            )
            session.vuln_result = result
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100
            progress.completed_at = datetime.utcnow()

            self.logger.info(
                "vuln_scan_completed",
                total_vulns=result.total_vulnerabilities,
                critical=result.critical_count,
                high=result.high_count,
            )
        except Exception as e:
            self.logger.error("vuln_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            progress.completed_at = datetime.utcnow()
            session.errors.append(f"vuln: {e}")

    async def _run_kev_check(self, session: ScanSession) -> None:
        """Check detected vulnerabilities against CISA KEV catalog."""
        if not session.vuln_result:
            return

        progress = ModuleProgress(
            module="kev",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._kev_checker.check_vulnerabilities(session.vuln_result)
            session.kev_matches = [
                {
                    "cve_id": match.vulnerability.cve_id,
                    "vendor": match.kev_entry.vendor_project,
                    "product": match.kev_entry.product,
                    "vulnerability_name": match.kev_entry.vulnerability_name,
                    "date_added": match.kev_entry.date_added,
                    "due_date": match.kev_entry.due_date,
                    "ransomware_related": match.kev_entry.is_ransomware_related,
                    "required_action": match.kev_entry.required_action,
                }
                for match in result.kev_matches
            ]
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100

            self.logger.info(
                "kev_check_completed",
                cves_checked=result.total_cves_checked,
                kev_matches=result.total_matches,
            )
        except Exception as e:
            self.logger.error("kev_check_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"kev: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_takeover_scan(self, session: ScanSession) -> None:
        """Scan for subdomain takeover vulnerabilities."""
        # Collect all discovered subdomains
        subdomains: list[str] = []

        if session.dns_result and session.dns_result.subdomains:
            subdomains.extend([s.full_domain for s in session.dns_result.subdomains])

        if session.crtsh_result and session.crtsh_result.discovered_subdomains:
            for sub in session.crtsh_result.discovered_subdomains:
                if sub.full_domain not in subdomains:
                    subdomains.append(sub.full_domain)

        if not subdomains:
            return

        progress = ModuleProgress(
            module="takeover",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._takeover_scanner.scan(subdomains)
            session.takeover_results = [
                {
                    "subdomain": v.subdomain,
                    "cname": v.cname,
                    "service": v.service,
                    "fingerprint": v.fingerprint,
                    "is_vulnerable": v.is_vulnerable,
                    "severity": v.severity,
                    "description": v.description,
                }
                for v in result.vulnerable + result.potentially_vulnerable
            ]
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100

            self.logger.info(
                "takeover_scan_completed",
                subdomains_checked=result.subdomains_checked,
                vulnerable=result.total_vulnerable,
            )
        except Exception as e:
            self.logger.error("takeover_scan_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"takeover: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_extended_subdomain_enum(self, session: ScanSession) -> None:
        """Run extended subdomain enumeration from 20+ sources."""
        if not session.target.domain:
            return

        progress = ModuleProgress(
            module="subdomain_enum",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        session.progress.append(progress)

        try:
            result = await self._subdomain_enum.enumerate(session.target.domain)
            session.subdomain_enum = {
                "target": result.target,
                "total_unique": result.total_unique,
                "subdomains": list(result.all_subdomains),
                "sources_successful": result.sources_successful,
                "sources_failed": result.sources_failed,
                "sources": [
                    {
                        "name": s.name,
                        "count": len(s.subdomains),
                        "success": s.success,
                        "error": s.error,
                    }
                    for s in result.sources
                ],
            }
            progress.status = ScanStatus.COMPLETED
            progress.progress_percent = 100

            self.logger.info(
                "subdomain_enum_completed",
                total_subdomains=result.total_unique,
                sources_successful=result.sources_successful,
            )
        except Exception as e:
            self.logger.error("subdomain_enum_failed", error=str(e))
            progress.status = ScanStatus.FAILED
            progress.error = str(e)
            session.errors.append(f"subdomain_enum: {e}")
        finally:
            progress.completed_at = datetime.utcnow()

    async def _run_ai_analysis(self, session: ScanSession) -> None:
        """Run AI analysis on scan results."""
        from argus.ai.analyzer import AIAnalyzer

        try:
            analyzer = AIAnalyzer(provider=session.options.ai_provider)
            analysis = await analyzer.analyze_session(session)
            session.ai_analysis = analysis.model_dump()
        except Exception as e:
            self.logger.error("ai_analysis_failed", error=str(e))
            session.errors.append(f"AI analysis: {e}")
