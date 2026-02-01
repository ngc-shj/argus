"""Subdomain takeover vulnerability scanner."""

import asyncio
import time
from datetime import datetime
from typing import Literal

import dns.resolver
import dns.exception
import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.security import SubdomainTakeover


class TakeoverResult:
    """Result of subdomain takeover scan."""

    def __init__(self) -> None:
        self.target: str = ""
        self.subdomains_checked: int = 0
        self.vulnerable: list[SubdomainTakeover] = []
        self.potentially_vulnerable: list[SubdomainTakeover] = []
        self.not_vulnerable: list[str] = []
        self.errors: list[str] = []
        self.scanned_at: datetime = datetime.utcnow()

    @property
    def total_vulnerable(self) -> int:
        return len(self.vulnerable)

    @property
    def total_potentially_vulnerable(self) -> int:
        return len(self.potentially_vulnerable)


class TakeoverScanner:
    """Scanner for detecting subdomain takeover vulnerabilities."""

    # Service fingerprints: (cname_pattern, http_fingerprint, service_name, severity)
    FINGERPRINTS: list[tuple[str, list[str], str, Literal["critical", "high", "medium"]]] = [
        # GitHub Pages
        (
            "github.io",
            ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/)"],
            "GitHub Pages",
            "high"
        ),
        # AWS S3
        (
            ".s3.amazonaws.com",
            ["NoSuchBucket", "The specified bucket does not exist"],
            "AWS S3",
            "critical"
        ),
        (
            ".s3-website",
            ["NoSuchBucket", "The specified bucket does not exist"],
            "AWS S3 Website",
            "critical"
        ),
        # AWS CloudFront
        (
            ".cloudfront.net",
            ["Bad Request", "The request could not be satisfied"],
            "AWS CloudFront",
            "high"
        ),
        # AWS Elastic Beanstalk
        (
            ".elasticbeanstalk.com",
            ["NXDOMAIN"],
            "AWS Elastic Beanstalk",
            "high"
        ),
        # Azure
        (
            ".azurewebsites.net",
            ["404 Web Site not found", "The resource you are looking for has been removed"],
            "Azure Web Apps",
            "high"
        ),
        (
            ".blob.core.windows.net",
            ["The specified container does not exist", "BlobNotFound"],
            "Azure Blob Storage",
            "critical"
        ),
        (
            ".cloudapp.net",
            ["NXDOMAIN"],
            "Azure Cloud Services",
            "high"
        ),
        (
            ".azurefd.net",
            ["The resource you are looking for has been removed"],
            "Azure Front Door",
            "high"
        ),
        (
            ".trafficmanager.net",
            ["NXDOMAIN"],
            "Azure Traffic Manager",
            "high"
        ),
        # Heroku
        (
            ".herokuapp.com",
            ["No such app", "There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html"],
            "Heroku",
            "high"
        ),
        (
            ".herokudns.com",
            ["No such app"],
            "Heroku DNS",
            "high"
        ),
        # Shopify
        (
            ".myshopify.com",
            ["Sorry, this shop is currently unavailable.", "Only one step left!"],
            "Shopify",
            "medium"
        ),
        # Tumblr
        (
            ".tumblr.com",
            ["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"],
            "Tumblr",
            "medium"
        ),
        # WordPress
        (
            ".wordpress.com",
            ["Do you want to register"],
            "WordPress.com",
            "medium"
        ),
        # Unbounce
        (
            ".unbouncepages.com",
            ["The requested URL was not found on this server", "NXDOMAIN"],
            "Unbounce",
            "high"
        ),
        # Zendesk
        (
            ".zendesk.com",
            ["Help Center Closed"],
            "Zendesk",
            "medium"
        ),
        # Fastly
        (
            ".fastly.net",
            ["Fastly error: unknown domain"],
            "Fastly",
            "high"
        ),
        # Pantheon
        (
            ".pantheonsite.io",
            ["404 error unknown site!"],
            "Pantheon",
            "high"
        ),
        # Netlify
        (
            ".netlify.app",
            ["Not Found - Request ID"],
            "Netlify",
            "high"
        ),
        (
            ".netlify.com",
            ["Not Found - Request ID"],
            "Netlify",
            "high"
        ),
        # Vercel / Now
        (
            ".vercel.app",
            ["NOT_FOUND"],
            "Vercel",
            "high"
        ),
        (
            ".now.sh",
            ["NOT_FOUND"],
            "Vercel (now.sh)",
            "high"
        ),
        # Ghost
        (
            ".ghost.io",
            ["The thing you were looking for is no longer here"],
            "Ghost",
            "medium"
        ),
        # Surge
        (
            ".surge.sh",
            ["project not found"],
            "Surge.sh",
            "medium"
        ),
        # Bitbucket
        (
            ".bitbucket.io",
            ["Repository not found"],
            "Bitbucket",
            "medium"
        ),
        # Cargo Collective
        (
            ".cargocollective.com",
            ["404 Not Found"],
            "Cargo Collective",
            "medium"
        ),
        # Help Scout
        (
            ".helpscoutdocs.com",
            ["No settings were found for this company"],
            "Help Scout",
            "medium"
        ),
        # Tilda
        (
            ".tilda.ws",
            ["Please go back or return to"],
            "Tilda",
            "medium"
        ),
        # Webflow
        (
            ".webflow.io",
            ["The page you are looking for doesn't exist or has been moved"],
            "Webflow",
            "medium"
        ),
        # Fly.io
        (
            ".fly.dev",
            ["NXDOMAIN"],
            "Fly.io",
            "high"
        ),
        # Render
        (
            ".onrender.com",
            ["Not Found"],
            "Render",
            "high"
        ),
        # Firebase
        (
            ".firebaseapp.com",
            ["Site Not Found"],
            "Firebase",
            "high"
        ),
        (
            ".web.app",
            ["Site Not Found"],
            "Firebase",
            "high"
        ),
        # Agile CRM
        (
            ".agilecrm.com",
            ["Sorry, this page is no longer available"],
            "Agile CRM",
            "medium"
        ),
        # Aha.io
        (
            ".ideas.aha.io",
            ["There is no portal here ... check portal address"],
            "Aha.io",
            "medium"
        ),
        # AWS API Gateway
        (
            ".execute-api.",
            ["Forbidden"],
            "AWS API Gateway",
            "medium"
        ),
        # ReadMe.io
        (
            ".readme.io",
            ["Project doesnt exist... yet!"],
            "ReadMe.io",
            "medium"
        ),
        # Tictail
        (
            ".tictail.com",
            ["Starting your own Tictail store is"],
            "Tictail",
            "medium"
        ),
        # SmartJobBoard
        (
            ".smartjobboard.com",
            ["This job board website is either expired"],
            "SmartJobBoard",
            "medium"
        ),
        # Strikingly
        (
            ".strikinglydns.com",
            ["But if you're looking to build your own website"],
            "Strikingly",
            "medium"
        ),
        # Uptimerobot
        (
            ".uptimerobot.com",
            ["page not found"],
            "UptimeRobot",
            "low"
        ),
        # Feedpress
        (
            ".redirect.feedpress.me",
            ["The feed has not been found"],
            "FeedPress",
            "medium"
        ),
        # Intercom
        (
            ".custom.intercom.help",
            ["This page is reserved for a customer"],
            "Intercom",
            "medium"
        ),
        # Campaign Monitor
        (
            ".createsend.com",
            ["Double opt-in Email Registration"],
            "Campaign Monitor",
            "medium"
        ),
    ]

    def __init__(self) -> None:
        self.logger = get_logger("takeover_scanner")

    async def scan(
        self,
        subdomains: list[str],
        concurrent_limit: int = 10,
    ) -> TakeoverResult:
        """Scan subdomains for takeover vulnerabilities."""
        start_time = time.time()
        settings = get_settings()

        self.logger.info("takeover_scan_started", subdomains_count=len(subdomains))

        result = TakeoverResult()
        result.target = subdomains[0].split(".")[-2] + "." + subdomains[0].split(".")[-1] if subdomains else ""
        result.subdomains_checked = len(subdomains)

        semaphore = asyncio.Semaphore(concurrent_limit)

        async def check_subdomain(subdomain: str) -> SubdomainTakeover | None:
            async with semaphore:
                return await self._check_subdomain(subdomain, settings.http_timeout)

        tasks = [check_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            if isinstance(res, Exception):
                result.errors.append(f"{subdomains[i]}: {str(res)}")
            elif res is None:
                result.not_vulnerable.append(subdomains[i])
            elif res.is_vulnerable:
                result.vulnerable.append(res)
            else:
                result.potentially_vulnerable.append(res)

        result.scanned_at = datetime.utcnow()

        duration = time.time() - start_time
        self.logger.info(
            "takeover_scan_completed",
            subdomains_checked=len(subdomains),
            vulnerable=len(result.vulnerable),
            potentially_vulnerable=len(result.potentially_vulnerable),
            duration=duration,
        )

        return result

    async def _check_subdomain(
        self, subdomain: str, timeout: int
    ) -> SubdomainTakeover | None:
        """Check a single subdomain for takeover vulnerability."""
        # First, get CNAME record
        cname = await self._get_cname(subdomain)

        if not cname:
            return None

        # Check if CNAME matches any fingerprint
        cname_lower = cname.lower()

        for cname_pattern, http_fingerprints, service, severity in self.FINGERPRINTS:
            if cname_pattern.lower() in cname_lower:
                # Found potential match, verify with HTTP
                is_vulnerable, fingerprint = await self._verify_vulnerability(
                    subdomain, http_fingerprints, timeout
                )

                if is_vulnerable:
                    return SubdomainTakeover(
                        subdomain=subdomain,
                        cname=cname,
                        service=service,
                        fingerprint=fingerprint,
                        is_vulnerable=True,
                        severity=severity,
                        description=f"Subdomain {subdomain} is vulnerable to takeover via {service}",
                        remediation=f"Remove the CNAME record pointing to {cname} or claim the resource on {service}",
                    )
                elif fingerprint == "NXDOMAIN":
                    # NXDOMAIN means the target doesn't exist - potentially vulnerable
                    return SubdomainTakeover(
                        subdomain=subdomain,
                        cname=cname,
                        service=service,
                        fingerprint="NXDOMAIN (target doesn't exist)",
                        is_vulnerable=False,  # Need manual verification
                        severity=severity,
                        description=f"Subdomain {subdomain} points to non-existent {service} resource",
                        remediation=f"Verify and remove the dangling CNAME record to {cname}",
                    )

        return None

    async def _get_cname(self, subdomain: str) -> str | None:
        """Get CNAME record for subdomain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")

        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.exception.DNSException as e:
            self.logger.debug("cname_lookup_failed", subdomain=subdomain, error=str(e))
            return None

        return None

    async def _verify_vulnerability(
        self, subdomain: str, fingerprints: list[str], timeout: int
    ) -> tuple[bool, str | None]:
        """Verify vulnerability by checking HTTP response."""
        # Check for NXDOMAIN fingerprint first
        if "NXDOMAIN" in fingerprints:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                resolver.resolve(subdomain, "A")
            except dns.resolver.NXDOMAIN:
                return True, "NXDOMAIN"
            except dns.exception.DNSException:
                pass

        # Check HTTP response
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{subdomain}"
                async with httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=True,
                    verify=False,  # May have invalid certs
                ) as client:
                    response = await client.get(url)
                    content = response.text.lower()

                    for fingerprint in fingerprints:
                        if fingerprint.lower() in content:
                            return True, fingerprint

            except Exception:
                continue

        return False, None

    async def scan_single(self, subdomain: str) -> SubdomainTakeover | None:
        """Scan a single subdomain for takeover vulnerability."""
        settings = get_settings()
        return await self._check_subdomain(subdomain, settings.http_timeout)
