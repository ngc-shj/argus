"""Web Technology Scanner implementation."""

import re
import time
from datetime import datetime

import httpx

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.webtech import (
    HTTPHeader,
    SecurityHeader,
    Technology,
    WebTechResult,
    SECURITY_HEADERS,
)
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


# Technology fingerprints (simplified version)
TECH_FINGERPRINTS = {
    # Web Servers
    "Apache": {
        "headers": {"Server": r"Apache"},
        "categories": ["Web servers"],
    },
    "nginx": {
        "headers": {"Server": r"nginx"},
        "categories": ["Web servers"],
    },
    "Microsoft-IIS": {
        "headers": {"Server": r"Microsoft-IIS"},
        "categories": ["Web servers"],
    },
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".+"},
        "categories": ["CDN"],
    },
    # Frameworks
    "Express": {
        "headers": {"X-Powered-By": r"Express"},
        "categories": ["Web frameworks"],
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
        "categories": ["Web frameworks"],
    },
    "PHP": {
        "headers": {"X-Powered-By": r"PHP"},
        "categories": ["Programming languages"],
    },
    "Django": {
        "headers": {"X-Frame-Options": r"SAMEORIGIN"},
        "body": r"csrfmiddlewaretoken",
        "categories": ["Web frameworks"],
    },
    # CMS
    "WordPress": {
        "body": r"wp-content|wp-includes|wordpress",
        "headers": {"Link": r"<.*>; rel=\"https://api.w.org/\""},
        "categories": ["CMS", "Blogs"],
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal"},
        "body": r"Drupal\.settings|drupal\.js",
        "categories": ["CMS"],
    },
    "Joomla": {
        "body": r"/media/jui/|/components/com_",
        "categories": ["CMS"],
    },
    # JavaScript frameworks
    "React": {
        "body": r"react\.production\.min\.js|reactDOM|_reactRootContainer",
        "categories": ["JavaScript frameworks"],
    },
    "Vue.js": {
        "body": r"vue\.min\.js|vue\.runtime\.min\.js|__vue__",
        "categories": ["JavaScript frameworks"],
    },
    "Angular": {
        "body": r"ng-app|ng-controller|angular\.min\.js",
        "categories": ["JavaScript frameworks"],
    },
    "jQuery": {
        "body": r"jquery\.min\.js|jquery-\d+\.\d+",
        "categories": ["JavaScript libraries"],
    },
    # Analytics
    "Google Analytics": {
        "body": r"google-analytics\.com/analytics\.js|gtag\(|_ga=",
        "categories": ["Analytics"],
    },
    "Google Tag Manager": {
        "body": r"googletagmanager\.com/gtm\.js",
        "categories": ["Tag managers"],
    },
    # Security
    "reCAPTCHA": {
        "body": r"google\.com/recaptcha|grecaptcha",
        "categories": ["Security"],
    },
}


@ScannerRegistry.register
class WebTechScanner(BaseScanner[WebTechResult]):
    """Web technology detection scanner."""

    @property
    def name(self) -> str:
        return "webtech"

    @property
    def description(self) -> str:
        return "Web technology and security header detection"

    def get_capabilities(self) -> list[str]:
        return [
            "Technology fingerprinting",
            "CMS detection",
            "Framework detection",
            "Security header analysis",
            "Server identification",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate target."""
        return target.domain is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> WebTechResult:
        """Execute web technology scan."""
        if not target.domain:
            raise ScanError("Domain is required for web tech scan", scanner=self.name)

        options = options or ScanOptions()
        settings = get_settings()
        start_time = time.time()

        self.logger.info("webtech_scan_started", target=target.domain)

        # Build URL
        url = f"https://{target.domain}"

        try:
            # First try with SSL verification enabled (secure default)
            try:
                async with httpx.AsyncClient(
                    timeout=settings.http_timeout,
                    follow_redirects=True,
                    verify=True,
                ) as client:
                    response = await client.get(url)
            except httpx.ConnectError as ssl_err:
                # SSL verification failed - log warning and retry without verification
                # This handles self-signed certificates on internal/development servers
                self.logger.warning(
                    "ssl_verification_failed",
                    target=target.domain,
                    error=str(ssl_err),
                    message="Retrying without SSL verification",
                )
                async with httpx.AsyncClient(
                    timeout=settings.http_timeout,
                    follow_redirects=True,
                    verify=False,  # noqa: S501 - Fallback for self-signed certs
                ) as client:
                    response = await client.get(url)

            # Get redirect chain
            redirect_chain = [str(r.url) for r in response.history]

            # Analyze response
            technologies = self._detect_technologies(response)
            headers = self._analyze_headers(response.headers)
            security_headers = self._analyze_security_headers(response.headers)

            # Extract server info
            server = response.headers.get("Server")
            powered_by = response.headers.get("X-Powered-By")

            # Detect CMS
            cms, cms_version = self._detect_cms(response)

            duration = time.time() - start_time

            result = WebTechResult(
                target=target.domain,
                url=url,
                status_code=response.status_code,
                response_time_ms=response.elapsed.total_seconds() * 1000,
                final_url=str(response.url),
                redirect_chain=redirect_chain,
                technologies=technologies,
                headers=headers,
                security_headers=security_headers,
                server=server,
                powered_by=powered_by,
                cms=cms,
                cms_version=cms_version,
                scanned_at=datetime.utcnow(),
                duration_seconds=duration,
            )

            self.logger.info(
                "webtech_scan_completed",
                target=target.domain,
                technologies=len(technologies),
                duration=duration,
            )

            return result

        except httpx.TimeoutException as e:
            raise ScanError(
                f"Request timeout for {url}",
                scanner=self.name,
                target=target.domain,
            ) from e
        except Exception as e:
            self.logger.error("webtech_scan_failed", target=target.domain, error=str(e))
            raise ScanError(
                f"Web tech scan failed: {e}",
                scanner=self.name,
                target=target.domain,
            ) from e

    def _detect_technologies(self, response: httpx.Response) -> list[Technology]:
        """Detect technologies from response."""
        technologies = []
        body = response.text
        # Normalize headers to lowercase keys for case-insensitive matching
        headers = {k.lower(): v for k, v in response.headers.items()}

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            confidence = 0
            version = None

            # Check headers
            if "headers" in fingerprint:
                for header_name, pattern in fingerprint["headers"].items():
                    header_value = headers.get(header_name.lower(), "")
                    if re.search(pattern, header_value, re.IGNORECASE):
                        confidence += 50
                        # Try to extract version
                        version_match = re.search(r"[\d.]+", header_value)
                        if version_match:
                            version = version_match.group()

            # Check body
            if "body" in fingerprint:
                if re.search(fingerprint["body"], body, re.IGNORECASE):
                    confidence += 50

            if confidence > 0:
                technologies.append(
                    Technology(
                        name=tech_name,
                        categories=fingerprint.get("categories", []),
                        version=version,
                        confidence=min(confidence, 100),
                    )
                )

        return technologies

    def _analyze_headers(self, headers: httpx.Headers) -> list[HTTPHeader]:
        """Analyze HTTP headers."""
        analyzed = []
        security_relevant_headers = {
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-runtime",
            "x-generator",
        }

        for name, value in headers.items():
            is_security = name.lower() in security_relevant_headers
            findings = []

            # Check for information disclosure
            if name.lower() == "server" and any(
                x in value.lower() for x in ["apache", "nginx", "iis"]
            ):
                if re.search(r"\d+\.\d+", value):
                    findings.append("Server version disclosed")

            if name.lower() == "x-powered-by":
                findings.append("Technology stack disclosed")

            analyzed.append(
                HTTPHeader(
                    name=name,
                    value=value,
                    security_relevant=is_security,
                    findings=findings,
                )
            )

        return analyzed

    def _analyze_security_headers(self, headers: httpx.Headers) -> list[SecurityHeader]:
        """Analyze security-related headers."""
        results = []

        recommendations = {
            "Content-Security-Policy": "Implement CSP to prevent XSS attacks",
            "X-Content-Type-Options": "Add 'nosniff' to prevent MIME sniffing",
            "X-Frame-Options": "Add 'DENY' or 'SAMEORIGIN' to prevent clickjacking",
            "X-XSS-Protection": "Add '1; mode=block' for XSS protection",
            "Strict-Transport-Security": "Enable HSTS to enforce HTTPS",
            "Referrer-Policy": "Control referrer information leakage",
            "Permissions-Policy": "Control browser feature access",
        }

        for header_name in SECURITY_HEADERS:
            value = headers.get(header_name)
            present = value is not None

            severity = "info"
            if not present:
                if header_name in ["Content-Security-Policy", "Strict-Transport-Security"]:
                    severity = "medium"
                elif header_name in ["X-Frame-Options", "X-Content-Type-Options"]:
                    severity = "low"

            results.append(
                SecurityHeader(
                    name=header_name,
                    present=present,
                    value=value,
                    recommendation=None if present else recommendations.get(header_name),
                    severity=severity if not present else "info",
                )
            )

        return results

    def _detect_cms(self, response: httpx.Response) -> tuple[str | None, str | None]:
        """Detect CMS from response."""
        body = response.text.lower()
        headers = response.headers

        # WordPress
        if "wp-content" in body or "wp-includes" in body:
            version = None
            # Try to get version from meta tag
            match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', response.text)
            if match:
                version = match.group(1)
            return "WordPress", version

        # Drupal
        if headers.get("X-Generator", "").startswith("Drupal"):
            version = None
            match = re.search(r"Drupal ([\d.]+)", headers.get("X-Generator", ""))
            if match:
                version = match.group(1)
            return "Drupal", version

        # Joomla
        if "/media/jui/" in body or "/components/com_" in body:
            return "Joomla", None

        return None, None
