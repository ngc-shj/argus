"""JavaScript analysis scanner for secrets and endpoints."""

import asyncio
import re
import time
from datetime import datetime
from typing import Literal
from urllib.parse import urljoin, urlparse

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.security import JSSecretFinding, JSEndpoint


class JSAnalysisResult:
    """Result of JavaScript analysis."""

    def __init__(self) -> None:
        self.target: str = ""
        self.js_files_analyzed: int = 0
        self.secrets: list[JSSecretFinding] = []
        self.endpoints: list[JSEndpoint] = []
        self.total_findings: int = 0
        self.critical_count: int = 0
        self.high_count: int = 0
        self.medium_count: int = 0
        self.low_count: int = 0
        self.scanned_at: datetime = datetime.utcnow()

    def calculate_counts(self) -> None:
        """Calculate severity counts."""
        self.total_findings = len(self.secrets)
        for secret in self.secrets:
            if secret.severity == "critical":
                self.critical_count += 1
            elif secret.severity == "high":
                self.high_count += 1
            elif secret.severity == "medium":
                self.medium_count += 1
            elif secret.severity == "low":
                self.low_count += 1


class JSAnalysisScanner:
    """Scanner for analyzing JavaScript files for secrets and endpoints."""

    # Secret patterns with their types and severities
    SECRET_PATTERNS: list[tuple[str, str, Literal["critical", "high", "medium", "low"], str]] = [
        # AWS
        (r"AKIA[0-9A-Z]{16}", "aws_key", "critical", "AWS Access Key ID"),
        (r"aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "aws_key", "critical", "AWS Secret Access Key"),

        # Google Cloud
        (r"AIza[0-9A-Za-z\-_]{35}", "api_key", "high", "Google API Key"),
        (r"ya29\.[0-9A-Za-z\-_]+", "oauth_token", "critical", "Google OAuth Token"),

        # GitHub
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", "api_key", "critical", "GitHub Token"),
        (r"github[_\-]?token[\s]*[=:]\s*['\"][A-Za-z0-9_]+['\"]", "api_key", "critical", "GitHub Token"),

        # Slack
        (r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}[a-zA-Z0-9-]*", "api_key", "critical", "Slack Token"),

        # Stripe
        (r"sk_live_[0-9a-zA-Z]{24}", "api_key", "critical", "Stripe Live Secret Key"),
        (r"sk_test_[0-9a-zA-Z]{24}", "api_key", "medium", "Stripe Test Secret Key"),
        (r"pk_live_[0-9a-zA-Z]{24}", "api_key", "medium", "Stripe Live Publishable Key"),

        # Twilio
        (r"SK[0-9a-fA-F]{32}", "api_key", "high", "Twilio API Key"),

        # SendGrid
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "api_key", "critical", "SendGrid API Key"),

        # JWT
        (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "jwt", "medium", "JSON Web Token"),

        # Private Keys
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "private_key", "critical", "Private Key"),
        (r"-----BEGIN CERTIFICATE-----", "private_key", "medium", "Certificate"),

        # Generic API Keys
        (r"api[_\-]?key[\s]*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "api_key", "high", "Generic API Key"),
        (r"api[_\-]?secret[\s]*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "api_key", "high", "API Secret"),
        (r"auth[_\-]?token[\s]*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "oauth_token", "high", "Auth Token"),
        (r"access[_\-]?token[\s]*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "oauth_token", "high", "Access Token"),
        (r"bearer[\s]+[A-Za-z0-9\-_\.]{20,}", "oauth_token", "high", "Bearer Token"),

        # Passwords
        (r"password[\s]*[=:]\s*['\"][^'\"]{8,}['\"]", "password", "high", "Hardcoded Password"),
        (r"passwd[\s]*[=:]\s*['\"][^'\"]{8,}['\"]", "password", "high", "Hardcoded Password"),
        (r"secret[\s]*[=:]\s*['\"][^'\"]{8,}['\"]", "password", "medium", "Hardcoded Secret"),

        # Database Connection Strings
        (r"mongodb(\+srv)?://[^\s\"']+", "connection_string", "critical", "MongoDB Connection String"),
        (r"postgres(ql)?://[^\s\"']+", "connection_string", "critical", "PostgreSQL Connection String"),
        (r"mysql://[^\s\"']+", "connection_string", "critical", "MySQL Connection String"),
        (r"redis://[^\s\"']+", "connection_string", "high", "Redis Connection String"),

        # Webhook URLs
        (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "webhook_url", "high", "Slack Webhook URL"),
        (r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "webhook_url", "high", "Discord Webhook URL"),

        # Firebase
        (r"firebase[_\-]?api[_\-]?key[\s]*[=:]\s*['\"][A-Za-z0-9\-_]+['\"]", "api_key", "high", "Firebase API Key"),

        # Mailgun
        (r"key-[0-9a-zA-Z]{32}", "api_key", "high", "Mailgun API Key"),

        # Square
        (r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}", "api_key", "high", "Square API Key"),

        # Heroku
        (r"heroku[_\-]?api[_\-]?key[\s]*[=:]\s*['\"][0-9a-fA-F-]{36}['\"]", "api_key", "critical", "Heroku API Key"),
    ]

    # Endpoint patterns
    ENDPOINT_PATTERNS: list[tuple[str, Literal["api", "graphql", "websocket", "internal", "external", "unknown"]]] = [
        # API paths
        (r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]+)["\']', "api"),
        (r'["\'](/v\d+/[a-zA-Z0-9/_-]+)["\']', "api"),
        (r'["\'](/graphql)["\']', "graphql"),
        (r'["\'](/query)["\']', "graphql"),

        # Full URLs
        (r'["\'](https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+)["\']', "api"),
        (r'["\'](https?://api\.[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]*)["\']', "api"),

        # WebSocket
        (r'["\'](wss?://[a-zA-Z0-9.-]+[a-zA-Z0-9/_-]*)["\']', "websocket"),

        # Internal paths
        (r'["\'](/admin/[a-zA-Z0-9/_-]+)["\']', "internal"),
        (r'["\'](/internal/[a-zA-Z0-9/_-]+)["\']', "internal"),
        (r'["\'](/private/[a-zA-Z0-9/_-]+)["\']', "internal"),

        # Generic paths that look like endpoints
        (r'(?:fetch|axios|ajax)\s*\(\s*["\']([a-zA-Z0-9/_-]+)["\']', "unknown"),
        (r'url\s*:\s*["\']([a-zA-Z0-9/_-]+)["\']', "unknown"),
        (r'endpoint\s*[=:]\s*["\']([a-zA-Z0-9/_-]+)["\']', "unknown"),
    ]

    def __init__(self) -> None:
        self.logger = get_logger("js_scanner")

    async def scan(
        self,
        target: str,
        max_js_files: int = 50,
        include_inline: bool = True,
    ) -> JSAnalysisResult:
        """Scan target for JavaScript files and analyze them."""
        start_time = time.time()
        settings = get_settings()

        # Normalize target URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info("js_scan_started", target=target)

        result = JSAnalysisResult()
        result.target = target

        try:
            async with httpx.AsyncClient(
                timeout=settings.http_timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                # Fetch main page
                response = await client.get(target)
                html_content = response.text

                # Extract JS file URLs
                js_urls = self._extract_js_urls(html_content, target)
                self.logger.debug("found_js_files", count=len(js_urls))

                # Limit number of JS files
                js_urls = js_urls[:max_js_files]

                # Analyze inline JavaScript
                if include_inline:
                    inline_scripts = self._extract_inline_scripts(html_content)
                    for i, script in enumerate(inline_scripts):
                        self._analyze_content(script, f"inline_script_{i}", result)

                # Fetch and analyze external JS files
                semaphore = asyncio.Semaphore(5)  # Limit concurrent requests

                async def fetch_and_analyze(url: str) -> None:
                    async with semaphore:
                        try:
                            js_response = await client.get(url)
                            if js_response.status_code == 200:
                                self._analyze_content(js_response.text, url, result)
                                result.js_files_analyzed += 1
                        except Exception as e:
                            self.logger.debug("js_fetch_failed", url=url, error=str(e))

                await asyncio.gather(*[fetch_and_analyze(url) for url in js_urls])

        except Exception as e:
            self.logger.error("js_scan_failed", target=target, error=str(e))

        result.calculate_counts()
        result.scanned_at = datetime.utcnow()

        duration = time.time() - start_time
        self.logger.info(
            "js_scan_completed",
            target=target,
            js_files=result.js_files_analyzed,
            secrets_found=len(result.secrets),
            endpoints_found=len(result.endpoints),
            duration=duration,
        )

        return result

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract JavaScript file URLs from HTML."""
        urls: list[str] = []
        seen: set[str] = set()

        # Script src attributes
        script_pattern = re.compile(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            re.IGNORECASE
        )

        for match in script_pattern.finditer(html):
            src = match.group(1)
            if src.endswith(".js") or ".js?" in src or "/js/" in src:
                full_url = urljoin(base_url, src)
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append(full_url)

        # Also look for dynamically loaded scripts
        dynamic_pattern = re.compile(
            r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            re.IGNORECASE
        )

        for match in dynamic_pattern.finditer(html):
            src = match.group(1)
            if not src.startswith(("http://", "https://", "//")):
                full_url = urljoin(base_url, src)
            elif src.startswith("//"):
                full_url = "https:" + src
            else:
                full_url = src

            if full_url not in seen and self._is_same_origin_or_trusted(full_url, base_url):
                seen.add(full_url)
                urls.append(full_url)

        return urls

    def _extract_inline_scripts(self, html: str) -> list[str]:
        """Extract inline JavaScript from HTML."""
        scripts: list[str] = []

        # Match script tags without src attribute
        pattern = re.compile(
            r'<script(?![^>]*\ssrc)[^>]*>(.*?)</script>',
            re.IGNORECASE | re.DOTALL
        )

        for match in pattern.finditer(html):
            content = match.group(1).strip()
            if content and len(content) > 50:  # Skip very short scripts
                scripts.append(content)

        return scripts

    def _is_same_origin_or_trusted(self, url: str, base_url: str) -> bool:
        """Check if URL is same origin or from trusted CDN."""
        try:
            url_parsed = urlparse(url)
            base_parsed = urlparse(base_url)

            # Same origin
            if url_parsed.netloc == base_parsed.netloc:
                return True

            # Trusted CDNs
            trusted_cdns = [
                "cdnjs.cloudflare.com",
                "cdn.jsdelivr.net",
                "unpkg.com",
                "code.jquery.com",
                "stackpath.bootstrapcdn.com",
                "maxcdn.bootstrapcdn.com",
                "ajax.googleapis.com",
                "fonts.googleapis.com",
            ]

            return url_parsed.netloc in trusted_cdns

        except Exception:
            return False

    def _analyze_content(self, content: str, source: str, result: JSAnalysisResult) -> None:
        """Analyze JavaScript content for secrets and endpoints."""
        # Search for secrets
        for pattern, secret_type, severity, description in self.SECRET_PATTERNS:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for match in regex.finditer(content):
                    value = match.group(0)

                    # Find line number
                    line_num = content[:match.start()].count("\n") + 1

                    # Redact the value for safety (show only first and last few chars)
                    if len(value) > 10:
                        redacted = value[:4] + "..." + value[-4:]
                    else:
                        redacted = value[:2] + "..."

                    # Avoid duplicates
                    if not any(s.value_snippet == redacted and s.source_file == source
                               for s in result.secrets if hasattr(s, 'source_file')):
                        result.secrets.append(JSSecretFinding(
                            url=source,
                            secret_type=secret_type,
                            pattern_matched=pattern[:50] + "..." if len(pattern) > 50 else pattern,
                            value_snippet=redacted,
                            line_number=line_num,
                            severity=severity,
                            description=description,
                        ))
            except re.error:
                pass

        # Search for endpoints
        for pattern, endpoint_type in self.ENDPOINT_PATTERNS:
            try:
                regex = re.compile(pattern)
                for match in regex.finditer(content):
                    endpoint = match.group(1)

                    # Skip if looks like file path or common false positives
                    if self._is_valid_endpoint(endpoint):
                        # Avoid duplicates
                        if not any(e.url == endpoint and e.source_file == source
                                   for e in result.endpoints):
                            result.endpoints.append(JSEndpoint(
                                url=endpoint,
                                source_file=source,
                                endpoint_type=endpoint_type,
                            ))
            except re.error:
                pass

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if extracted string looks like a valid API endpoint."""
        # Skip common false positives
        false_positives = [
            "/static/",
            "/assets/",
            "/images/",
            "/img/",
            "/css/",
            "/js/",
            "/fonts/",
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".ttf",
        ]

        endpoint_lower = endpoint.lower()
        for fp in false_positives:
            if fp in endpoint_lower:
                return False

        # Must start with / or http
        if not endpoint.startswith(("/", "http://", "https://", "ws://", "wss://")):
            return False

        # Must be at least 3 characters
        if len(endpoint) < 3:
            return False

        return True
