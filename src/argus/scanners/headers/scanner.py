"""HTTP Security Headers scanner."""

import re
import time
from datetime import datetime
from typing import Literal

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.headers import (
    SecurityHeadersResult,
    HeaderFinding,
    CSPAnalysis,
    HSTSAnalysis,
    CookieFinding,
)


class SecurityHeadersScanner:
    """Scanner for HTTP security headers analysis."""

    # Security headers to check
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HSTS",
            "severity": "high",
            "description": "HTTP Strict Transport Security prevents downgrade attacks",
        },
        "content-security-policy": {
            "name": "CSP",
            "severity": "high",
            "description": "Content Security Policy prevents XSS and injection attacks",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "medium",
            "description": "Prevents clickjacking attacks",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "medium",
            "description": "Prevents MIME-type sniffing",
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "severity": "low",
            "description": "Legacy XSS filter (deprecated but still checked)",
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "low",
            "description": "Controls referrer information sent with requests",
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "medium",
            "description": "Controls browser features and APIs",
        },
        "cross-origin-embedder-policy": {
            "name": "COEP",
            "severity": "low",
            "description": "Cross-Origin Embedder Policy for isolation",
        },
        "cross-origin-opener-policy": {
            "name": "COOP",
            "severity": "low",
            "description": "Cross-Origin Opener Policy for isolation",
        },
        "cross-origin-resource-policy": {
            "name": "CORP",
            "severity": "low",
            "description": "Cross-Origin Resource Policy for isolation",
        },
    }

    # Headers that should NOT be present (information disclosure)
    INFO_DISCLOSURE_HEADERS = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
        "x-runtime",
        "x-version",
    ]

    # CSP directive analysis
    CSP_DANGEROUS_VALUES = {
        "unsafe-inline": "Allows inline scripts/styles - XSS risk",
        "unsafe-eval": "Allows eval() - code injection risk",
        "data:": "Allows data: URIs - potential bypass",
        "*": "Wildcard allows any source",
        "http:": "Allows insecure HTTP sources",
        "'none'": None,  # This is actually safe
    }

    CSP_IMPORTANT_DIRECTIVES = [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "frame-ancestors",
        "form-action",
        "base-uri",
        "upgrade-insecure-requests",
    ]

    def __init__(self) -> None:
        self.logger = get_logger("headers_scanner")

    async def scan(self, target: str) -> SecurityHeadersResult:
        """Scan target for HTTP security headers."""
        start_time = time.time()
        settings = get_settings()

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info("headers_scan_started", target=target)

        result = SecurityHeadersResult(target=target)

        try:
            async with httpx.AsyncClient(
                timeout=settings.http_timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                response = await client.get(target)

                # Store all headers
                result.all_headers = dict(response.headers)

                # Analyze security headers
                self._analyze_security_headers(response, result)

                # Analyze CSP
                self._analyze_csp(response, result)

                # Analyze HSTS
                self._analyze_hsts(response, result)

                # Check for information disclosure
                self._check_info_disclosure(response, result)

                # Analyze cookies
                self._analyze_cookies(response, result)

                # Calculate score
                self._calculate_score(result)

        except Exception as e:
            self.logger.error("headers_scan_failed", error=str(e))
            result.errors.append(str(e))

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "headers_scan_completed",
            target=target,
            score=result.score,
            grade=result.grade,
            duration=duration,
        )

        return result

    def _analyze_security_headers(
        self, response: httpx.Response, result: SecurityHeadersResult
    ) -> None:
        """Check presence of security headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header_key, header_info in self.SECURITY_HEADERS.items():
            present = header_key in headers
            value = headers.get(header_key)

            finding = HeaderFinding(
                header_name=header_info["name"],
                header_key=header_key,
                present=present,
                value=value,
                severity=header_info["severity"] if not present else "info",
                description=header_info["description"],
            )

            if present:
                result.present_headers.append(finding)
            else:
                finding.recommendation = f"Add {header_key} header to improve security"
                result.missing_headers.append(finding)

    def _analyze_csp(
        self, response: httpx.Response, result: SecurityHeadersResult
    ) -> None:
        """Analyze Content-Security-Policy header."""
        csp_value = response.headers.get("content-security-policy", "")
        csp_ro_value = response.headers.get("content-security-policy-report-only", "")

        if not csp_value and not csp_ro_value:
            result.csp = CSPAnalysis(
                present=False,
                report_only=False,
                score=0,
            )
            return

        # Parse CSP
        csp = csp_value or csp_ro_value
        is_report_only = bool(csp_ro_value and not csp_value)

        analysis = CSPAnalysis(
            present=True,
            raw_value=csp,
            report_only=is_report_only,
        )

        # Parse directives
        directives: dict[str, list[str]] = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name = parts[0].lower()
                values = parts[1:] if len(parts) > 1 else []
                directives[name] = values

        analysis.directives = directives

        # Check for dangerous values
        issues: list[str] = []
        for directive, values in directives.items():
            for value in values:
                value_lower = value.lower().strip("'\"")
                for dangerous, desc in self.CSP_DANGEROUS_VALUES.items():
                    if desc and (dangerous in value_lower or value_lower == dangerous.strip("'")):
                        issues.append(f"{directive}: {value} - {desc}")

        analysis.issues = issues

        # Check missing important directives
        missing_directives = []
        for directive in self.CSP_IMPORTANT_DIRECTIVES:
            if directive not in directives and "default-src" not in directives:
                missing_directives.append(directive)
        analysis.missing_directives = missing_directives[:5]  # Top 5

        # Calculate CSP score
        score = 100
        if is_report_only:
            score -= 20
        score -= len(issues) * 10
        score -= len(missing_directives) * 5
        if "default-src" not in directives:
            score -= 20
        analysis.score = max(0, min(100, score))

        result.csp = analysis

    def _analyze_hsts(
        self, response: httpx.Response, result: SecurityHeadersResult
    ) -> None:
        """Analyze Strict-Transport-Security header."""
        hsts_value = response.headers.get("strict-transport-security", "")

        if not hsts_value:
            result.hsts = HSTSAnalysis(present=False, score=0)
            return

        analysis = HSTSAnalysis(present=True, raw_value=hsts_value)

        # Parse max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
        if max_age_match:
            analysis.max_age = int(max_age_match.group(1))

        # Check for includeSubDomains
        analysis.include_subdomains = "includesubdomains" in hsts_value.lower()

        # Check for preload
        analysis.preload = "preload" in hsts_value.lower()

        # Calculate score
        score = 50  # Base for having HSTS
        if analysis.max_age:
            if analysis.max_age >= 31536000:  # 1 year
                score += 20
            elif analysis.max_age >= 15768000:  # 6 months
                score += 15
            elif analysis.max_age >= 2592000:  # 1 month
                score += 10
            else:
                score += 5

        if analysis.include_subdomains:
            score += 15

        if analysis.preload:
            score += 15

        analysis.score = min(100, score)

        # Add recommendations
        if not analysis.include_subdomains:
            analysis.recommendations.append("Add includeSubDomains directive")
        if not analysis.preload:
            analysis.recommendations.append("Consider adding preload for HSTS preload list")
        if analysis.max_age and analysis.max_age < 31536000:
            analysis.recommendations.append("Increase max-age to at least 31536000 (1 year)")

        result.hsts = analysis

    def _check_info_disclosure(
        self, response: httpx.Response, result: SecurityHeadersResult
    ) -> None:
        """Check for information disclosure headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header in self.INFO_DISCLOSURE_HEADERS:
            if header in headers:
                value = headers[header]
                # Check if it reveals version info
                severity: Literal["low", "medium", "info"] = "info"
                if re.search(r"\d+\.\d+", value):
                    severity = "medium"
                elif header in ["x-powered-by", "x-aspnet-version"]:
                    severity = "low"

                finding = HeaderFinding(
                    header_name=header.title(),
                    header_key=header,
                    present=True,
                    value=value,
                    severity=severity,
                    description=f"Information disclosure via {header} header",
                    recommendation=f"Remove or sanitize {header} header",
                )
                result.info_disclosure.append(finding)

    def _analyze_cookies(
        self, response: httpx.Response, result: SecurityHeadersResult
    ) -> None:
        """Analyze cookie security attributes."""
        cookies = response.headers.get_list("set-cookie")

        for cookie_str in cookies:
            # Parse cookie name
            name_match = re.match(r"([^=]+)=", cookie_str)
            if not name_match:
                continue

            name = name_match.group(1).strip()
            cookie_lower = cookie_str.lower()

            issues: list[str] = []
            recommendations: list[str] = []

            # Check Secure flag
            has_secure = "secure" in cookie_lower
            if not has_secure:
                issues.append("Missing Secure flag")
                recommendations.append("Add Secure flag")

            # Check HttpOnly flag
            has_httponly = "httponly" in cookie_lower
            if not has_httponly:
                # Only warn for session-like cookies
                if any(kw in name.lower() for kw in ["session", "auth", "token", "jwt"]):
                    issues.append("Missing HttpOnly flag on sensitive cookie")
                    recommendations.append("Add HttpOnly flag")

            # Check SameSite
            samesite_match = re.search(r"samesite=(\w+)", cookie_lower)
            has_samesite = bool(samesite_match)
            samesite_value = samesite_match.group(1) if samesite_match else None

            if not has_samesite:
                issues.append("Missing SameSite attribute")
                recommendations.append("Add SameSite=Strict or SameSite=Lax")
            elif samesite_value == "none" and not has_secure:
                issues.append("SameSite=None requires Secure flag")

            # Determine severity
            severity: Literal["critical", "high", "medium", "low", "info"] = "info"
            is_sensitive = any(
                kw in name.lower() for kw in ["session", "auth", "token", "jwt", "csrf"]
            )
            if is_sensitive and not has_secure:
                severity = "high"
            elif is_sensitive and (not has_httponly or not has_samesite):
                severity = "medium"
            elif issues:
                severity = "low"

            finding = CookieFinding(
                name=name,
                has_secure=has_secure,
                has_httponly=has_httponly,
                has_samesite=has_samesite,
                samesite_value=samesite_value,
                issues=issues,
                recommendations=recommendations,
                severity=severity,
            )
            result.cookies.append(finding)

    def _calculate_score(self, result: SecurityHeadersResult) -> None:
        """Calculate overall security headers score."""
        score = 0
        max_score = 100

        # Missing critical headers (40 points)
        critical_headers = ["strict-transport-security", "content-security-policy"]
        for header in result.present_headers:
            if header.header_key in critical_headers:
                score += 20

        # Missing important headers (30 points)
        important_headers = [
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        ]
        for header in result.present_headers:
            if header.header_key in important_headers:
                score += 10

        # Nice-to-have headers (10 points)
        optional_headers = [
            "permissions-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
        ]
        for header in result.present_headers:
            if header.header_key in optional_headers:
                score += 3

        # CSP quality bonus (10 points)
        if result.csp and result.csp.present and not result.csp.report_only:
            score += min(10, result.csp.score // 10)

        # HSTS quality bonus (10 points)
        if result.hsts and result.hsts.present:
            score += min(10, result.hsts.score // 10)

        # Deductions for info disclosure
        score -= len(result.info_disclosure) * 2

        # Deductions for cookie issues
        for cookie in result.cookies:
            if cookie.severity == "high":
                score -= 5
            elif cookie.severity == "medium":
                score -= 3

        result.score = max(0, min(max_score, score))

        # Calculate grade
        if result.score >= 90:
            result.grade = "A+"
        elif result.score >= 80:
            result.grade = "A"
        elif result.score >= 70:
            result.grade = "B"
        elif result.score >= 60:
            result.grade = "C"
        elif result.score >= 50:
            result.grade = "D"
        else:
            result.grade = "F"
