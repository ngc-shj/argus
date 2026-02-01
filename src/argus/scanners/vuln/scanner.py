"""Vulnerability scanner for CVE cross-referencing."""

import asyncio
import time
from datetime import datetime
from typing import Literal

import httpx

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.core.logging import get_logger
from argus.models import ScanTarget, ScanOptions
from argus.models.vuln import (
    VulnerabilityInfo,
    TechnologyVulnerability,
    VulnScanResult,
)
from argus.models.webtech import WebTechResult


class VulnScanner:
    """Vulnerability scanner that cross-references detected technologies with CVE databases."""

    # NVD API endpoint (NIST National Vulnerability Database)
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Technology name mappings to CPE vendor/product
    TECH_TO_CPE: dict[str, tuple[str, str]] = {
        # Web Servers
        "apache": ("apache", "http_server"),
        "nginx": ("nginx", "nginx"),
        "iis": ("microsoft", "internet_information_services"),
        "lighttpd": ("lighttpd", "lighttpd"),
        "caddy": ("caddyserver", "caddy"),
        # Languages/Runtimes
        "php": ("php", "php"),
        "python": ("python", "python"),
        "node.js": ("nodejs", "node.js"),
        "ruby": ("ruby-lang", "ruby"),
        "java": ("oracle", "java"),
        # Frameworks
        "express": ("expressjs", "express"),
        "django": ("djangoproject", "django"),
        "rails": ("rubyonrails", "rails"),
        "laravel": ("laravel", "laravel"),
        "spring": ("vmware", "spring_framework"),
        "asp.net": ("microsoft", "asp.net"),
        "flask": ("palletsprojects", "flask"),
        "fastapi": ("tiangolo", "fastapi"),
        # CMS
        "wordpress": ("wordpress", "wordpress"),
        "drupal": ("drupal", "drupal"),
        "joomla": ("joomla", "joomla"),
        "magento": ("magento", "magento"),
        # JavaScript Frameworks
        "react": ("facebook", "react"),
        "vue.js": ("vuejs", "vue.js"),
        "angular": ("google", "angular"),
        "jquery": ("jquery", "jquery"),
        # Databases (if exposed)
        "mysql": ("mysql", "mysql"),
        "postgresql": ("postgresql", "postgresql"),
        "mongodb": ("mongodb", "mongodb"),
        "redis": ("redis", "redis"),
        # Other
        "openssh": ("openbsd", "openssh"),
        "openssl": ("openssl", "openssl"),
        "tomcat": ("apache", "tomcat"),
    }

    def __init__(self) -> None:
        self.logger = get_logger("vuln_scanner")

    async def scan_technologies(
        self,
        webtech_result: WebTechResult,
        options: ScanOptions | None = None,
    ) -> VulnScanResult:
        """Scan detected technologies for known vulnerabilities."""
        start_time = time.time()
        settings = get_settings()

        self.logger.info("vuln_scan_started", target=webtech_result.target)

        technology_vulns: list[TechnologyVulnerability] = []
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        # Process each detected technology
        tasks = []
        for tech in webtech_result.technologies:
            tech_name = tech.name.lower()

            # Check if we have CPE mapping for this technology
            if tech_name in self.TECH_TO_CPE:
                vendor, product = self.TECH_TO_CPE[tech_name]
                tasks.append(
                    self._fetch_vulnerabilities(
                        tech.name,
                        tech.version,
                        tech.categories[0] if tech.categories else None,
                        vendor,
                        product,
                        settings.http_timeout,
                    )
                )

        # Run vulnerability lookups concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    self.logger.warning("vuln_lookup_failed", error=str(result))
                    continue

                if result and result.vulnerabilities:
                    technology_vulns.append(result)
                    total_critical += result.critical_count
                    total_high += result.high_count
                    for vuln in result.vulnerabilities:
                        if vuln.severity == "medium":
                            total_medium += 1
                        elif vuln.severity == "low":
                            total_low += 1

        duration = time.time() - start_time

        result = VulnScanResult(
            target=webtech_result.target,
            technology_vulnerabilities=technology_vulns,
            total_vulnerabilities=sum(tv.total_vulnerabilities for tv in technology_vulns),
            critical_count=total_critical,
            high_count=total_high,
            medium_count=total_medium,
            low_count=total_low,
            scanned_at=datetime.utcnow(),
            duration_seconds=duration,
            data_sources=["NVD (NIST)"],
        )

        self.logger.info(
            "vuln_scan_completed",
            target=webtech_result.target,
            total_vulns=result.total_vulnerabilities,
            critical=total_critical,
            high=total_high,
            duration=duration,
        )

        return result

    async def _fetch_vulnerabilities(
        self,
        tech_name: str,
        version: str | None,
        category: str | None,
        vendor: str,
        product: str,
        timeout: int,
    ) -> TechnologyVulnerability:
        """Fetch vulnerabilities for a specific technology from NVD."""
        vulnerabilities: list[VulnerabilityInfo] = []

        # Build CPE match string
        # CPE 2.3 format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        cpe_match = f"cpe:2.3:a:{vendor}:{product}"
        if version:
            # Clean version string
            clean_version = version.split()[0].strip("v")
            cpe_match += f":{clean_version}"

        try:
            params = {
                "keywordSearch": f"{vendor} {product}",
                "resultsPerPage": 20,
            }

            # Add version-specific search if available
            if version:
                params["keywordSearch"] += f" {version.split()[0]}"

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(self.NVD_API_URL, params=params)

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = self._parse_nvd_response(data)
                elif response.status_code == 403:
                    # Rate limited - NVD requires API key for higher rate limits
                    self.logger.debug("nvd_rate_limited", tech=tech_name)
                else:
                    self.logger.debug(
                        "nvd_request_failed",
                        tech=tech_name,
                        status=response.status_code,
                    )

        except Exception as e:
            self.logger.debug("nvd_fetch_error", tech=tech_name, error=str(e))

        # Count by severity
        critical_count = sum(1 for v in vulnerabilities if v.severity == "critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "high")

        return TechnologyVulnerability(
            technology=tech_name,
            version=version,
            category=category,
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
        )

    def _parse_nvd_response(self, data: dict) -> list[VulnerabilityInfo]:
        """Parse NVD API response."""
        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id:
                continue

            # Get description
            descriptions = cve.get("descriptions", [])
            description = None
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            # Get CVSS score and severity
            cvss_score = None
            cvss_version = None
            severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"

            metrics = cve.get("metrics", {})

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0]
                    if "cvssData" in cvss_data:
                        cvss_info = cvss_data["cvssData"]
                        cvss_score = cvss_info.get("baseScore")
                        cvss_version = cvss_info.get("version")
                        base_severity = cvss_info.get("baseSeverity", "").lower()
                        if base_severity in ["critical", "high", "medium", "low"]:
                            severity = base_severity  # type: ignore
                        break

            # Get dates
            published = cve.get("published")
            modified = cve.get("lastModified")

            published_date = None
            if published:
                try:
                    published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except ValueError:
                    pass

            modified_date = None
            if modified:
                try:
                    modified_date = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                except ValueError:
                    pass

            # Get references
            references = []
            for ref in cve.get("references", []):
                url = ref.get("url")
                if url:
                    references.append(url)

            vulnerabilities.append(
                VulnerabilityInfo(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_version=cvss_version,
                    published_date=published_date,
                    last_modified=modified_date,
                    references=references[:5],  # Limit references
                )
            )

        return vulnerabilities
