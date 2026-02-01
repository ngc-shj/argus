"""CISA KEV (Known Exploited Vulnerabilities) checker."""

import asyncio
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.vuln import VulnScanResult, VulnerabilityInfo


class KEVEntry:
    """CISA KEV catalog entry."""

    def __init__(self, data: dict) -> None:
        self.cve_id: str = data.get("cveID", "")
        self.vendor_project: str = data.get("vendorProject", "")
        self.product: str = data.get("product", "")
        self.vulnerability_name: str = data.get("vulnerabilityName", "")
        self.date_added: str = data.get("dateAdded", "")
        self.short_description: str = data.get("shortDescription", "")
        self.required_action: str = data.get("requiredAction", "")
        self.due_date: str = data.get("dueDate", "")
        self.known_ransomware_campaign_use: str = data.get("knownRansomwareCampaignUse", "Unknown")
        self.notes: str = data.get("notes", "")

    @property
    def is_ransomware_related(self) -> bool:
        return self.known_ransomware_campaign_use.lower() == "known"


class KEVMatchResult:
    """Result of KEV matching for a vulnerability."""

    def __init__(
        self,
        vulnerability: VulnerabilityInfo,
        kev_entry: KEVEntry,
    ) -> None:
        self.vulnerability = vulnerability
        self.kev_entry = kev_entry

    @property
    def severity_boost(self) -> str:
        """KEV vulnerabilities should be treated as critical."""
        return "critical"


class KEVCheckResult:
    """Result of KEV checking."""

    def __init__(self) -> None:
        self.total_cves_checked: int = 0
        self.kev_matches: list[KEVMatchResult] = []
        self.ransomware_related: list[KEVMatchResult] = []
        self.catalog_version: str = ""
        self.catalog_date: str = ""
        self.total_kev_entries: int = 0
        self.checked_at: datetime = datetime.utcnow()

    @property
    def total_matches(self) -> int:
        return len(self.kev_matches)

    @property
    def has_kev_vulnerabilities(self) -> bool:
        return self.total_matches > 0


class KEVChecker:
    """Checker for CISA Known Exploited Vulnerabilities catalog."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_DURATION_HOURS = 24

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.logger = get_logger("kev_checker")
        self.cache_dir = cache_dir or Path.home() / ".cache" / "argus"
        self.cache_file = self.cache_dir / "kev_catalog.json"
        self._catalog: dict[str, KEVEntry] = {}
        self._catalog_version: str = ""
        self._catalog_date: str = ""

    async def load_catalog(self, force_refresh: bool = False) -> bool:
        """Load KEV catalog from cache or download fresh."""
        # Check if cache exists and is recent
        if not force_refresh and self._is_cache_valid():
            return self._load_from_cache()

        # Download fresh catalog
        return await self._download_catalog()

    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is still valid."""
        if not self.cache_file.exists():
            return False

        # Check cache age
        mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
        age = datetime.now() - mtime

        return age < timedelta(hours=self.CACHE_DURATION_HOURS)

    def _load_from_cache(self) -> bool:
        """Load catalog from cache file."""
        try:
            with open(self.cache_file) as f:
                data = json.load(f)

            self._parse_catalog(data)
            self.logger.info("kev_catalog_loaded_from_cache", entries=len(self._catalog))
            return True

        except Exception as e:
            self.logger.warning("kev_cache_load_failed", error=str(e))
            return False

    async def _download_catalog(self) -> bool:
        """Download fresh KEV catalog from CISA."""
        settings = get_settings()

        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout) as client:
                response = await client.get(self.KEV_URL)

                if response.status_code == 200:
                    data = response.json()

                    # Save to cache
                    self.cache_dir.mkdir(parents=True, exist_ok=True)
                    with open(self.cache_file, "w") as f:
                        json.dump(data, f)

                    self._parse_catalog(data)
                    self.logger.info(
                        "kev_catalog_downloaded",
                        entries=len(self._catalog),
                        version=self._catalog_version,
                    )
                    return True

        except Exception as e:
            self.logger.error("kev_download_failed", error=str(e))

        # Try to use stale cache if download fails
        if self.cache_file.exists():
            return self._load_from_cache()

        return False

    def _parse_catalog(self, data: dict) -> None:
        """Parse KEV catalog JSON."""
        self._catalog = {}
        self._catalog_version = data.get("catalogVersion", "")
        self._catalog_date = data.get("dateReleased", "")

        for vuln in data.get("vulnerabilities", []):
            entry = KEVEntry(vuln)
            if entry.cve_id:
                self._catalog[entry.cve_id.upper()] = entry

    async def check_vulnerabilities(
        self, vuln_result: VulnScanResult
    ) -> KEVCheckResult:
        """Check vulnerability scan results against KEV catalog."""
        result = KEVCheckResult()

        # Ensure catalog is loaded
        if not self._catalog:
            await self.load_catalog()

        result.catalog_version = self._catalog_version
        result.catalog_date = self._catalog_date
        result.total_kev_entries = len(self._catalog)

        # Check each vulnerability
        for tech_vuln in vuln_result.technology_vulnerabilities:
            for vuln in tech_vuln.vulnerabilities:
                result.total_cves_checked += 1

                cve_id = vuln.cve_id.upper() if vuln.cve_id else ""

                if cve_id in self._catalog:
                    kev_entry = self._catalog[cve_id]
                    match = KEVMatchResult(vuln, kev_entry)
                    result.kev_matches.append(match)

                    if kev_entry.is_ransomware_related:
                        result.ransomware_related.append(match)

        result.checked_at = datetime.utcnow()

        self.logger.info(
            "kev_check_completed",
            cves_checked=result.total_cves_checked,
            kev_matches=result.total_matches,
            ransomware_related=len(result.ransomware_related),
        )

        return result

    async def check_cve_list(self, cve_ids: list[str]) -> KEVCheckResult:
        """Check a list of CVE IDs against KEV catalog."""
        result = KEVCheckResult()

        # Ensure catalog is loaded
        if not self._catalog:
            await self.load_catalog()

        result.catalog_version = self._catalog_version
        result.catalog_date = self._catalog_date
        result.total_kev_entries = len(self._catalog)
        result.total_cves_checked = len(cve_ids)

        for cve_id in cve_ids:
            cve_upper = cve_id.upper()

            if cve_upper in self._catalog:
                kev_entry = self._catalog[cve_upper]

                # Create a minimal VulnerabilityInfo for the match
                vuln_info = VulnerabilityInfo(
                    cve_id=cve_id,
                    description=kev_entry.short_description,
                    severity="critical",  # KEV vulns are critical by definition
                )

                match = KEVMatchResult(vuln_info, kev_entry)
                result.kev_matches.append(match)

                if kev_entry.is_ransomware_related:
                    result.ransomware_related.append(match)

        result.checked_at = datetime.utcnow()
        return result

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE ID is in the KEV catalog."""
        return cve_id.upper() in self._catalog

    def get_kev_entry(self, cve_id: str) -> KEVEntry | None:
        """Get KEV entry for a CVE ID."""
        return self._catalog.get(cve_id.upper())

    @property
    def catalog_size(self) -> int:
        """Get number of entries in catalog."""
        return len(self._catalog)

    async def get_stats(self) -> dict:
        """Get KEV catalog statistics."""
        if not self._catalog:
            await self.load_catalog()

        ransomware_count = sum(
            1 for entry in self._catalog.values()
            if entry.is_ransomware_related
        )

        # Count by vendor
        vendors: dict[str, int] = {}
        for entry in self._catalog.values():
            vendor = entry.vendor_project
            vendors[vendor] = vendors.get(vendor, 0) + 1

        top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_entries": len(self._catalog),
            "catalog_version": self._catalog_version,
            "catalog_date": self._catalog_date,
            "ransomware_related": ransomware_count,
            "top_vendors": dict(top_vendors),
        }
