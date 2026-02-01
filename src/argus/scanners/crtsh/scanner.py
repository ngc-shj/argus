"""Certificate Transparency Log scanner using crt.sh."""

import re
import time
from datetime import datetime

import httpx

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.crtsh import (
    CertificateEntry,
    CrtshResult,
    DiscoveredSubdomain,
)
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


@ScannerRegistry.register
class CrtshScanner(BaseScanner[CrtshResult]):
    """Certificate Transparency log scanner using crt.sh."""

    CRTSH_URL = "https://crt.sh/"

    @property
    def name(self) -> str:
        return "crtsh"

    @property
    def description(self) -> str:
        return "Certificate Transparency log subdomain discovery via crt.sh"

    def get_capabilities(self) -> list[str]:
        return [
            "Subdomain discovery from CT logs",
            "Certificate enumeration",
            "Wildcard domain detection",
            "Historical certificate data",
            "Issuer information",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate that target has a domain."""
        return target.domain is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> CrtshResult:
        """Execute CT log scan via crt.sh."""
        if not target.domain:
            raise ScanError("Domain is required for CT log scan", scanner=self.name)

        settings = get_settings()
        start_time = time.time()

        self.logger.info("crtsh_scan_started", target=target.domain)

        try:
            # Query crt.sh API
            certificates = await self._query_crtsh(target.domain, settings.http_timeout)

            # Extract unique subdomains
            subdomains_map: dict[str, DiscoveredSubdomain] = {}
            wildcard_domains: set[str] = set()

            for cert in certificates:
                for name in cert.name_values:
                    # Clean and normalize the domain name
                    clean_name = self._normalize_domain(name, target.domain)
                    if not clean_name:
                        continue

                    # Check for wildcard
                    if clean_name.startswith("*."):
                        wildcard_domains.add(clean_name)
                        # Also add without wildcard prefix
                        clean_name = clean_name[2:]

                    if clean_name not in subdomains_map:
                        subdomain = self._extract_subdomain(clean_name, target.domain)
                        subdomains_map[clean_name] = DiscoveredSubdomain(
                            subdomain=subdomain,
                            full_domain=clean_name,
                            source="crt.sh",
                            certificate_ids=[cert.id] if cert.id else [],
                            first_seen=cert.not_before,
                            last_seen=cert.not_after,
                            is_wildcard=name.startswith("*."),
                        )
                    else:
                        # Update existing entry
                        existing = subdomains_map[clean_name]
                        if cert.id and cert.id not in existing.certificate_ids:
                            existing.certificate_ids.append(cert.id)
                        if cert.not_before and (
                            not existing.first_seen or cert.not_before < existing.first_seen
                        ):
                            existing.first_seen = cert.not_before
                        if cert.not_after and (
                            not existing.last_seen or cert.not_after > existing.last_seen
                        ):
                            existing.last_seen = cert.not_after

            duration = time.time() - start_time

            # Build unique subdomain list (sorted)
            unique_subdomains = sorted(subdomains_map.keys())

            result = CrtshResult(
                target=target.domain,
                certificates=certificates,
                discovered_subdomains=list(subdomains_map.values()),
                unique_subdomains=unique_subdomains,
                wildcard_domains=sorted(wildcard_domains),
                total_certificates=len(certificates),
                scanned_at=datetime.utcnow(),
                duration_seconds=duration,
            )

            self.logger.info(
                "crtsh_scan_completed",
                target=target.domain,
                certificates=len(certificates),
                subdomains=len(unique_subdomains),
                duration=duration,
            )

            return result

        except Exception as e:
            self.logger.error("crtsh_scan_failed", target=target.domain, error=str(e))
            raise ScanError(
                f"CT log scan failed: {e}",
                scanner=self.name,
                target=target.domain,
            ) from e

    async def _query_crtsh(self, domain: str, timeout: int) -> list[CertificateEntry]:
        """Query crt.sh API for certificates."""
        # Query for the domain and all subdomains
        url = f"{self.CRTSH_URL}?q=%.{domain}&output=json"

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()

            certificates = []
            seen_ids: set[int] = set()

            for entry in data:
                cert_id = entry.get("id")

                # Skip duplicates
                if cert_id in seen_ids:
                    continue
                seen_ids.add(cert_id)

                # Parse dates
                not_before = self._parse_date(entry.get("not_before"))
                not_after = self._parse_date(entry.get("not_after"))

                # Check if expired
                is_expired = False
                if not_after and not_after < datetime.utcnow():
                    is_expired = True

                # Parse name_value (can contain multiple domains separated by newlines)
                name_value = entry.get("name_value", "")
                name_values = [
                    n.strip().lower()
                    for n in name_value.split("\n")
                    if n.strip()
                ]

                certificates.append(
                    CertificateEntry(
                        id=cert_id,
                        issuer_ca_id=entry.get("issuer_ca_id"),
                        issuer_name=entry.get("issuer_name"),
                        common_name=entry.get("common_name", "").lower(),
                        name_values=name_values,
                        serial_number=entry.get("serial_number"),
                        not_before=not_before,
                        not_after=not_after,
                        is_expired=is_expired,
                    )
                )

            return certificates

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse date string from crt.sh."""
        if not date_str:
            return None
        try:
            # crt.sh returns dates in format like "2024-01-15T00:00:00"
            return datetime.fromisoformat(date_str.replace("T", " ").split(".")[0])
        except (ValueError, AttributeError):
            return None

    def _normalize_domain(self, name: str, base_domain: str) -> str | None:
        """Normalize and validate a domain name."""
        name = name.strip().lower()

        # Remove leading wildcard for validation
        check_name = name[2:] if name.startswith("*.") else name

        # Must end with base domain
        if not check_name.endswith(base_domain) and check_name != base_domain:
            return None

        # Basic domain validation
        pattern = r"^(\*\.)?[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$"
        if not re.match(pattern, name):
            return None

        return name

    def _extract_subdomain(self, full_domain: str, base_domain: str) -> str:
        """Extract subdomain part from full domain."""
        if full_domain == base_domain:
            return ""

        if full_domain.endswith("." + base_domain):
            return full_domain[: -(len(base_domain) + 1)]

        return full_domain
