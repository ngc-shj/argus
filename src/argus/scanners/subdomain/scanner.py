"""Passive subdomain enumeration from 20+ sources."""

import asyncio
import re
import time
from datetime import datetime
from typing import Any

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger


class SubdomainSource:
    """Result from a single subdomain source."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.subdomains: set[str] = set()
        self.success: bool = False
        self.error: str | None = None
        self.duration: float = 0.0


class SubdomainEnumResult:
    """Result of subdomain enumeration."""

    def __init__(self) -> None:
        self.target: str = ""
        self.all_subdomains: set[str] = set()
        self.sources: list[SubdomainSource] = []
        self.total_unique: int = 0
        self.sources_successful: int = 0
        self.sources_failed: int = 0
        self.scanned_at: datetime = datetime.utcnow()
        self.duration_seconds: float = 0.0

    def add_source_result(self, source: SubdomainSource) -> None:
        """Add result from a source."""
        self.sources.append(source)
        if source.success:
            self.sources_successful += 1
            self.all_subdomains.update(source.subdomains)
        else:
            self.sources_failed += 1
        self.total_unique = len(self.all_subdomains)


class SubdomainEnumerator:
    """Passive subdomain enumeration using 20+ sources."""

    def __init__(self) -> None:
        self.logger = get_logger("subdomain_enum")

    async def enumerate(
        self,
        domain: str,
        sources: list[str] | None = None,
        timeout: int = 30,
    ) -> SubdomainEnumResult:
        """Enumerate subdomains from multiple sources."""
        start_time = time.time()

        self.logger.info("subdomain_enum_started", domain=domain)

        result = SubdomainEnumResult()
        result.target = domain

        # Available sources
        all_sources = {
            "crtsh": self._fetch_crtsh,
            "hackertarget": self._fetch_hackertarget,
            "threatcrowd": self._fetch_threatcrowd,
            "alienvault": self._fetch_alienvault,
            "urlscan": self._fetch_urlscan,
            "rapiddns": self._fetch_rapiddns,
            "wayback": self._fetch_wayback,
            "bufferover": self._fetch_bufferover,
            "anubis": self._fetch_anubis,
            "certspotter": self._fetch_certspotter,
            "threatminer": self._fetch_threatminer,
            "webarchive": self._fetch_webarchive,
            "dnsdumpster": self._fetch_dnsdumpster,
            "riddler": self._fetch_riddler,
            "sitedossier": self._fetch_sitedossier,
            "netcraft": self._fetch_netcraft,
            "crtsh_psql": self._fetch_crtsh_psql,
            "securitytrails": self._fetch_securitytrails,
            "shodan": self._fetch_shodan,
            "binaryedge": self._fetch_binaryedge,
        }

        # Use specified sources or all
        if sources:
            selected_sources = {k: v for k, v in all_sources.items() if k in sources}
        else:
            selected_sources = all_sources

        # Run all sources concurrently
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            tasks = []
            for source_name, fetch_func in selected_sources.items():
                tasks.append(self._run_source(source_name, fetch_func, client, domain))

            source_results = await asyncio.gather(*tasks, return_exceptions=True)

            for source_result in source_results:
                if isinstance(source_result, SubdomainSource):
                    result.add_source_result(source_result)
                elif isinstance(source_result, Exception):
                    self.logger.warning("source_exception", error=str(source_result))

        result.scanned_at = datetime.utcnow()
        result.duration_seconds = time.time() - start_time

        self.logger.info(
            "subdomain_enum_completed",
            domain=domain,
            total_subdomains=result.total_unique,
            sources_successful=result.sources_successful,
            sources_failed=result.sources_failed,
            duration=result.duration_seconds,
        )

        return result

    async def _run_source(
        self,
        name: str,
        fetch_func: Any,
        client: httpx.AsyncClient,
        domain: str,
    ) -> SubdomainSource:
        """Run a single source with error handling."""
        source = SubdomainSource(name)
        start = time.time()

        try:
            subdomains = await fetch_func(client, domain)
            source.subdomains = self._filter_subdomains(subdomains, domain)
            source.success = True
        except Exception as e:
            source.error = str(e)
            source.success = False
            self.logger.debug("source_failed", source=name, error=str(e))

        source.duration = time.time() - start
        return source

    def _filter_subdomains(self, subdomains: set[str], domain: str) -> set[str]:
        """Filter and validate subdomains."""
        valid = set()
        domain_lower = domain.lower()

        for sub in subdomains:
            sub = sub.lower().strip().strip(".")

            # Must end with the target domain
            if not sub.endswith(domain_lower):
                continue

            # Must be a valid subdomain format
            if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", sub):
                continue

            # Skip wildcards
            if "*" in sub:
                continue

            valid.add(sub)

        return valid

    # ============ Source implementations ============

    async def _fetch_crtsh(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from crt.sh."""
        subdomains: set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    subdomains.add(name.strip())

        return subdomains

    async def _fetch_crtsh_psql(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from crt.sh with deeper query."""
        subdomains: set[str] = set()
        url = f"https://crt.sh/?q={domain}&output=json"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    subdomains.add(name.strip())

        return subdomains

    async def _fetch_hackertarget(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from HackerTarget."""
        subdomains: set[str] = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

        response = await client.get(url)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.split("\n"):
                if "," in line:
                    subdomain = line.split(",")[0].strip()
                    subdomains.add(subdomain)

        return subdomains

    async def _fetch_threatcrowd(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from ThreatCrowd."""
        subdomains: set[str] = set()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("response_code") == "1":
                for sub in data.get("subdomains", []):
                    subdomains.add(sub)

        return subdomains

    async def _fetch_alienvault(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from AlienVault OTX."""
        subdomains: set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "")
                subdomains.add(hostname)

        return subdomains

    async def _fetch_urlscan(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from URLScan.io."""
        subdomains: set[str] = set()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                subdomain = page.get("domain", "")
                subdomains.add(subdomain)

        return subdomains

    async def _fetch_rapiddns(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from RapidDNS."""
        subdomains: set[str] = set()
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"

        response = await client.get(url)
        if response.status_code == 200:
            # Parse HTML for subdomains
            pattern = rf"([a-zA-Z0-9\-\.]+\.{re.escape(domain)})"
            matches = re.findall(pattern, response.text)
            subdomains.update(matches)

        return subdomains

    async def _fetch_wayback(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Wayback Machine."""
        subdomains: set[str] = set()
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"

        response = await client.get(url)
        if response.status_code == 200:
            for line in response.text.split("\n"):
                if line:
                    try:
                        # Extract subdomain from URL
                        match = re.search(r"https?://([^/]+)", line)
                        if match:
                            subdomains.add(match.group(1))
                    except Exception:
                        pass

        return subdomains

    async def _fetch_bufferover(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from BufferOver.run."""
        subdomains: set[str] = set()
        url = f"https://dns.bufferover.run/dns?q=.{domain}"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for record in data.get("FDNS_A", []) or []:
                if "," in record:
                    subdomain = record.split(",")[1]
                    subdomains.add(subdomain)
            for record in data.get("RDNS", []) or []:
                if "," in record:
                    subdomain = record.split(",")[1]
                    subdomains.add(subdomain)

        return subdomains

    async def _fetch_anubis(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Anubis-DB."""
        subdomains: set[str] = set()
        url = f"https://jldc.me/anubis/subdomains/{domain}"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                subdomains.update(data)

        return subdomains

    async def _fetch_certspotter(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from CertSpotter."""
        subdomains: set[str] = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                for name in cert.get("dns_names", []):
                    subdomains.add(name)

        return subdomains

    async def _fetch_threatminer(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from ThreatMiner."""
        subdomains: set[str] = set()
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("status_code") == "200":
                for sub in data.get("results", []):
                    subdomains.add(sub)

        return subdomains

    async def _fetch_webarchive(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Common Crawl index."""
        subdomains: set[str] = set()
        url = f"http://index.commoncrawl.org/CC-MAIN-2023-23-index?url=*.{domain}&output=json"

        try:
            response = await client.get(url, timeout=60)
            if response.status_code == 200:
                for line in response.text.split("\n"):
                    if line.strip():
                        try:
                            data = __import__("json").loads(line)
                            url_str = data.get("url", "")
                            match = re.search(r"https?://([^/]+)", url_str)
                            if match:
                                subdomains.add(match.group(1))
                        except Exception:
                            pass
        except Exception:
            pass

        return subdomains

    async def _fetch_dnsdumpster(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from DNSDumpster (scraping)."""
        subdomains: set[str] = set()

        # DNSDumpster requires a CSRF token, so we simulate browser interaction
        try:
            # Get the page first for CSRF token
            response = await client.get("https://dnsdumpster.com/")
            if response.status_code == 200:
                # Extract CSRF token
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)

                    # Submit the form
                    cookies = response.cookies
                    headers = {
                        "Referer": "https://dnsdumpster.com/",
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                    data = {
                        "csrfmiddlewaretoken": csrf_token,
                        "targetip": domain,
                        "user": "free",
                    }

                    post_response = await client.post(
                        "https://dnsdumpster.com/",
                        data=data,
                        headers=headers,
                        cookies=cookies,
                    )

                    if post_response.status_code == 200:
                        # Parse response for subdomains
                        pattern = rf"([a-zA-Z0-9\-\.]+\.{re.escape(domain)})"
                        matches = re.findall(pattern, post_response.text)
                        subdomains.update(matches)
        except Exception:
            pass

        return subdomains

    async def _fetch_riddler(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Riddler.io."""
        subdomains: set[str] = set()
        url = f"https://riddler.io/search/exportcsv?q=pld:{domain}"

        try:
            response = await client.get(url)
            if response.status_code == 200:
                for line in response.text.split("\n"):
                    if "," in line:
                        parts = line.split(",")
                        if len(parts) > 0:
                            subdomains.add(parts[0].strip('"'))
        except Exception:
            pass

        return subdomains

    async def _fetch_sitedossier(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from SiteDossier."""
        subdomains: set[str] = set()
        url = f"http://www.sitedossier.com/parentdomain/{domain}"

        try:
            response = await client.get(url)
            if response.status_code == 200:
                pattern = rf'href="/site/([^"]+\.{re.escape(domain)})"'
                matches = re.findall(pattern, response.text)
                subdomains.update(matches)
        except Exception:
            pass

        return subdomains

    async def _fetch_netcraft(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Netcraft."""
        subdomains: set[str] = set()
        url = f"https://searchdns.netcraft.com/?restriction=site+contains&host=*.{domain}"

        try:
            response = await client.get(url)
            if response.status_code == 200:
                pattern = rf"([a-zA-Z0-9\-\.]+\.{re.escape(domain)})"
                matches = re.findall(pattern, response.text)
                subdomains.update(matches)
        except Exception:
            pass

        return subdomains

    # ============ API key required sources ============

    async def _fetch_securitytrails(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from SecurityTrails (requires API key)."""
        subdomains: set[str] = set()
        settings = get_settings()

        api_key = getattr(settings, "securitytrails_api_key", None)
        if not api_key:
            return subdomains

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}

        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{domain}")

        return subdomains

    async def _fetch_shodan(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from Shodan (requires API key)."""
        subdomains: set[str] = set()
        settings = get_settings()

        api_key = getattr(settings, "shodan_api_key", None)
        if not api_key:
            return subdomains

        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"

        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{domain}")

        return subdomains

    async def _fetch_binaryedge(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        """Fetch from BinaryEdge (requires API key)."""
        subdomains: set[str] = set()
        settings = get_settings()

        api_key = getattr(settings, "binaryedge_api_key", None)
        if not api_key:
            return subdomains

        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        headers = {"X-Key": api_key}

        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for sub in data.get("events", []):
                subdomains.add(sub)

        return subdomains
