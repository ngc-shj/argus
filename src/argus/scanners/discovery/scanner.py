"""Discovery scanner for robots.txt, sitemap.xml, and more."""

import asyncio
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.discovery import (
    DiscoveryResult,
    RobotsTxtResult,
    SitemapResult,
    SecurityTxtResult,
    HumansTxtResult,
    DisallowedPath,
    SitemapURL,
)


class DiscoveryScanner:
    """Scanner for robots.txt, sitemap.xml, and other discovery files."""

    # Interesting paths that might reveal sensitive content when disallowed
    SENSITIVE_DISALLOW_PATTERNS = [
        r"/admin",
        r"/api",
        r"/backup",
        r"/config",
        r"/cron",
        r"/database",
        r"/debug",
        r"/dev",
        r"/export",
        r"/import",
        r"/internal",
        r"/log",
        r"/old",
        r"/private",
        r"/secret",
        r"/staging",
        r"/temp",
        r"/test",
        r"/tmp",
        r"/upload",
        r"/user",
        r"/wp-admin",
        r"/wp-includes",
        r"\.git",
        r"\.svn",
        r"\.env",
        r"\.bak",
        r"\.sql",
        r"\.zip",
        r"\.tar",
    ]

    def __init__(self) -> None:
        self.logger = get_logger("discovery_scanner")

    async def scan(self, target: str) -> DiscoveryResult:
        """Run discovery scan on target."""
        start_time = time.time()
        settings = get_settings()

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        self.logger.info("discovery_scan_started", target=target)

        result = DiscoveryResult(target=target)

        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Run all checks concurrently
            tasks = [
                self._parse_robots_txt(client, base_url),
                self._parse_sitemap_xml(client, base_url),
                self._parse_security_txt(client, base_url),
                self._parse_humans_txt(client, base_url),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            if isinstance(results[0], RobotsTxtResult):
                result.robots = results[0]
            if isinstance(results[1], SitemapResult):
                result.sitemap = results[1]
            if isinstance(results[2], SecurityTxtResult):
                result.security_txt = results[2]
            if isinstance(results[3], HumansTxtResult):
                result.humans_txt = results[3]

        # Collect all discovered paths
        result.discovered_paths = self._collect_paths(result)
        result.interesting_paths = self._find_interesting_paths(result)

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "discovery_scan_completed",
            target=target,
            robots_found=result.robots is not None and result.robots.found,
            sitemap_found=result.sitemap is not None and result.sitemap.found,
            discovered_paths=len(result.discovered_paths),
            duration=duration,
        )

        return result

    async def _parse_robots_txt(
        self, client: httpx.AsyncClient, base_url: str
    ) -> RobotsTxtResult:
        """Parse robots.txt file."""
        url = urljoin(base_url, "/robots.txt")
        result = RobotsTxtResult(url=url)

        try:
            response = await client.get(url)

            if response.status_code != 200:
                result.found = False
                return result

            result.found = True
            result.raw_content = response.text

            # Parse content
            current_agent = "*"
            user_agents: list[str] = []
            disallowed: list[DisallowedPath] = []
            allowed: list[str] = []
            sitemaps: list[str] = []
            crawl_delay: int | None = None

            for line in response.text.split("\n"):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse directive
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if key == "user-agent":
                        current_agent = value
                        if value not in user_agents:
                            user_agents.append(value)

                    elif key == "disallow" and value:
                        # Check if it's an interesting disallow
                        is_interesting = any(
                            re.search(pattern, value, re.IGNORECASE)
                            for pattern in self.SENSITIVE_DISALLOW_PATTERNS
                        )
                        disallowed.append(DisallowedPath(
                            path=value,
                            user_agent=current_agent,
                            is_interesting=is_interesting,
                        ))

                    elif key == "allow" and value:
                        allowed.append(value)

                    elif key == "sitemap":
                        sitemaps.append(value)

                    elif key == "crawl-delay":
                        try:
                            crawl_delay = int(value)
                        except ValueError:
                            pass

            result.user_agents = user_agents
            result.disallowed_paths = disallowed
            result.allowed_paths = allowed
            result.sitemaps = sitemaps
            result.crawl_delay = crawl_delay

            # Security analysis
            result.blocks_all = any(
                d.path == "/" and d.user_agent == "*"
                for d in disallowed
            )
            result.interesting_disallows = [
                d for d in disallowed if d.is_interesting
            ]

        except Exception as e:
            self.logger.debug("robots_txt_failed", error=str(e))
            result.error = str(e)

        return result

    async def _parse_sitemap_xml(
        self, client: httpx.AsyncClient, base_url: str
    ) -> SitemapResult:
        """Parse sitemap.xml file."""
        # Check common sitemap locations
        sitemap_paths = [
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/sitemaps.xml",
            "/sitemap/sitemap.xml",
        ]

        result = SitemapResult()

        for path in sitemap_paths:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url)

                if response.status_code == 200 and "xml" in response.headers.get("content-type", "").lower():
                    result.found = True
                    result.url = url
                    result.raw_content = response.text[:10000]  # Limit stored content

                    # Parse XML
                    try:
                        root = ET.fromstring(response.content)
                        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                        # Check if it's a sitemap index
                        sitemap_locs = root.findall(".//sm:sitemap/sm:loc", ns)
                        if sitemap_locs:
                            result.is_index = True
                            result.nested_sitemaps = [
                                loc.text for loc in sitemap_locs if loc.text
                            ]

                        # Get URLs
                        urls: list[SitemapURL] = []
                        for url_elem in root.findall(".//sm:url", ns):
                            loc = url_elem.find("sm:loc", ns)
                            lastmod = url_elem.find("sm:lastmod", ns)
                            priority = url_elem.find("sm:priority", ns)
                            changefreq = url_elem.find("sm:changefreq", ns)

                            if loc is not None and loc.text:
                                # Check if URL looks interesting
                                is_interesting = any(
                                    kw in loc.text.lower()
                                    for kw in ["admin", "api", "login", "user", "account", "dashboard", "config"]
                                )

                                urls.append(SitemapURL(
                                    loc=loc.text,
                                    lastmod=lastmod.text if lastmod is not None else None,
                                    priority=priority.text if priority is not None else None,
                                    changefreq=changefreq.text if changefreq is not None else None,
                                    is_interesting=is_interesting,
                                ))

                        result.urls = urls[:1000]  # Limit to 1000 URLs
                        result.total_urls = len(urls)

                    except ET.ParseError as e:
                        result.parse_error = str(e)

                    break

            except Exception as e:
                self.logger.debug("sitemap_check_failed", path=path, error=str(e))

        return result

    async def _parse_security_txt(
        self, client: httpx.AsyncClient, base_url: str
    ) -> SecurityTxtResult:
        """Parse security.txt file."""
        # Check both locations
        paths = [
            "/.well-known/security.txt",
            "/security.txt",
        ]

        result = SecurityTxtResult()

        for path in paths:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url)

                if response.status_code == 200:
                    result.found = True
                    result.url = url
                    result.raw_content = response.text

                    # Parse fields
                    for line in response.text.split("\n"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        if ":" in line:
                            key, value = line.split(":", 1)
                            key = key.strip().lower()
                            value = value.strip()

                            if key == "contact":
                                result.contacts.append(value)
                            elif key == "expires":
                                result.expires = value
                            elif key == "encryption":
                                result.encryption = value
                            elif key == "acknowledgments" or key == "acknowledgements":
                                result.acknowledgments = value
                            elif key == "preferred-languages":
                                result.preferred_languages = value
                            elif key == "canonical":
                                result.canonical = value
                            elif key == "policy":
                                result.policy = value
                            elif key == "hiring":
                                result.hiring = value

                    break

            except Exception as e:
                self.logger.debug("security_txt_failed", path=path, error=str(e))

        return result

    async def _parse_humans_txt(
        self, client: httpx.AsyncClient, base_url: str
    ) -> HumansTxtResult:
        """Parse humans.txt file."""
        url = urljoin(base_url, "/humans.txt")
        result = HumansTxtResult(url=url)

        try:
            response = await client.get(url)

            if response.status_code == 200:
                result.found = True
                result.raw_content = response.text

                # Try to extract team members and technologies
                content = response.text.lower()

                # Common sections in humans.txt
                if "/* team */" in content or "/* site */" in content:
                    result.is_standard_format = True

        except Exception as e:
            self.logger.debug("humans_txt_failed", error=str(e))

        return result

    def _collect_paths(self, result: DiscoveryResult) -> list[str]:
        """Collect all discovered paths."""
        paths: set[str] = set()

        # From robots.txt
        if result.robots and result.robots.found:
            for disallow in result.robots.disallowed_paths:
                paths.add(disallow.path)
            for allow in result.robots.allowed_paths:
                paths.add(allow)

        # From sitemap
        if result.sitemap and result.sitemap.found:
            for url in result.sitemap.urls[:100]:  # Limit
                parsed = urlparse(url.loc)
                paths.add(parsed.path)

        return sorted(list(paths))

    def _find_interesting_paths(self, result: DiscoveryResult) -> list[str]:
        """Find interesting paths from all sources."""
        interesting: set[str] = set()

        # Interesting disallows from robots.txt
        if result.robots and result.robots.interesting_disallows:
            for disallow in result.robots.interesting_disallows:
                interesting.add(disallow.path)

        # Interesting URLs from sitemap
        if result.sitemap:
            for url in result.sitemap.urls:
                if url.is_interesting:
                    parsed = urlparse(url.loc)
                    interesting.add(parsed.path)

        return sorted(list(interesting))
