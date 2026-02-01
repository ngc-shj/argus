"""Wayback Machine URL extraction scanner."""

import asyncio
import re
import time
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.wayback import (
    WaybackResult,
    WaybackURL,
    ParameterInfo,
)


class WaybackScanner:
    """Scanner for extracting URLs from Wayback Machine."""

    # Wayback Machine CDX API
    CDX_API = "https://web.archive.org/cdx/search/cdx"

    # Interesting file extensions
    INTERESTING_EXTENSIONS = {
        "sensitive": [".sql", ".bak", ".backup", ".old", ".zip", ".tar", ".gz", ".7z",
                      ".env", ".git", ".svn", ".htaccess", ".htpasswd", ".config",
                      ".ini", ".log", ".key", ".pem", ".pfx", ".crt"],
        "source": [".py", ".rb", ".php", ".java", ".cs", ".go", ".rs", ".c", ".cpp",
                   ".h", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"],
        "config": [".json", ".yaml", ".yml", ".xml", ".toml", ".conf", ".properties"],
        "api": ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/swagger",
                "/openapi", "/_api/", "/internal/"],
        "admin": ["/admin", "/administrator", "/manager", "/dashboard", "/control",
                  "/portal", "/login", "/signin", "/auth", "/panel", "/console"],
    }

    # Interesting parameters that might be vulnerable
    INTERESTING_PARAMS = [
        "id", "user", "username", "email", "password", "pass", "token", "key",
        "api_key", "apikey", "secret", "auth", "session", "redirect", "url",
        "next", "return", "file", "path", "page", "document", "download",
        "upload", "image", "include", "require", "load", "cmd", "exec",
        "query", "search", "filter", "sort", "order", "callback", "jsonp",
    ]

    def __init__(self) -> None:
        self.logger = get_logger("wayback_scanner")

    async def scan(
        self,
        target: str,
        max_urls: int = 5000,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> WaybackResult:
        """Scan Wayback Machine for historical URLs."""
        start_time = time.time()
        settings = get_settings()

        # Normalize domain
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.logger.info("wayback_scan_started", target=domain)

        result = WaybackResult(target=domain)

        try:
            async with httpx.AsyncClient(
                timeout=60.0,  # Wayback can be slow
                follow_redirects=True,
            ) as client:
                # Build CDX API query
                params = {
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode,mimetype,length",
                    "collapse": "urlkey",
                    "limit": str(max_urls),
                }

                if from_date:
                    params["from"] = from_date
                if to_date:
                    params["to"] = to_date

                response = await client.get(self.CDX_API, params=params)

                if response.status_code != 200:
                    result.errors.append(f"CDX API returned {response.status_code}")
                    return result

                # Parse response
                lines = response.text.strip().split("\n")
                if not lines or lines[0] == "":
                    result.total_urls = 0
                    return result

                # First line is header
                urls: list[WaybackURL] = []
                all_params: list[str] = []
                extension_counts: Counter[str] = Counter()
                path_patterns: set[str] = set()

                for line in lines[1:]:  # Skip header
                    try:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            original = parts[0]
                            timestamp = parts[1]
                            status = parts[2]
                            mimetype = parts[3]
                            length = parts[4]

                            # Categorize URL
                            categories = self._categorize_url(original)
                            is_interesting = len(categories) > 0

                            # Extract parameters
                            parsed = urlparse(original)
                            params_list = list(parse_qs(parsed.query).keys())
                            all_params.extend(params_list)

                            # Get extension
                            ext = self._get_extension(parsed.path)
                            if ext:
                                extension_counts[ext] += 1

                            # Get path pattern
                            path_pattern = self._get_path_pattern(parsed.path)
                            path_patterns.add(path_pattern)

                            url_obj = WaybackURL(
                                url=original,
                                timestamp=timestamp,
                                status_code=status if status != "-" else None,
                                mimetype=mimetype if mimetype != "-" else None,
                                length=int(length) if length != "-" else None,
                                categories=categories,
                                is_interesting=is_interesting,
                                parameters=params_list,
                            )
                            urls.append(url_obj)

                    except Exception as e:
                        self.logger.debug("wayback_url_parse_failed", line=line, error=str(e))

                result.urls = urls
                result.total_urls = len(urls)

                # Analyze parameters
                param_counter = Counter(all_params)
                for param, count in param_counter.most_common(50):
                    is_sensitive = param.lower() in self.INTERESTING_PARAMS
                    result.parameters.append(ParameterInfo(
                        name=param,
                        count=count,
                        is_sensitive=is_sensitive,
                    ))

                # Interesting URLs (limited)
                result.interesting_urls = [u for u in urls if u.is_interesting][:200]

                # File extensions
                result.file_extensions = dict(extension_counts.most_common(30))

                # Path patterns
                result.unique_paths = len(path_patterns)

                # Identify sensitive file types found
                result.sensitive_files = [
                    u.url for u in urls
                    if "sensitive" in u.categories
                ][:100]

                # API endpoints
                result.api_endpoints = [
                    u.url for u in urls
                    if "api" in u.categories
                ][:100]

                # Admin paths
                result.admin_paths = [
                    u.url for u in urls
                    if "admin" in u.categories
                ][:100]

        except Exception as e:
            self.logger.error("wayback_scan_failed", error=str(e))
            result.errors.append(str(e))

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "wayback_scan_completed",
            target=domain,
            total_urls=result.total_urls,
            interesting=len(result.interesting_urls),
            duration=duration,
        )

        return result

    def _categorize_url(self, url: str) -> list[str]:
        """Categorize URL based on patterns."""
        categories: list[str] = []
        url_lower = url.lower()

        for category, patterns in self.INTERESTING_EXTENSIONS.items():
            for pattern in patterns:
                if pattern in url_lower:
                    categories.append(category)
                    break

        return list(set(categories))

    def _get_extension(self, path: str) -> str | None:
        """Extract file extension from path."""
        # Remove query string
        path = path.split("?")[0]

        # Get extension
        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].lower()
            if len(ext) <= 10 and ext.isalpha() or ext[1:].isalnum():
                return ext
        return None

    def _get_path_pattern(self, path: str) -> str:
        """Convert path to pattern (normalize IDs)."""
        # Replace numeric IDs with placeholder
        pattern = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        # Replace UUIDs
        pattern = re.sub(
            r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            "/{uuid}",
            pattern,
            flags=re.IGNORECASE
        )
        # Replace hashes
        pattern = re.sub(r"/[a-f0-9]{32,}", "/{hash}", pattern, flags=re.IGNORECASE)

        return pattern
