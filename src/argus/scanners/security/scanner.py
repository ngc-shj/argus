"""Security scanner for exposed files, CORS, redirects, and more."""

import asyncio
import re
import time
from datetime import datetime
from typing import Literal
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.security import (
    SecurityScanResult,
    ExposedFile,
    CORSMisconfiguration,
    OpenRedirect,
    HTTPMethodFinding,
    WAFDetection,
    CloudProvider,
    CloudStorageFinding,
    ActuatorFinding,
    SourceMapFinding,
    DockerK8sFinding,
    HostHeaderInjectionFinding,
    DefaultCredentialFinding,
    CMSFinding,
)


class SecurityScanner:
    """Security scanner for common web vulnerabilities and misconfigurations."""

    # Exposed file/directory paths to check
    EXPOSED_PATHS: list[tuple[str, str, Literal[
        "git", "svn", "hg", "env", "backup", "config", "log",
        "database", "archive", "source", "admin", "api", "other"
    ], Literal["critical", "high", "medium", "low", "info"]]] = [
        # Version Control
        ("/.git/HEAD", "Git repository", "git", "critical"),
        ("/.git/config", "Git config", "git", "critical"),
        ("/.git/logs/HEAD", "Git logs", "git", "high"),
        ("/.svn/entries", "SVN repository", "svn", "critical"),
        ("/.svn/wc.db", "SVN database", "svn", "critical"),
        ("/.hg/store/00manifest.i", "Mercurial repository", "hg", "critical"),
        ("/.bzr/README", "Bazaar repository", "other", "critical"),
        # Environment files
        ("/.env", "Environment file", "env", "critical"),
        ("/.env.local", "Local environment file", "env", "critical"),
        ("/.env.production", "Production environment file", "env", "critical"),
        ("/.env.development", "Development environment file", "env", "high"),
        ("/.env.backup", "Environment backup", "env", "critical"),
        ("/env.js", "JavaScript environment", "env", "high"),
        ("/config.js", "JavaScript config", "config", "high"),
        # Configuration files
        ("/config.php", "PHP config", "config", "high"),
        ("/config.yml", "YAML config", "config", "high"),
        ("/config.yaml", "YAML config", "config", "high"),
        ("/config.json", "JSON config", "config", "high"),
        ("/settings.py", "Python settings", "config", "high"),
        ("/settings.json", "JSON settings", "config", "high"),
        ("/application.properties", "Java properties", "config", "high"),
        ("/application.yml", "Java YAML config", "config", "high"),
        ("/web.config", "IIS config", "config", "high"),
        ("/wp-config.php", "WordPress config", "config", "critical"),
        ("/wp-config.php.bak", "WordPress config backup", "backup", "critical"),
        ("/configuration.php", "Joomla config", "config", "critical"),
        # Backup files
        ("/backup.sql", "SQL backup", "database", "critical"),
        ("/backup.zip", "Backup archive", "archive", "high"),
        ("/backup.tar.gz", "Backup archive", "archive", "high"),
        ("/database.sql", "Database dump", "database", "critical"),
        ("/dump.sql", "Database dump", "database", "critical"),
        ("/db.sql", "Database dump", "database", "critical"),
        ("/data.sql", "Database dump", "database", "critical"),
        ("/.sql", "SQL file", "database", "high"),
        ("/site.zip", "Site backup", "archive", "high"),
        ("/www.zip", "WWW backup", "archive", "high"),
        ("/htdocs.zip", "Htdocs backup", "archive", "high"),
        # Log files
        ("/debug.log", "Debug log", "log", "medium"),
        ("/error.log", "Error log", "log", "medium"),
        ("/access.log", "Access log", "log", "low"),
        ("/app.log", "Application log", "log", "medium"),
        ("/laravel.log", "Laravel log", "log", "medium"),
        ("/storage/logs/laravel.log", "Laravel log", "log", "medium"),
        # Source code
        ("/index.php~", "PHP backup", "source", "medium"),
        ("/index.php.bak", "PHP backup", "source", "medium"),
        ("/index.php.old", "PHP old file", "source", "medium"),
        ("/index.php.swp", "Vim swap file", "source", "medium"),
        ("/.htaccess", "Apache htaccess", "config", "medium"),
        ("/.htpasswd", "Apache htpasswd", "config", "critical"),
        ("/server-status", "Apache status", "admin", "medium"),
        ("/nginx.conf", "Nginx config", "config", "high"),
        # Admin/sensitive paths
        ("/phpmyadmin/", "phpMyAdmin", "admin", "high"),
        ("/pma/", "phpMyAdmin", "admin", "high"),
        ("/adminer.php", "Adminer", "admin", "high"),
        ("/admin/", "Admin panel", "admin", "medium"),
        ("/administrator/", "Admin panel", "admin", "medium"),
        ("/wp-admin/", "WordPress admin", "admin", "info"),
        ("/cpanel/", "cPanel", "admin", "medium"),
        # API documentation
        ("/swagger.json", "Swagger API docs", "api", "medium"),
        ("/swagger.yaml", "Swagger API docs", "api", "medium"),
        ("/openapi.json", "OpenAPI docs", "api", "medium"),
        ("/api-docs", "API documentation", "api", "low"),
        ("/graphql", "GraphQL endpoint", "api", "low"),
        # Other sensitive
        ("/phpinfo.php", "PHP info", "other", "medium"),
        ("/info.php", "PHP info", "other", "medium"),
        ("/test.php", "Test file", "other", "low"),
        ("/debug.php", "Debug file", "other", "medium"),
        ("/.DS_Store", "macOS metadata", "other", "low"),
        ("/Thumbs.db", "Windows metadata", "other", "low"),
        ("/robots.txt", "Robots file", "other", "info"),
        ("/sitemap.xml", "Sitemap", "other", "info"),
        ("/crossdomain.xml", "Flash crossdomain", "config", "medium"),
        ("/clientaccesspolicy.xml", "Silverlight policy", "config", "medium"),
        ("/.well-known/security.txt", "Security contact", "other", "info"),
        ("/composer.json", "Composer deps", "config", "low"),
        ("/package.json", "NPM deps", "config", "low"),
        ("/Gemfile", "Ruby deps", "config", "low"),
        ("/requirements.txt", "Python deps", "config", "low"),
    ]

    # Common redirect parameters
    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_uri", "redirect_url", "redir",
        "return", "return_url", "returnUrl", "returnTo", "return_to",
        "next", "next_url", "nextUrl", "goto", "go", "target",
        "dest", "destination", "out", "continue", "continueTo",
        "link", "forward", "forward_url", "callback", "callback_url",
    ]

    # WAF signatures
    WAF_SIGNATURES: dict[str, list[tuple[str, str]]] = {
        "cloudflare": [
            ("server", "cloudflare"),
            ("cf-ray", ""),
            ("cf-cache-status", ""),
        ],
        "aws_waf": [
            ("x-amzn-requestid", ""),
            ("x-amz-cf-id", ""),
        ],
        "akamai": [
            ("x-akamai-transformed", ""),
            ("akamai-grn", ""),
        ],
        "imperva": [
            ("x-cdn", "imperva"),
            ("x-iinfo", ""),
        ],
        "sucuri": [
            ("x-sucuri-id", ""),
            ("server", "sucuri"),
        ],
        "f5_bigip": [
            ("server", "bigip"),
            ("x-wa-info", ""),
        ],
        "barracuda": [
            ("server", "barracuda"),
        ],
        "fortinet": [
            ("server", "fortiweb"),
        ],
        "modsecurity": [
            ("server", "mod_security"),
        ],
    }

    # Cloud provider signatures
    CLOUD_SIGNATURES: dict[str, list[tuple[str, str, str | None]]] = {
        "aws": [
            ("server", "amazons3", "S3"),
            ("server", "awselb", "ELB"),
            ("x-amz-cf-id", "", "CloudFront"),
            ("x-amz-request-id", "", "S3"),
            ("x-amz-bucket-region", "", "S3"),
        ],
        "azure": [
            ("server", "microsoft-azure", None),
            ("x-ms-request-id", "", None),
            ("x-azure-ref", "", None),
        ],
        "gcp": [
            ("server", "google frontend", None),
            ("x-goog-generation", "", "Cloud Storage"),
            ("x-guploader-uploadid", "", "Cloud Storage"),
        ],
        "cloudflare": [
            ("server", "cloudflare", "CDN"),
            ("cf-ray", "", "CDN"),
        ],
        "heroku": [
            ("via", "heroku", None),
            ("server", "heroku", None),
        ],
        "netlify": [
            ("server", "netlify", None),
            ("x-nf-request-id", "", None),
        ],
        "vercel": [
            ("server", "vercel", None),
            ("x-vercel-id", "", None),
        ],
        "digitalocean": [
            ("server", "digitalocean", "Spaces"),
        ],
    }

    # Cloud storage bucket naming patterns
    CLOUD_STORAGE_PATTERNS = {
        "aws_s3": [
            # Virtual-hosted style
            "{bucket}.s3.amazonaws.com",
            "{bucket}.s3-{region}.amazonaws.com",
            "{bucket}.s3.{region}.amazonaws.com",
            # Path style
            "s3.amazonaws.com/{bucket}",
            "s3-{region}.amazonaws.com/{bucket}",
        ],
        "azure_blob": [
            "{storage_account}.blob.core.windows.net",
            "{storage_account}.blob.core.windows.net/{container}",
        ],
        "gcp_storage": [
            "storage.googleapis.com/{bucket}",
            "{bucket}.storage.googleapis.com",
            "storage.cloud.google.com/{bucket}",
        ],
    }

    # Common bucket naming patterns to try (optimized for speed)
    BUCKET_NAME_PATTERNS = [
        "{domain_base}",
        "{domain_base}-assets",
        "{domain_base}-static",
        "{domain_base}-media",
        "{domain_base}-backup",
        "{domain_base}-backups",
        "{domain_base}-files",
        "{domain_base}-data",
        "{domain_base}-public",
        "{domain_base}-prod",
        "{domain_base}-dev",
        "{domain_base}-cdn",
        "{domain_base}-web",
        "{domain_base}-storage",
        "www-{domain_base}",
    ]

    # Sensitive file patterns to check in buckets (minimal for speed)
    SENSITIVE_BUCKET_FILES = [
        ".env",
        "config.json",
        "credentials.json",
        ".git/config",
        "backup.sql",
    ]

    # Spring Boot Actuator endpoints
    ACTUATOR_ENDPOINTS: list[tuple[str, str, Literal["critical", "high", "medium", "low", "info"]]] = [
        ("/actuator", "Actuator index", "medium"),
        ("/actuator/health", "Health endpoint", "info"),
        ("/actuator/info", "Application info", "low"),
        ("/actuator/env", "Environment variables", "critical"),
        ("/actuator/configprops", "Configuration properties", "critical"),
        ("/actuator/beans", "Spring beans", "high"),
        ("/actuator/mappings", "Request mappings", "high"),
        ("/actuator/heapdump", "Heap dump", "critical"),
        ("/actuator/threaddump", "Thread dump", "high"),
        ("/actuator/loggers", "Loggers (may allow modification)", "high"),
        ("/actuator/metrics", "Application metrics", "medium"),
        ("/actuator/scheduledtasks", "Scheduled tasks", "medium"),
        ("/actuator/httptrace", "HTTP trace", "high"),
        ("/actuator/caches", "Cache information", "medium"),
        ("/actuator/conditions", "Auto-config conditions", "medium"),
        ("/actuator/shutdown", "Shutdown endpoint", "critical"),
        ("/actuator/jolokia", "JMX over HTTP", "critical"),
        ("/actuator/prometheus", "Prometheus metrics", "low"),
        # Legacy endpoints (Spring Boot 1.x)
        ("/env", "Legacy environment", "critical"),
        ("/heapdump", "Legacy heap dump", "critical"),
        ("/trace", "Legacy HTTP trace", "high"),
        ("/dump", "Legacy thread dump", "high"),
        ("/beans", "Legacy beans", "high"),
        ("/autoconfig", "Legacy auto-config", "medium"),
        ("/configprops", "Legacy config properties", "critical"),
        ("/mappings", "Legacy mappings", "high"),
        # Management context
        ("/management/health", "Management health", "info"),
        ("/management/info", "Management info", "low"),
        ("/manage/health", "Manage health", "info"),
        ("/manage/env", "Manage environment", "critical"),
    ]

    # Source map patterns for JS files
    SOURCE_MAP_PATTERNS = [
        ".js.map",
        ".min.js.map",
        ".bundle.js.map",
        ".chunk.js.map",
    ]

    # Docker/Kubernetes exposure paths
    DOCKER_K8S_PATHS: list[tuple[str, str, Literal["critical", "high", "medium", "low", "info"]]] = [
        # Docker
        ("/v1.24/containers/json", "Docker API - containers list", "critical"),
        ("/v1.24/images/json", "Docker API - images list", "critical"),
        ("/v1.24/info", "Docker API - system info", "critical"),
        ("/v1.24/version", "Docker API - version", "high"),
        ("/_ping", "Docker API - ping", "medium"),
        # Kubernetes
        ("/api/v1/pods", "Kubernetes API - pods", "critical"),
        ("/api/v1/namespaces", "Kubernetes API - namespaces", "critical"),
        ("/api/v1/secrets", "Kubernetes API - secrets", "critical"),
        ("/api/v1/configmaps", "Kubernetes API - configmaps", "critical"),
        ("/apis", "Kubernetes API - API groups", "high"),
        ("/version", "Kubernetes API - version", "medium"),
        # Container registries
        ("/v2/_catalog", "Docker Registry - catalog", "critical"),
        ("/v2/", "Docker Registry - base", "high"),
    ]

    # Default credentials to test (username, password, service pattern)
    DEFAULT_CREDENTIALS: list[tuple[str, str, str, str]] = [
        # (path, username, password, service_name)
        ("/manager/html", "tomcat", "tomcat", "Apache Tomcat"),
        ("/manager/html", "admin", "admin", "Apache Tomcat"),
        ("/phpmyadmin/", "root", "", "phpMyAdmin"),
        ("/phpmyadmin/", "root", "root", "phpMyAdmin"),
        ("/admin/", "admin", "admin", "Admin Panel"),
        ("/administrator/", "admin", "admin", "Admin Panel"),
    ]

    # CMS-specific paths to check
    CMS_PATHS: list[tuple[str, str, str, Literal["critical", "high", "medium", "low", "info"]]] = [
        # WordPress
        ("/wp-json/wp/v2/users", "WordPress", "User enumeration via REST API", "high"),
        ("/wp-json/", "WordPress", "REST API exposed", "low"),
        ("/wp-content/debug.log", "WordPress", "Debug log exposed", "high"),
        ("/wp-config.php.bak", "WordPress", "Config backup file", "critical"),
        ("/wp-content/uploads/", "WordPress", "Uploads directory listing", "medium"),
        ("/wp-includes/version.php", "WordPress", "Version file exposed", "low"),
        ("/xmlrpc.php", "WordPress", "XML-RPC enabled (brute force risk)", "medium"),
        ("/wp-login.php", "WordPress", "Login page accessible", "info"),
        ("/?author=1", "WordPress", "Author enumeration", "low"),
        ("/wp-content/plugins/", "WordPress", "Plugins directory listing", "medium"),
        ("/readme.html", "WordPress", "Version disclosure", "low"),
        # Drupal
        ("/CHANGELOG.txt", "Drupal", "Version disclosure", "low"),
        ("/core/CHANGELOG.txt", "Drupal", "Drupal 8+ version disclosure", "low"),
        ("/user/register", "Drupal", "User registration enabled", "info"),
        ("/admin/config", "Drupal", "Admin config accessible", "medium"),
        ("/sites/default/files/", "Drupal", "Files directory listing", "medium"),
        ("/update.php", "Drupal", "Update script accessible", "high"),
        # Joomla
        ("/administrator/manifests/files/joomla.xml", "Joomla", "Version disclosure", "low"),
        ("/configuration.php.bak", "Joomla", "Config backup file", "critical"),
        ("/administrator/", "Joomla", "Admin panel accessible", "info"),
        ("/htaccess.txt", "Joomla", "Htaccess file exposed", "medium"),
        # Magento
        ("/magento_version", "Magento", "Version disclosure", "low"),
        ("/app/etc/local.xml", "Magento", "Config file exposed", "critical"),
        ("/downloader/", "Magento", "Magento Connect Manager", "high"),
        # Laravel
        ("/.env", "Laravel", "Environment file", "critical"),
        ("/storage/logs/laravel.log", "Laravel", "Debug logs exposed", "high"),
        ("/api/documentation", "Laravel", "API documentation exposed", "low"),
        # Django
        ("/admin/", "Django", "Django admin", "info"),
        ("/__debug__/", "Django", "Django Debug Toolbar", "high"),
        ("/static/admin/", "Django", "Static admin files", "low"),
        # Rails
        ("/rails/info/properties", "Rails", "Rails info page", "high"),
        ("/rails/info", "Rails", "Rails info", "medium"),
        # Symfony
        ("/_profiler/", "Symfony", "Profiler exposed", "high"),
        ("/app_dev.php", "Symfony", "Dev environment", "critical"),
        # Node.js/Express
        ("/.npmrc", "Node.js", "NPM config exposed", "high"),
        ("/npm-debug.log", "Node.js", "NPM debug log", "medium"),
        # ASP.NET
        ("/trace.axd", "ASP.NET", "Trace handler exposed", "high"),
        ("/elmah.axd", "ASP.NET", "Error log handler", "high"),
        # Generic CMS
        ("/cms/", "Generic CMS", "CMS root accessible", "info"),
        ("/backend/", "Generic CMS", "Backend accessible", "info"),
    ]

    def __init__(self) -> None:
        self.logger = get_logger("security_scanner")

    async def scan(
        self,
        target: str,
        check_exposed_files: bool = True,
        check_cors: bool = True,
        check_redirects: bool = True,
        check_methods: bool = True,
        check_waf: bool = True,
        check_cloud: bool = True,
        check_cloud_storage: bool = True,
        check_actuators: bool = True,
        check_source_maps: bool = True,
        check_docker_k8s: bool = True,
        check_host_header: bool = True,
        check_cms: bool = True,
    ) -> SecurityScanResult:
        """Run comprehensive security scan on target."""
        start_time = time.time()
        settings = get_settings()

        # Normalize target URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info("security_scan_started", target=target)

        result = SecurityScanResult(target=target)

        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=False,
            verify=True,
        ) as client:
            tasks = []

            if check_exposed_files:
                tasks.append(self._check_exposed_files(client, target))
            if check_cors:
                tasks.append(self._check_cors(client, target))
            if check_redirects:
                tasks.append(self._check_open_redirects(client, target))
            if check_methods:
                tasks.append(self._check_http_methods(client, target))
            if check_waf:
                tasks.append(self._detect_waf(client, target))
            if check_cloud:
                tasks.append(self._detect_cloud_provider(client, target))
            if check_cloud_storage:
                tasks.append(self._check_cloud_storage(client, target))
            if check_actuators:
                tasks.append(self._check_actuator_endpoints(client, target))
            if check_source_maps:
                tasks.append(self._check_source_maps(client, target))
            if check_docker_k8s:
                tasks.append(self._check_docker_k8s(client, target))
            if check_host_header:
                tasks.append(self._check_host_header_injection(client, target))
            if check_cms:
                tasks.append(self._check_cms_paths(client, target))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            idx = 0
            if check_exposed_files:
                if isinstance(results[idx], list):
                    result.exposed_files = results[idx]
                idx += 1
            if check_cors:
                if isinstance(results[idx], list):
                    result.cors_misconfigurations = results[idx]
                idx += 1
            if check_redirects:
                if isinstance(results[idx], list):
                    result.open_redirects = results[idx]
                idx += 1
            if check_methods:
                if isinstance(results[idx], list):
                    result.http_method_findings = results[idx]
                idx += 1
            if check_waf:
                if isinstance(results[idx], WAFDetection):
                    result.waf = results[idx]
                idx += 1
            if check_cloud:
                if isinstance(results[idx], list):
                    result.cloud_providers = results[idx]
                idx += 1
            if check_cloud_storage:
                if isinstance(results[idx], list):
                    result.cloud_storage_findings = results[idx]
                idx += 1
            if check_actuators:
                if isinstance(results[idx], list):
                    result.actuator_findings = results[idx]
                idx += 1
            if check_source_maps:
                if isinstance(results[idx], list):
                    result.source_map_findings = results[idx]
                idx += 1
            if check_docker_k8s:
                if isinstance(results[idx], list):
                    result.docker_k8s_findings = results[idx]
                idx += 1
            if check_host_header:
                if isinstance(results[idx], list):
                    result.host_header_findings = results[idx]
                idx += 1
            if check_cms:
                if isinstance(results[idx], list):
                    result.cms_findings = results[idx]

        result.calculate_counts()
        result.scanned_at = datetime.utcnow()

        duration = time.time() - start_time
        self.logger.info(
            "security_scan_completed",
            target=target,
            total_findings=result.total_findings,
            critical=result.critical_count,
            high=result.high_count,
            duration=duration,
        )

        return result

    async def _check_exposed_files(
        self, client: httpx.AsyncClient, target: str
    ) -> list[ExposedFile]:
        """Check for exposed sensitive files and directories."""
        findings: list[ExposedFile] = []

        # Create tasks for concurrent checking
        async def check_path(
            path: str, description: str, file_type: str, severity: str
        ) -> ExposedFile | None:
            url = urljoin(target, path)
            try:
                response = await client.get(url, follow_redirects=False)

                # Check for successful response
                if response.status_code in (200, 403):
                    content_length = len(response.content) if response.content else 0

                    # Skip empty responses
                    if content_length == 0:
                        return None

                    # For 200, get content snippet
                    content_snippet = None
                    if response.status_code == 200 and response.content:
                        # Get first 100 bytes as snippet
                        try:
                            snippet = response.content[:100].decode("utf-8", errors="ignore")
                            # Redact potential secrets
                            content_snippet = re.sub(
                                r'(password|secret|key|token|api[_-]?key)\s*[=:]\s*["\']?[^\s"\']+',
                                r"\1=[REDACTED]",
                                snippet,
                                flags=re.IGNORECASE,
                            )
                        except Exception:
                            content_snippet = "[binary content]"

                    # Validate it's not a custom 404 page
                    if self._is_likely_valid(response, path, file_type):
                        # Adjust severity for 403 responses (file exists but not accessible)
                        # 403 is less severe than 200 since content is not exposed
                        adjusted_severity = severity
                        if response.status_code == 403:
                            severity_downgrade = {
                                "critical": "high",
                                "high": "medium",
                                "medium": "low",
                                "low": "info",
                                "info": "info",
                            }
                            adjusted_severity = severity_downgrade.get(severity, severity)
                            description_suffix = f"{description} found at {path} (403 Forbidden - file exists but not accessible)"
                        else:
                            description_suffix = f"{description} exposed at {path}"

                        return ExposedFile(
                            path=path,
                            file_type=file_type,
                            url=url,
                            status_code=response.status_code,
                            content_length=content_length,
                            content_snippet=content_snippet,
                            severity=adjusted_severity,
                            description=description_suffix,
                        )
            except Exception as e:
                self.logger.debug("exposed_file_check_failed", path=path, error=str(e))

            return None

        # Run checks concurrently with semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)

        async def limited_check(args: tuple) -> ExposedFile | None:
            async with semaphore:
                return await check_path(*args)

        tasks = [limited_check(path_info) for path_info in self.EXPOSED_PATHS]
        results = await asyncio.gather(*tasks)

        findings = [r for r in results if r is not None]
        return findings

    def _is_likely_valid(
        self, response: httpx.Response, path: str, file_type: str
    ) -> bool:
        """Check if response is likely a valid file, not a custom 404."""
        content_type = response.headers.get("content-type", "").lower()
        content = response.text.lower() if response.content else ""

        # Git files should contain specific content
        if file_type == "git":
            if path == "/.git/HEAD":
                return "ref:" in content or content.startswith("ref:")
            if path == "/.git/config":
                return "[core]" in content or "[remote" in content

        # SVN files
        if file_type == "svn":
            if ".svn/entries" in path:
                return response.status_code == 200
            if ".svn/wc.db" in path:
                return "SQLite" in content or response.content[:16] == b"SQLite format 3\x00"

        # Environment files
        if file_type == "env":
            # Should contain key=value patterns
            if re.search(r"^[A-Z_]+=", content, re.MULTILINE):
                return True

        # Config files
        if file_type == "config":
            # Check for common config patterns
            if any(kw in content for kw in ["password", "secret", "key", "database", "host"]):
                return True

        # SQL files
        if file_type == "database":
            if any(kw in content for kw in ["create table", "insert into", "drop table"]):
                return True

        # Check Content-Type for some file types
        if path.endswith(".json") and "application/json" in content_type:
            return True
        if path.endswith((".yml", ".yaml")) and ("yaml" in content_type or "text/plain" in content_type):
            return True

        # For 403 responses, if the path exists but is forbidden, it's notable
        if response.status_code == 403:
            return True

        # Generic check: if response doesn't look like HTML error page
        if response.status_code == 200:
            # Likely false positive if it's an HTML page with "404" or "not found"
            if "text/html" in content_type:
                if "404" in content or "not found" in content:
                    return False
            return True

        return False

    async def _check_cors(
        self, client: httpx.AsyncClient, target: str
    ) -> list[CORSMisconfiguration]:
        """Check for CORS misconfigurations."""
        findings: list[CORSMisconfiguration] = []

        test_origins = [
            ("https://evil.com", "origin_reflection"),
            ("null", "null_origin_allowed"),
            (f"{urlparse(target).scheme}://attacker.{urlparse(target).netloc}", "origin_reflection"),
        ]

        for test_origin, issue_type in test_origins:
            try:
                headers = {"Origin": test_origin}
                response = await client.get(target, headers=headers)

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                # Check for wildcard
                if acao == "*":
                    if acac.lower() == "true":
                        findings.append(CORSMisconfiguration(
                            url=target,
                            issue_type="credentials_with_wildcard",
                            tested_origin=test_origin,
                            response_headers={
                                "access-control-allow-origin": acao,
                                "access-control-allow-credentials": acac,
                            },
                            severity="critical",
                            description="CORS allows credentials with wildcard origin",
                            exploitable=True,
                        ))
                    else:
                        findings.append(CORSMisconfiguration(
                            url=target,
                            issue_type="wildcard_origin",
                            tested_origin=test_origin,
                            response_headers={"access-control-allow-origin": acao},
                            severity="medium",
                            description="CORS allows any origin (wildcard)",
                            exploitable=False,
                        ))

                # Check for origin reflection
                elif acao == test_origin:
                    severity = "high" if acac.lower() == "true" else "medium"
                    findings.append(CORSMisconfiguration(
                        url=target,
                        issue_type=issue_type,
                        tested_origin=test_origin,
                        response_headers={
                            "access-control-allow-origin": acao,
                            "access-control-allow-credentials": acac,
                        },
                        severity=severity,
                        description=f"CORS reflects origin: {test_origin}",
                        exploitable=acac.lower() == "true",
                    ))

                # Check for null origin
                elif test_origin == "null" and acao == "null":
                    findings.append(CORSMisconfiguration(
                        url=target,
                        issue_type="null_origin_allowed",
                        tested_origin="null",
                        response_headers={"access-control-allow-origin": acao},
                        severity="high",
                        description="CORS allows null origin (exploitable via sandboxed iframe)",
                        exploitable=True,
                    ))

            except Exception as e:
                self.logger.debug("cors_check_failed", origin=test_origin, error=str(e))

        return findings

    async def _check_open_redirects(
        self, client: httpx.AsyncClient, target: str
    ) -> list[OpenRedirect]:
        """Check for open redirect vulnerabilities."""
        findings: list[OpenRedirect] = []

        payload = "https://evil.com"
        parsed = urlparse(target)

        for param in self.REDIRECT_PARAMS:
            test_url = f"{target}?{param}={payload}"

            try:
                response = await client.get(test_url, follow_redirects=False)

                # Check for redirect
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")

                    if "evil.com" in location.lower():
                        findings.append(OpenRedirect(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            redirect_url=location,
                            severity="high",
                            description=f"Open redirect via {param} parameter",
                        ))

                # Also check for meta refresh or JavaScript redirects
                if response.status_code == 200 and response.content:
                    content = response.text.lower()
                    if f'content="0;url={payload.lower()}' in content:
                        findings.append(OpenRedirect(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            redirect_url=payload,
                            severity="medium",
                            description=f"Open redirect via meta refresh in {param}",
                        ))
                    if f'window.location="{payload.lower()}' in content or \
                       f"window.location='{payload.lower()}'" in content:
                        findings.append(OpenRedirect(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            redirect_url=payload,
                            severity="medium",
                            description=f"Open redirect via JavaScript in {param}",
                        ))

            except Exception as e:
                self.logger.debug("redirect_check_failed", param=param, error=str(e))

        return findings

    async def _check_http_methods(
        self, client: httpx.AsyncClient, target: str
    ) -> list[HTTPMethodFinding]:
        """Check for dangerous HTTP methods."""
        findings: list[HTTPMethodFinding] = []

        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        all_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"]

        allowed_methods: list[str] = []
        found_dangerous: list[str] = []
        # Track methods by response: 2xx = fully allowed, 403 = forbidden but recognized
        fully_allowed_dangerous: list[str] = []
        forbidden_dangerous: list[str] = []

        # Try OPTIONS first to get allowed methods
        try:
            response = await client.options(target)
            allow_header = response.headers.get("allow", "")
            if allow_header:
                allowed_methods = [m.strip().upper() for m in allow_header.split(",")]
                found_dangerous = [m for m in allowed_methods if m in dangerous_methods]
        except Exception:
            pass

        # If OPTIONS didn't work, probe each method
        if not allowed_methods:
            for method in all_methods:
                try:
                    response = await client.request(method, target)
                    if response.status_code != 405:  # Method Not Allowed
                        allowed_methods.append(method)
                        if method in dangerous_methods:
                            found_dangerous.append(method)
                            # Distinguish between 2xx (fully allowed) and 403 (forbidden)
                            if 200 <= response.status_code < 300:
                                fully_allowed_dangerous.append(method)
                            elif response.status_code == 403:
                                forbidden_dangerous.append(method)
                except Exception:
                    pass

        if found_dangerous:
            # Determine severity based on what's actually allowed vs forbidden
            # HIGH: Methods that return 2xx (especially TRACE, PUT, DELETE)
            # MEDIUM: Methods that return 403 (exist but access denied)
            if fully_allowed_dangerous:
                if any(m in fully_allowed_dangerous for m in ["TRACE", "PUT", "DELETE"]):
                    severity: Literal["high", "medium", "low", "info"] = "high"
                else:
                    severity = "medium"
            else:
                # All dangerous methods returned 403 - lower severity
                severity = "low"

            # Build detailed description
            descriptions = []

            # Report fully allowed dangerous methods (2xx responses) - more severe
            if "TRACE" in fully_allowed_dangerous:
                descriptions.append("TRACE method enabled (Cross-Site Tracing/XST vulnerability)")
            if "PUT" in fully_allowed_dangerous:
                descriptions.append("PUT method enabled (allows file upload)")
            if "DELETE" in fully_allowed_dangerous:
                descriptions.append("DELETE method enabled (allows file deletion)")
            if "CONNECT" in fully_allowed_dangerous:
                descriptions.append("CONNECT method enabled (proxy tunneling)")
            if "PATCH" in fully_allowed_dangerous:
                descriptions.append("PATCH method enabled (allows resource modification)")

            # Report forbidden dangerous methods (403 responses) - less severe but notable
            if forbidden_dangerous:
                forbidden_note = f"Methods recognized but forbidden (403): {', '.join(forbidden_dangerous)}"
                descriptions.append(forbidden_note)

            description = "; ".join(descriptions) if descriptions else f"Dangerous HTTP methods enabled: {', '.join(found_dangerous)}"

            findings.append(HTTPMethodFinding(
                url=target,
                allowed_methods=allowed_methods,
                dangerous_methods=found_dangerous,
                severity=severity,
                description=description,
            ))
        elif allowed_methods:
            findings.append(HTTPMethodFinding(
                url=target,
                allowed_methods=allowed_methods,
                dangerous_methods=[],
                severity="info",
                description=f"Allowed HTTP methods: {', '.join(allowed_methods)}",
            ))

        return findings

    async def _detect_waf(
        self, client: httpx.AsyncClient, target: str
    ) -> WAFDetection:
        """Detect Web Application Firewall presence."""
        result = WAFDetection(detected=False)

        try:
            # Normal request
            response = await client.get(target)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            # Check WAF signatures
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                for header_name, header_value in signatures:
                    if header_name in headers:
                        header_val = headers[header_name]
                        if not header_value or header_value in header_val:
                            result.detected = True
                            result.waf_name = waf_name.replace("_", " ").title()
                            result.confidence = "high"
                            result.detection_method = f"Header: {header_name}"
                            result.headers_found[header_name] = headers[header_name]
                            break
                if result.detected:
                    break

            # If not detected, try triggering WAF with malicious payload
            if not result.detected:
                malicious_payloads = [
                    "?id=1' OR '1'='1",  # SQL injection
                    "?q=<script>alert(1)</script>",  # XSS
                    "/../../../etc/passwd",  # Path traversal
                ]

                for payload in malicious_payloads:
                    try:
                        test_url = target.rstrip("/") + payload
                        response = await client.get(test_url)

                        # Check for WAF block response
                        if response.status_code in (403, 406, 429, 503):
                            content = response.text.lower()

                            waf_indicators = [
                                ("cloudflare", "cloudflare"),
                                ("akamai", "akamai"),
                                ("imperva", "incapsula"),
                                ("sucuri", "sucuri"),
                                ("modsecurity", "mod_security"),
                                ("aws waf", "aws"),
                                ("f5 bigip", "bigip"),
                            ]

                            for waf_name, indicator in waf_indicators:
                                if indicator in content:
                                    result.detected = True
                                    result.waf_name = waf_name.title()
                                    result.confidence = "medium"
                                    result.detection_method = "Block page content"
                                    result.notes = f"Detected via {response.status_code} response to malicious payload"
                                    break

                            if not result.detected and response.status_code == 403:
                                result.detected = True
                                result.waf_name = "Unknown"
                                result.confidence = "low"
                                result.detection_method = "403 response to malicious payload"

                            if result.detected:
                                break

                    except Exception:
                        pass

        except Exception as e:
            self.logger.debug("waf_detection_failed", error=str(e))

        return result

    async def _detect_cloud_provider(
        self, client: httpx.AsyncClient, target: str
    ) -> list[CloudProvider]:
        """Detect cloud provider from response headers."""
        providers: list[CloudProvider] = []
        seen_providers: set[str] = set()

        try:
            response = await client.get(target)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            for provider_name, signatures in self.CLOUD_SIGNATURES.items():
                for header_name, header_value, service in signatures:
                    if header_name in headers:
                        header_val = headers[header_name]
                        if not header_value or header_value in header_val:
                            if provider_name not in seen_providers:
                                seen_providers.add(provider_name)

                                # Map to provider literal type
                                provider_map = {
                                    "aws": "aws",
                                    "azure": "azure",
                                    "gcp": "gcp",
                                    "cloudflare": "cloudflare",
                                    "heroku": "heroku",
                                    "netlify": "netlify",
                                    "vercel": "vercel",
                                    "digitalocean": "digitalocean",
                                }
                                provider_type = provider_map.get(provider_name, "other")

                                providers.append(CloudProvider(
                                    provider=provider_type,
                                    confidence="high" if header_value else "medium",
                                    service=service,
                                    detection_method=f"Header: {header_name}",
                                ))
                            break

        except Exception as e:
            self.logger.debug("cloud_detection_failed", error=str(e))

        return providers

    async def _check_cloud_storage(
        self, client: httpx.AsyncClient, target: str
    ) -> list[CloudStorageFinding]:
        """Check for exposed cloud storage buckets (S3, Azure Blob, GCS)."""
        findings: list[CloudStorageFinding] = []
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path

        # Extract domain base name (remove TLD and www)
        domain_parts = domain.replace("www.", "").split(".")
        domain_base = domain_parts[0] if domain_parts else domain

        # Generate bucket names to test
        bucket_names = set()
        for pattern in self.BUCKET_NAME_PATTERNS:
            bucket_name = pattern.format(
                domain=domain.replace(".", "-"),
                domain_base=domain_base,
            )
            bucket_names.add(bucket_name.lower())

        # AWS S3 regions to check
        s3_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]

        # Semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)

        async def check_s3_bucket(bucket_name: str) -> CloudStorageFinding | None:
            """Check if S3 bucket exists and is publicly accessible."""
            async with semaphore:
                # Try virtual-hosted style first (most common)
                url = f"https://{bucket_name}.s3.amazonaws.com"
                try:
                    response = await client.get(url, timeout=5.0)

                    if response.status_code == 200:
                        # Bucket listing is public
                        return CloudStorageFinding(
                            provider="aws_s3",
                            bucket_name=bucket_name,
                            url=url,
                            is_public=True,
                            allows_listing=True,
                            severity="critical",
                            description=f"S3 bucket '{bucket_name}' allows public listing",
                            container_type="bucket",
                        )
                    elif response.status_code == 403:
                        # Bucket exists but listing denied - just note its existence (faster)
                        content = response.text.lower()
                        if "accessdenied" in content:
                            return CloudStorageFinding(
                                provider="aws_s3",
                                bucket_name=bucket_name,
                                url=url,
                                is_public=False,
                                allows_listing=False,
                                severity="info",
                                description=f"S3 bucket '{bucket_name}' exists (access denied)",
                                container_type="bucket",
                            )
                except Exception:
                    pass
                return None

        async def check_azure_blob(storage_account: str) -> CloudStorageFinding | None:
            """Check if Azure Blob storage is publicly accessible."""
            async with semaphore:
                url = f"https://{storage_account}.blob.core.windows.net"
                try:
                    # Try to list containers
                    list_url = f"{url}?comp=list"
                    response = await client.get(list_url, timeout=5.0)

                    if response.status_code == 200:
                        return CloudStorageFinding(
                            provider="azure_blob",
                            bucket_name=storage_account,
                            url=url,
                            is_public=True,
                            allows_listing=True,
                            severity="critical",
                            description=f"Azure storage account '{storage_account}' allows public container listing",
                            container_type="storage_account",
                        )
                    elif response.status_code in (403, 404):
                        # Check a few common container names (optimized for speed)
                        common_containers = ["$web", "public", "assets"]
                        for container in common_containers:
                            container_url = f"{url}/{container}?restype=container&comp=list"
                            try:
                                container_resp = await client.get(container_url, timeout=3.0)
                                if container_resp.status_code == 200:
                                    return CloudStorageFinding(
                                        provider="azure_blob",
                                        bucket_name=f"{storage_account}/{container}",
                                        url=f"{url}/{container}",
                                        is_public=True,
                                        allows_listing=True,
                                        severity="high",
                                        description=f"Azure container '{storage_account}/{container}' allows public listing",
                                        container_type="blob_container",
                                    )
                            except Exception:
                                pass
                except Exception:
                    pass
                return None

        async def check_gcs_bucket(bucket_name: str) -> CloudStorageFinding | None:
            """Check if Google Cloud Storage bucket is publicly accessible."""
            async with semaphore:
                # Try Google Cloud Storage URL
                url = f"https://storage.googleapis.com/{bucket_name}"
                try:
                    response = await client.get(url, timeout=5.0)

                    if response.status_code == 200:
                        return CloudStorageFinding(
                            provider="gcp_storage",
                            bucket_name=bucket_name,
                            url=url,
                            is_public=True,
                            allows_listing=True,
                            severity="critical",
                            description=f"GCS bucket '{bucket_name}' allows public listing",
                            container_type="bucket",
                        )
                    elif response.status_code == 403:
                        # Bucket exists but access denied - just note its existence (faster)
                        return CloudStorageFinding(
                            provider="gcp_storage",
                            bucket_name=bucket_name,
                            url=url,
                            is_public=False,
                            allows_listing=False,
                            severity="info",
                            description=f"GCS bucket '{bucket_name}' exists (access denied)",
                            container_type="bucket",
                        )
                except Exception:
                    pass
                return None

        # Run all checks concurrently
        tasks = []

        # S3 bucket checks
        for bucket_name in bucket_names:
            tasks.append(check_s3_bucket(bucket_name))

        # Azure Blob checks (using bucket_names as storage account names)
        for storage_account in list(bucket_names)[:5]:  # Limit Azure checks for speed
            tasks.append(check_azure_blob(storage_account))

        # GCS bucket checks (limit for speed)
        for bucket_name in list(bucket_names)[:10]:
            tasks.append(check_gcs_bucket(bucket_name))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, CloudStorageFinding):
                findings.append(result)

        # Log summary
        if findings:
            self.logger.info(
                "cloud_storage_scan_completed",
                target=target,
                findings_count=len(findings),
                critical=[f.bucket_name for f in findings if f.severity == "critical"],
            )

        return findings

    async def _check_bucket_sensitive_files(
        self, client: httpx.AsyncClient, bucket_url: str, semaphore: asyncio.Semaphore
    ) -> list[str]:
        """Check for sensitive files in a bucket."""
        found_files: list[str] = []

        async def check_file(file_path: str) -> str | None:
            async with semaphore:
                url = f"{bucket_url.rstrip('/')}/{file_path}"
                try:
                    response = await client.head(url, timeout=3.0)
                    if response.status_code == 200:
                        return file_path
                except Exception:
                    pass
                return None

        tasks = [check_file(f) for f in self.SENSITIVE_BUCKET_FILES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                found_files.append(result)

        return found_files

    async def _check_actuator_endpoints(
        self, client: httpx.AsyncClient, target: str
    ) -> list[ActuatorFinding]:
        """Check for exposed Spring Boot Actuator endpoints."""
        findings: list[ActuatorFinding] = []
        semaphore = asyncio.Semaphore(10)

        async def check_endpoint(
            path: str, description: str, severity: str
        ) -> ActuatorFinding | None:
            async with semaphore:
                url = urljoin(target, path)
                try:
                    response = await client.get(url, timeout=5.0, follow_redirects=False)

                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")

                        # Validate it's actually an actuator endpoint (JSON response)
                        is_actuator = False
                        response_preview = None

                        if "application/json" in content_type or "application/vnd.spring-boot.actuator" in content_type:
                            is_actuator = True
                            try:
                                response_preview = response.text[:200] if response.text else None
                            except Exception:
                                response_preview = "[binary content]"
                        elif response.content:
                            # Check if content looks like JSON
                            content = response.text[:500] if response.text else ""
                            if content.strip().startswith(("{", "[")):
                                is_actuator = True
                                response_preview = content[:200]

                        if is_actuator:
                            # Determine framework type
                            framework: Literal["spring_boot", "spring_boot_legacy", "management"] = "spring_boot"
                            if path.startswith("/management") or path.startswith("/manage"):
                                framework = "management"
                            elif not path.startswith("/actuator"):
                                framework = "spring_boot_legacy"

                            return ActuatorFinding(
                                endpoint=path,
                                url=url,
                                status_code=response.status_code,
                                is_accessible=True,
                                framework=framework,
                                content_type=content_type,
                                response_preview=response_preview,
                                severity=severity,
                                description=f"{description} exposed at {path}",
                            )

                except Exception as e:
                    self.logger.debug("actuator_check_failed", path=path, error=str(e))

            return None

        tasks = [
            check_endpoint(path, desc, sev)
            for path, desc, sev in self.ACTUATOR_ENDPOINTS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ActuatorFinding):
                findings.append(result)

        if findings:
            self.logger.info(
                "actuator_scan_completed",
                target=target,
                findings_count=len(findings),
                critical=[f.endpoint for f in findings if f.severity == "critical"],
            )

        return findings

    async def _check_source_maps(
        self, client: httpx.AsyncClient, target: str
    ) -> list[SourceMapFinding]:
        """Check for exposed JavaScript source maps."""
        findings: list[SourceMapFinding] = []
        semaphore = asyncio.Semaphore(5)

        # First, get the main page to find JS files
        js_files: set[str] = set()
        try:
            response = await client.get(target, timeout=10.0)
            if response.status_code == 200:
                # Extract JS file references from HTML
                content = response.text
                # Find script src attributes
                import re
                script_pattern = r'<script[^>]+src=["\']([^"\']+\.js)["\']'
                for match in re.finditer(script_pattern, content, re.IGNORECASE):
                    js_url = match.group(1)
                    if not js_url.startswith(("http://", "https://", "//")):
                        js_url = urljoin(target, js_url)
                    elif js_url.startswith("//"):
                        js_url = "https:" + js_url
                    js_files.add(js_url)

        except Exception as e:
            self.logger.debug("source_map_js_discovery_failed", error=str(e))

        # Also check common JS file paths
        common_js_paths = [
            "/main.js", "/app.js", "/bundle.js", "/vendor.js",
            "/static/js/main.js", "/static/js/bundle.js",
            "/assets/js/app.js", "/dist/bundle.js",
            "/js/app.js", "/js/main.js",
        ]

        for path in common_js_paths:
            js_files.add(urljoin(target, path))

        async def check_source_map(js_url: str) -> SourceMapFinding | None:
            async with semaphore:
                # Try .map extension
                map_url = js_url + ".map"
                try:
                    response = await client.head(map_url, timeout=5.0)

                    if response.status_code == 200:
                        content_length = int(response.headers.get("content-length", 0))

                        # Optionally fetch a bit of the content to verify it's a source map
                        sources_exposed = []
                        try:
                            map_response = await client.get(map_url, timeout=5.0)
                            if map_response.status_code == 200:
                                map_content = map_response.text[:5000]
                                if '"sources"' in map_content or '"mappings"' in map_content:
                                    # Extract source file names if possible
                                    import json
                                    try:
                                        map_data = json.loads(map_response.text)
                                        sources = map_data.get("sources", [])
                                        sources_exposed = [s for s in sources[:10] if isinstance(s, str)]
                                    except json.JSONDecodeError:
                                        pass
                                else:
                                    return None  # Not actually a source map
                        except Exception:
                            pass

                        return SourceMapFinding(
                            js_file=js_url,
                            source_map_url=map_url,
                            is_accessible=True,
                            file_size=content_length,
                            sources_exposed=sources_exposed,
                            severity="high" if sources_exposed else "medium",
                            description=f"Source map exposed for {js_url.split('/')[-1]}",
                        )

                except Exception as e:
                    self.logger.debug("source_map_check_failed", url=map_url, error=str(e))

            return None

        tasks = [check_source_map(js_url) for js_url in list(js_files)[:20]]  # Limit checks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, SourceMapFinding):
                findings.append(result)

        if findings:
            self.logger.info(
                "source_map_scan_completed",
                target=target,
                findings_count=len(findings),
            )

        return findings

    async def _check_docker_k8s(
        self, client: httpx.AsyncClient, target: str
    ) -> list[DockerK8sFinding]:
        """Check for exposed Docker/Kubernetes APIs."""
        findings: list[DockerK8sFinding] = []
        semaphore = asyncio.Semaphore(10)

        # Common ports for Docker/K8s APIs
        parsed = urlparse(target)
        base_host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]

        # URLs to check (original target + common API ports)
        check_urls = [target]
        for port in [2375, 2376, 6443, 8443, 5000]:  # Docker, K8s, Registry ports
            check_urls.append(f"https://{base_host}:{port}")
            check_urls.append(f"http://{base_host}:{port}")

        async def check_path(
            base_url: str, path: str, description: str, severity: str
        ) -> DockerK8sFinding | None:
            async with semaphore:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    response = await client.get(url, timeout=3.0, follow_redirects=False)

                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")

                        # Validate it looks like API response
                        is_api_response = False
                        response_preview = None

                        if "application/json" in content_type:
                            is_api_response = True
                            try:
                                response_preview = response.text[:200] if response.text else None
                            except Exception:
                                response_preview = "[binary content]"

                        if is_api_response:
                            # Determine service type
                            service_type: Literal["docker_api", "kubernetes_api", "docker_registry"] = "docker_api"
                            if "/api/v1" in path or "/apis" in path:
                                service_type = "kubernetes_api"
                            elif "/v2" in path:
                                service_type = "docker_registry"

                            return DockerK8sFinding(
                                path=path,
                                url=url,
                                service_type=service_type,
                                is_accessible=True,
                                requires_auth=False,
                                response_preview=response_preview,
                                severity=severity,
                                description=f"{description} accessible at {url}",
                            )

                    elif response.status_code == 401:
                        # API exists but requires auth
                        service_type = "docker_api"
                        if "/api/v1" in path or "/apis" in path:
                            service_type = "kubernetes_api"
                        elif "/v2" in path:
                            service_type = "docker_registry"

                        return DockerK8sFinding(
                            path=path,
                            url=url,
                            service_type=service_type,
                            is_accessible=False,
                            requires_auth=True,
                            severity="info",
                            description=f"{description} found but requires authentication",
                        )

                except Exception:
                    pass

            return None

        # Only check the main target URL for these paths (not all ports to save time)
        tasks = [
            check_path(target, path, desc, sev)
            for path, desc, sev in self.DOCKER_K8S_PATHS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DockerK8sFinding):
                findings.append(result)

        if findings:
            self.logger.info(
                "docker_k8s_scan_completed",
                target=target,
                findings_count=len(findings),
                critical=[f.path for f in findings if f.severity == "critical"],
            )

        return findings

    async def _check_host_header_injection(
        self, client: httpx.AsyncClient, target: str
    ) -> list[HostHeaderInjectionFinding]:
        """Check for Host Header Injection vulnerabilities."""
        findings: list[HostHeaderInjectionFinding] = []
        parsed = urlparse(target)
        original_host = parsed.netloc

        # Test payloads for Host header injection
        test_payloads = [
            ("evil.com", "basic"),
            (f"evil.com:{parsed.port or 443}", "with_port"),
            (f"{original_host}.evil.com", "subdomain_prefix"),
            (f"evil.com/{original_host}", "path_injection"),
            (f"{original_host}@evil.com", "at_sign"),
            (f"{original_host}%0d%0aX-Injected: header", "crlf"),
        ]

        # Also test X-Forwarded-Host and X-Host headers
        forwarded_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "X-Original-Host",
        ]

        async def check_host_injection(
            injected_host: str, payload_type: str
        ) -> HostHeaderInjectionFinding | None:
            try:
                # Send request with modified Host header
                headers = {"Host": injected_host}
                response = await client.get(target, headers=headers, timeout=5.0, follow_redirects=False)

                # Check for reflection in response body
                if response.content:
                    content = response.text.lower()
                    if "evil.com" in content:
                        return HostHeaderInjectionFinding(
                            url=target,
                            injection_type="reflection_in_body",
                            injected_host=injected_host,
                            evidence=f"Injected host reflected in response body",
                            response_location="body",
                            severity="high",
                            description=f"Host header injection: {payload_type} payload reflected in response body",
                        )

                # Check for reflection in headers (e.g., Location header for redirects)
                for header_name, header_value in response.headers.items():
                    if "evil.com" in header_value.lower():
                        # Critical if it's in Location header (redirect poisoning)
                        severity: Literal["critical", "high", "medium", "low"] = "high"
                        injection_type: Literal["reflection_in_body", "reflection_in_headers", "cache_poisoning", "password_reset_poisoning", "redirect"] = "reflection_in_headers"

                        if header_name.lower() == "location":
                            severity = "critical"
                            injection_type = "redirect"

                        return HostHeaderInjectionFinding(
                            url=target,
                            injection_type=injection_type,
                            injected_host=injected_host,
                            evidence=f"Reflected in {header_name}: {header_value[:100]}",
                            response_location=header_name,
                            severity=severity,
                            description=f"Host header injection: {payload_type} payload reflected in {header_name} header",
                        )

            except Exception as e:
                self.logger.debug("host_header_check_failed", error=str(e))

            return None

        async def check_forwarded_header(
            header_name: str
        ) -> HostHeaderInjectionFinding | None:
            try:
                headers = {header_name: "evil.com"}
                response = await client.get(target, headers=headers, timeout=5.0, follow_redirects=False)

                # Check for reflection
                if response.content and "evil.com" in response.text.lower():
                    return HostHeaderInjectionFinding(
                        url=target,
                        injection_type="reflection_in_body",
                        injected_host=f"{header_name}: evil.com",
                        evidence=f"{header_name} header value reflected in response",
                        response_location="body",
                        severity="high",
                        description=f"{header_name} injection reflected in response body",
                    )

                for resp_header, value in response.headers.items():
                    if "evil.com" in value.lower():
                        return HostHeaderInjectionFinding(
                            url=target,
                            injection_type="reflection_in_headers",
                            injected_host=f"{header_name}: evil.com",
                            evidence=f"Reflected in {resp_header}",
                            response_location=resp_header,
                            severity="high" if resp_header.lower() == "location" else "medium",
                            description=f"{header_name} injection reflected in {resp_header}",
                        )

            except Exception:
                pass

            return None

        # Run all checks
        tasks = []

        for injected_host, payload_type in test_payloads:
            tasks.append(check_host_injection(injected_host, payload_type))

        for header_name in forwarded_headers:
            tasks.append(check_forwarded_header(header_name))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, HostHeaderInjectionFinding):
                findings.append(result)

        # Deduplicate findings based on injection_type
        seen_types: set[str] = set()
        unique_findings: list[HostHeaderInjectionFinding] = []
        for finding in findings:
            key = f"{finding.injection_type}:{finding.response_location}"
            if key not in seen_types:
                seen_types.add(key)
                unique_findings.append(finding)

        if unique_findings:
            self.logger.info(
                "host_header_injection_scan_completed",
                target=target,
                findings_count=len(unique_findings),
            )

        return unique_findings

    async def _check_cms_paths(
        self, client: httpx.AsyncClient, target: str
    ) -> list[CMSFinding]:
        """Check for CMS-specific paths and potential vulnerabilities."""
        findings: list[CMSFinding] = []
        semaphore = asyncio.Semaphore(10)

        async def check_cms_path(
            path: str, cms_type: str, description: str, severity: str
        ) -> CMSFinding | None:
            async with semaphore:
                url = urljoin(target, path)
                try:
                    response = await client.get(url, timeout=5.0, follow_redirects=False)

                    if response.status_code == 200:
                        content = response.text if response.content else ""
                        content_type = response.headers.get("content-type", "")
                        evidence = None
                        version = None
                        finding_type: Literal[
                            "version_disclosure", "user_enumeration", "config_exposure",
                            "debug_exposure", "directory_listing", "sensitive_endpoint",
                            "admin_panel", "dev_environment"
                        ] = "sensitive_endpoint"

                        # Determine finding type based on path and content
                        if "debug" in path.lower() or "log" in path.lower():
                            finding_type = "debug_exposure"
                        elif "config" in path.lower() or ".env" in path.lower():
                            finding_type = "config_exposure"
                        elif "admin" in path.lower() or "login" in path.lower():
                            finding_type = "admin_panel"
                        elif "version" in path.lower() or "readme" in path.lower() or "changelog" in path.lower():
                            finding_type = "version_disclosure"
                        elif "users" in path.lower() or "author" in path.lower():
                            finding_type = "user_enumeration"
                        elif "_dev" in path.lower() or "debug" in path.lower() or "profiler" in path.lower():
                            finding_type = "dev_environment"

                        # Try to extract version information
                        if finding_type == "version_disclosure":
                            # Look for version patterns
                            version_patterns = [
                                r"version[:\s]+([0-9.]+)",
                                r"v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                                r"WordPress ([0-9.]+)",
                                r"Drupal ([0-9.]+)",
                                r"Joomla[!\s]+([0-9.]+)",
                            ]
                            for pattern in version_patterns:
                                match = re.search(pattern, content, re.IGNORECASE)
                                if match:
                                    version = match.group(1)
                                    evidence = f"Version {version} detected"
                                    break

                        # Check for directory listing
                        if "Index of" in content or "Directory listing" in content:
                            finding_type = "directory_listing"
                            evidence = "Directory listing enabled"

                        # Check for user enumeration in WordPress
                        if "wp-json/wp/v2/users" in path and content.strip().startswith("["):
                            finding_type = "user_enumeration"
                            try:
                                import json
                                users = json.loads(content)
                                if users and isinstance(users, list):
                                    usernames = [u.get("slug", u.get("name")) for u in users[:5] if isinstance(u, dict)]
                                    evidence = f"Users found: {', '.join(usernames)}"
                            except json.JSONDecodeError:
                                pass

                        return CMSFinding(
                            url=url,
                            cms_type=cms_type,
                            path=path,
                            finding_type=finding_type,
                            version=version,
                            evidence=evidence,
                            severity=severity,
                            description=f"{cms_type}: {description}",
                        )

                    elif response.status_code == 403:
                        # Path exists but forbidden - note for admin paths only
                        if "admin" in path.lower() or "login" in path.lower():
                            return CMSFinding(
                                url=url,
                                cms_type=cms_type,
                                path=path,
                                finding_type="admin_panel",
                                severity="info",
                                description=f"{cms_type}: {description} (access denied)",
                            )

                except Exception as e:
                    self.logger.debug("cms_path_check_failed", path=path, error=str(e))

            return None

        tasks = [
            check_cms_path(path, cms_type, desc, sev)
            for path, cms_type, desc, sev in self.CMS_PATHS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, CMSFinding):
                findings.append(result)

        # Detect CMS type based on findings
        cms_detected: dict[str, int] = {}
        for finding in findings:
            cms_detected[finding.cms_type] = cms_detected.get(finding.cms_type, 0) + 1

        if findings:
            self.logger.info(
                "cms_scan_completed",
                target=target,
                findings_count=len(findings),
                cms_detected=list(cms_detected.keys()),
            )

        return findings
