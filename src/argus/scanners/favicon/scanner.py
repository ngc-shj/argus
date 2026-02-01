"""Favicon hash fingerprinting scanner."""

import base64
import hashlib
import re
import struct
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.favicon import FaviconResult, FaviconMatch


class FaviconScanner:
    """Scanner for favicon hash fingerprinting (like Shodan)."""

    # Known favicon hashes (MurmurHash3)
    # Format: hash -> (technology, description, category)
    KNOWN_HASHES: dict[int, tuple[str, str, str]] = {
        # CMS
        116323821: ("WordPress", "WordPress CMS", "cms"),
        -1485350695: ("Drupal", "Drupal CMS", "cms"),
        1820923792: ("Joomla", "Joomla CMS", "cms"),
        -1395803172: ("Magento", "Magento E-Commerce", "cms"),
        -1999028939: ("Shopify", "Shopify E-Commerce", "cms"),

        # Web Servers
        -1137282013: ("Apache", "Apache HTTP Server", "server"),
        -91559716: ("nginx", "nginx Web Server", "server"),
        1076019596: ("IIS", "Microsoft IIS", "server"),

        # Security/Network
        -247388731: ("pfSense", "pfSense Firewall", "security"),
        1485957958: ("Fortinet", "Fortinet FortiGate", "security"),
        -1293291046: ("Palo Alto", "Palo Alto Networks", "security"),
        -1018024164: ("Sophos", "Sophos UTM/XG", "security"),
        116325195: ("F5 BIG-IP", "F5 BIG-IP", "security"),
        -1357949474: ("Citrix", "Citrix ADC/NetScaler", "security"),
        708578229: ("Cisco ASA", "Cisco ASA VPN", "security"),
        -1571997060: ("SonicWall", "SonicWall Firewall", "security"),
        -1625607154: ("WatchGuard", "WatchGuard Firewall", "security"),

        # Remote Access
        -2144606731: ("VMware Horizon", "VMware Horizon View", "remote"),
        -1654003859: ("Citrix Virtual Apps", "Citrix Virtual Apps", "remote"),
        442749392: ("TeamViewer", "TeamViewer", "remote"),
        -540445939: ("AnyDesk", "AnyDesk Remote", "remote"),

        # Development
        1485481052: ("Jenkins", "Jenkins CI/CD", "devops"),
        -1089328572: ("GitLab", "GitLab", "devops"),
        1200704648: ("Grafana", "Grafana Monitoring", "devops"),
        1616574915: ("Kibana", "Kibana (Elastic)", "devops"),
        -305179312: ("Prometheus", "Prometheus", "devops"),
        1579621391: ("Kubernetes Dashboard", "Kubernetes Dashboard", "devops"),
        -1467534799: ("ArgoCD", "ArgoCD GitOps", "devops"),
        81586312: ("SonarQube", "SonarQube", "devops"),
        -676836308: ("Nexus Repository", "Sonatype Nexus", "devops"),
        -1950415971: ("Artifactory", "JFrog Artifactory", "devops"),
        989289239: ("Harbor", "Harbor Container Registry", "devops"),
        -1831551480: ("Traefik", "Traefik Proxy", "devops"),

        # Database/Admin
        470922649: ("phpMyAdmin", "phpMyAdmin", "database"),
        -1503668405: ("Adminer", "Adminer DB Admin", "database"),
        -956089362: ("pgAdmin", "pgAdmin PostgreSQL", "database"),
        -1168856927: ("MongoDB Compass", "MongoDB", "database"),
        876876147: ("Redis Commander", "Redis Commander", "database"),
        -1190015801: ("Elasticsearch", "Elasticsearch", "database"),

        # Routers/IoT
        708578229: ("Cisco", "Cisco Device", "router"),
        -533085157: ("MikroTik", "MikroTik Router", "router"),
        -1820944247: ("Ubiquiti", "Ubiquiti UniFi", "router"),
        -1057526508: ("TP-Link", "TP-Link Device", "router"),
        1935056178: ("NETGEAR", "NETGEAR Device", "router"),
        -1095190892: ("Synology", "Synology NAS", "storage"),
        -1882015314: ("QNAP", "QNAP NAS", "storage"),

        # Cloud/Panels
        -1659958523: ("cPanel", "cPanel", "panel"),
        1137828799: ("Plesk", "Plesk", "panel"),
        -1312660747: ("DirectAdmin", "DirectAdmin", "panel"),
        -1318235953: ("Webmin", "Webmin", "panel"),
        -1940350834: ("Cockpit", "Cockpit Linux", "panel"),
        -1403656549: ("Portainer", "Portainer Docker", "panel"),
        -1263695765: ("Proxmox", "Proxmox VE", "panel"),
        117812177: ("AWS", "Amazon Web Services", "cloud"),
        878647854: ("Azure", "Microsoft Azure", "cloud"),
        -1414511853: ("GCP", "Google Cloud Platform", "cloud"),

        # Microsoft
        -1353588006: ("Exchange OWA", "Microsoft Exchange OWA", "microsoft"),
        -1654152666: ("SharePoint", "Microsoft SharePoint", "microsoft"),
        -1137533671: ("Office 365", "Microsoft Office 365", "microsoft"),
        666871022: ("ADFS", "Microsoft ADFS", "microsoft"),
        1637599554: ("Azure AD", "Azure Active Directory", "microsoft"),

        # Security Tools
        1419556784: ("Burp Suite", "Burp Suite Collaborator", "security"),
        -1501605107: ("Nessus", "Tenable Nessus", "security"),
        -1949154606: ("Qualys", "Qualys Scanner", "security"),
        1090048227: ("Rapid7", "Rapid7", "security"),
        -1718152421: ("OSSEC", "OSSEC HIDS", "security"),
        -924047792: ("Wazuh", "Wazuh SIEM", "security"),

        # Other
        -1021855567: ("Spring Boot", "Spring Boot Admin", "framework"),
        -630223528: ("Django", "Django Admin", "framework"),
        -1550224459: ("Laravel", "Laravel", "framework"),
        -1395265098: ("Ruby on Rails", "Ruby on Rails", "framework"),
        -508217979: ("ASP.NET", "ASP.NET Application", "framework"),
    }

    def __init__(self) -> None:
        self.logger = get_logger("favicon_scanner")

    async def scan(self, target: str) -> FaviconResult:
        """Scan target for favicon and calculate hash."""
        start_time = time.time()
        settings = get_settings()

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        self.logger.info("favicon_scan_started", target=target)

        result = FaviconResult(target=target)

        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Try to find favicon URL from HTML
            favicon_urls = await self._find_favicon_urls(client, target)

            # Add common fallback paths
            favicon_urls.extend([
                urljoin(base_url, "/favicon.ico"),
                urljoin(base_url, "/favicon.png"),
                urljoin(base_url, "/apple-touch-icon.png"),
            ])

            # Remove duplicates while preserving order
            seen: set[str] = set()
            unique_urls: list[str] = []
            for url in favicon_urls:
                if url not in seen:
                    seen.add(url)
                    unique_urls.append(url)

            # Try each URL
            for favicon_url in unique_urls:
                try:
                    response = await client.get(favicon_url)

                    if response.status_code == 200 and len(response.content) > 0:
                        content_type = response.headers.get("content-type", "").lower()

                        # Check if it's likely an image
                        if self._is_valid_favicon(response.content, content_type):
                            result.found = True
                            result.url = favicon_url
                            result.content_type = content_type
                            result.size = len(response.content)

                            # Calculate hashes
                            result.md5_hash = hashlib.md5(response.content).hexdigest()
                            result.sha256_hash = hashlib.sha256(response.content).hexdigest()

                            # Calculate MurmurHash3 (Shodan-style)
                            favicon_b64 = base64.b64encode(response.content).decode()
                            result.mmh3_hash = self._mmh3_hash(favicon_b64)

                            # Try to match against known hashes
                            if result.mmh3_hash in self.KNOWN_HASHES:
                                tech, desc, category = self.KNOWN_HASHES[result.mmh3_hash]
                                result.matches.append(FaviconMatch(
                                    technology=tech,
                                    description=desc,
                                    category=category,
                                    confidence="high",
                                    hash_matched=result.mmh3_hash,
                                ))

                            self.logger.info(
                                "favicon_found",
                                url=favicon_url,
                                mmh3_hash=result.mmh3_hash,
                                matched=len(result.matches) > 0,
                            )
                            break

                except Exception as e:
                    self.logger.debug("favicon_fetch_failed", url=favicon_url, error=str(e))

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "favicon_scan_completed",
            target=target,
            found=result.found,
            matches=len(result.matches),
            duration=duration,
        )

        return result

    async def _find_favicon_urls(
        self, client: httpx.AsyncClient, target: str
    ) -> list[str]:
        """Find favicon URLs from HTML."""
        urls: list[str] = []

        try:
            response = await client.get(target)
            if response.status_code != 200:
                return urls

            html = response.text

            # Look for link tags with rel="icon" or rel="shortcut icon"
            patterns = [
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
                r'<link[^>]+rel=["\']apple-touch-icon["\'][^>]+href=["\']([^"\']+)["\']',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    # Resolve relative URLs
                    if match.startswith(("http://", "https://")):
                        urls.append(match)
                    elif match.startswith("//"):
                        urls.append(f"https:{match}")
                    elif match.startswith("/"):
                        parsed = urlparse(target)
                        urls.append(f"{parsed.scheme}://{parsed.netloc}{match}")
                    else:
                        urls.append(urljoin(target, match))

        except Exception as e:
            self.logger.debug("favicon_html_parse_failed", error=str(e))

        return urls

    def _is_valid_favicon(self, content: bytes, content_type: str) -> bool:
        """Check if content is a valid favicon."""
        # Check content type
        valid_types = ["image/", "application/octet-stream", "text/plain"]
        if any(vt in content_type for vt in valid_types):
            pass
        elif content_type:
            return False

        # Check magic bytes
        if len(content) < 4:
            return False

        # ICO format
        if content[:4] == b"\x00\x00\x01\x00":
            return True

        # PNG format
        if content[:8] == b"\x89PNG\r\n\x1a\n":
            return True

        # GIF format
        if content[:6] in (b"GIF87a", b"GIF89a"):
            return True

        # JPEG format
        if content[:2] == b"\xff\xd8":
            return True

        # SVG format (check for XML/SVG markers)
        if b"<svg" in content[:1000].lower() or b"<?xml" in content[:100]:
            return True

        # BMP format
        if content[:2] == b"BM":
            return True

        # WebP format
        if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
            return True

        return False

    def _mmh3_hash(self, data: str) -> int:
        """Calculate MurmurHash3 (32-bit, seed 0) like Shodan."""
        # This is a Python implementation of MurmurHash3
        key = data.encode("utf-8")

        def fmix(h: int) -> int:
            h ^= h >> 16
            h = (h * 0x85EBCA6B) & 0xFFFFFFFF
            h ^= h >> 13
            h = (h * 0xC2B2AE35) & 0xFFFFFFFF
            h ^= h >> 16
            return h

        length = len(key)
        nblocks = length // 4

        h1 = 0
        c1 = 0xCC9E2D51
        c2 = 0x1B873593

        # Body
        for block_start in range(0, nblocks * 4, 4):
            k1 = struct.unpack("<I", key[block_start:block_start + 4])[0]

            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF

            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

        # Tail
        tail_index = nblocks * 4
        k1 = 0
        tail_size = length & 3

        if tail_size >= 3:
            k1 ^= key[tail_index + 2] << 16
        if tail_size >= 2:
            k1 ^= key[tail_index + 1] << 8
        if tail_size >= 1:
            k1 ^= key[tail_index]

        if tail_size > 0:
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        # Finalization
        h1 ^= length
        h1 = fmix(h1)

        # Convert to signed 32-bit integer (like Shodan)
        if h1 >= 0x80000000:
            h1 -= 0x100000000

        return h1
