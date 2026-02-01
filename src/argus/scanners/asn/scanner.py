"""ASN and IP range lookup scanner."""

import asyncio
import re
import socket
import time
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.asn import (
    ASNResult,
    ASNInfo,
    IPRange,
    BGPPeer,
    GeoLocation,
)


class ASNScanner:
    """Scanner for ASN, IP range, and network information."""

    # Free API endpoints for ASN/IP info
    APIS = {
        "ipinfo": "https://ipinfo.io/{ip}/json",
        "bgpview_ip": "https://api.bgpview.io/ip/{ip}",
        "bgpview_asn": "https://api.bgpview.io/asn/{asn}",
        "bgpview_prefixes": "https://api.bgpview.io/asn/{asn}/prefixes",
        "bgpview_peers": "https://api.bgpview.io/asn/{asn}/peers",
        "rdap": "https://rdap.arin.net/registry/ip/{ip}",
        # RIPEstat APIs (fallback)
        "ripestat_prefixes": "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
        "ripestat_neighbours": "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}",
        "ripestat_asn_overview": "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
    }

    def __init__(self) -> None:
        self.logger = get_logger("asn_scanner")

    async def scan(self, target: str) -> ASNResult:
        """Scan target for ASN and network information."""
        start_time = time.time()
        settings = get_settings()

        self.logger.info("asn_scan_started", target=target)

        result = ASNResult(target=target)

        # Resolve hostname to IP if needed
        ip_address = await self._resolve_to_ip(target)
        if not ip_address:
            result.errors.append(f"Could not resolve {target} to IP address")
            return result

        result.ip_address = ip_address

        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Argus Security Scanner/1.0",
                "Accept": "application/json",
            },
        ) as client:
            # Run all lookups concurrently
            tasks = [
                self._lookup_ipinfo(client, ip_address),
                self._lookup_bgpview_ip(client, ip_address),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process ipinfo result
            if isinstance(results[0], dict):
                self._process_ipinfo(results[0], result)

            # Process BGPView IP result
            if isinstance(results[1], dict):
                self._process_bgpview_ip(results[1], result)

            # If we have ASN, get more details
            if result.asn and result.asn.asn:
                self.logger.info("asn_details_lookup", asn=result.asn.asn)

                # Use RIPEstat APIs (more reliable than BGPView)
                asn_tasks = [
                    self._lookup_ripestat_overview(client, result.asn.asn),
                    self._lookup_ripestat_prefixes(client, result.asn.asn),
                    self._lookup_ripestat_neighbours(client, result.asn.asn),
                ]

                asn_results = await asyncio.gather(*asn_tasks, return_exceptions=True)

                # Process ASN overview
                if isinstance(asn_results[0], dict):
                    self._process_ripestat_overview(asn_results[0], result)
                elif isinstance(asn_results[0], Exception):
                    self.logger.debug("ripestat_overview_exception", error=str(asn_results[0]))

                # Process prefixes
                if isinstance(asn_results[1], dict):
                    self._process_ripestat_prefixes(asn_results[1], result)
                    self.logger.debug("prefixes_processed", count=len(result.ip_ranges))
                elif isinstance(asn_results[1], Exception):
                    self.logger.debug("ripestat_prefixes_exception", error=str(asn_results[1]))

                # Process neighbours/peers
                if isinstance(asn_results[2], dict):
                    self._process_ripestat_neighbours(asn_results[2], result)
                    self.logger.debug("peers_processed", count=len(result.bgp_peers))
                elif isinstance(asn_results[2], Exception):
                    self.logger.debug("ripestat_neighbours_exception", error=str(asn_results[2]))
            else:
                self.logger.debug("asn_not_found", asn_obj=result.asn)

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "asn_scan_completed",
            target=target,
            ip=ip_address,
            asn=result.asn.asn if result.asn else None,
            duration=duration,
        )

        return result

    async def _resolve_to_ip(self, target: str) -> str | None:
        """Resolve hostname to IP address."""
        # Check if already an IP
        try:
            IPv4Address(target)
            return target
        except ValueError:
            pass

        # Resolve hostname
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, socket.gethostbyname, target.lstrip("https://").lstrip("http://").split("/")[0]
            )
            return result
        except socket.gaierror:
            return None

    async def _lookup_ipinfo(
        self, client: httpx.AsyncClient, ip: str
    ) -> dict | None:
        """Lookup IP info from ipinfo.io."""
        try:
            url = self.APIS["ipinfo"].format(ip=ip)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug("ipinfo_lookup_success", ip=ip, org=data.get("org"))
                return data
            else:
                self.logger.debug("ipinfo_lookup_failed", ip=ip, status=response.status_code)
        except Exception as e:
            self.logger.debug("ipinfo_lookup_error", ip=ip, error=str(e))
        return None

    async def _lookup_bgpview_ip(
        self, client: httpx.AsyncClient, ip: str
    ) -> dict | None:
        """Lookup IP info from BGPView."""
        try:
            url = self.APIS["bgpview_ip"].format(ip=ip)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug("bgpview_ip_lookup_success", ip=ip, status=data.get("status"))
                return data
            else:
                self.logger.debug("bgpview_ip_lookup_failed", ip=ip, status=response.status_code)
        except Exception as e:
            self.logger.debug("bgpview_ip_lookup_error", ip=ip, error=str(e))
        return None

    async def _lookup_bgpview_asn(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup ASN details from BGPView."""
        try:
            url = self.APIS["bgpview_asn"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug("bgpview_asn_lookup_success", asn=asn, status=data.get("status"))
                return data
            else:
                self.logger.debug("bgpview_asn_lookup_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("bgpview_asn_lookup_error", asn=asn, error=str(e))
        return None

    async def _lookup_bgpview_prefixes(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup ASN prefixes from BGPView."""
        try:
            url = self.APIS["bgpview_prefixes"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                prefixes_data = data.get("data", {})
                ipv4_count = len(prefixes_data.get("ipv4_prefixes", []))
                ipv6_count = len(prefixes_data.get("ipv6_prefixes", []))
                self.logger.debug(
                    "bgpview_prefixes_lookup_success",
                    asn=asn,
                    ipv4_count=ipv4_count,
                    ipv6_count=ipv6_count
                )
                return data
            else:
                self.logger.debug("bgpview_prefixes_lookup_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("bgpview_prefixes_lookup_error", asn=asn, error=str(e))
        return None

    async def _lookup_bgpview_peers(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup ASN peers from BGPView."""
        try:
            url = self.APIS["bgpview_peers"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                peers_data = data.get("data", {})
                upstream_count = len(peers_data.get("ipv4_upstreams", []))
                peer_count = len(peers_data.get("ipv4_peers", []))
                self.logger.debug(
                    "bgpview_peers_lookup_success",
                    asn=asn,
                    upstream_count=upstream_count,
                    peer_count=peer_count
                )
                return data
            else:
                self.logger.debug("bgpview_peers_lookup_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("bgpview_peers_lookup_error", asn=asn, error=str(e))
        return None

    # RIPEstat API methods (more reliable alternative)

    async def _lookup_ripestat_overview(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup ASN overview from RIPEstat."""
        try:
            url = self.APIS["ripestat_asn_overview"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                self.logger.debug("ripestat_overview_success", asn=asn, status=data.get("status"))
                return data
            else:
                self.logger.debug("ripestat_overview_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("ripestat_overview_error", asn=asn, error=str(e))
        return None

    async def _lookup_ripestat_prefixes(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup announced prefixes from RIPEstat."""
        try:
            url = self.APIS["ripestat_prefixes"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                prefixes = data.get("data", {}).get("prefixes", [])
                self.logger.debug("ripestat_prefixes_success", asn=asn, count=len(prefixes))
                return data
            else:
                self.logger.debug("ripestat_prefixes_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("ripestat_prefixes_error", asn=asn, error=str(e))
        return None

    async def _lookup_ripestat_neighbours(
        self, client: httpx.AsyncClient, asn: int
    ) -> dict | None:
        """Lookup ASN neighbours from RIPEstat."""
        try:
            url = self.APIS["ripestat_neighbours"].format(asn=asn)
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                neighbours = data.get("data", {}).get("neighbours", [])
                self.logger.debug("ripestat_neighbours_success", asn=asn, count=len(neighbours))
                return data
            else:
                self.logger.debug("ripestat_neighbours_failed", asn=asn, status=response.status_code)
        except Exception as e:
            self.logger.debug("ripestat_neighbours_error", asn=asn, error=str(e))
        return None

    def _process_ipinfo(self, data: dict, result: ASNResult) -> None:
        """Process ipinfo.io response."""
        # Parse ASN from org field (format: "AS12345 Company Name")
        org = data.get("org", "")
        asn_match = re.match(r"AS(\d+)\s+(.+)", org)

        if asn_match:
            asn_num = int(asn_match.group(1))
            asn_name = asn_match.group(2)

            if not result.asn:
                result.asn = ASNInfo(asn=asn_num, name=asn_name)
            else:
                result.asn.asn = asn_num
                result.asn.name = asn_name

        # Geolocation
        result.geolocation = GeoLocation(
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country"),
            country_name=data.get("country"),
            postal=data.get("postal"),
            timezone=data.get("timezone"),
        )

        # Parse coordinates
        loc = data.get("loc", "")
        if "," in loc:
            lat, lon = loc.split(",")
            try:
                result.geolocation.latitude = float(lat)
                result.geolocation.longitude = float(lon)
            except ValueError:
                pass

        result.hostname = data.get("hostname")

    def _process_bgpview_ip(self, data: dict, result: ASNResult) -> None:
        """Process BGPView IP response."""
        if data.get("status") != "ok":
            return

        ip_data = data.get("data", {})

        # Get prefix info
        prefixes = ip_data.get("prefixes", [])
        if prefixes:
            prefix = prefixes[0]
            asn_data = prefix.get("asn", {})

            if not result.asn:
                result.asn = ASNInfo(
                    asn=asn_data.get("asn"),
                    name=asn_data.get("name"),
                    description=asn_data.get("description"),
                    country=asn_data.get("country_code"),
                )

            # Add this prefix to ranges
            prefix_str = prefix.get("prefix")
            if prefix_str:
                result.ip_ranges.append(IPRange(
                    prefix=prefix_str,
                    name=prefix.get("name"),
                    description=prefix.get("description"),
                ))

        # RIR info
        rir = ip_data.get("rir_allocation", {})
        if rir:
            result.rir = rir.get("rir_name")
            result.allocation_date = rir.get("date_allocated")

    def _process_bgpview_asn(self, data: dict, result: ASNResult) -> None:
        """Process BGPView ASN response."""
        if data.get("status") != "ok":
            return

        asn_data = data.get("data", {})

        if result.asn:
            result.asn.description = asn_data.get("description_full") or result.asn.description
            result.asn.country = asn_data.get("country_code") or result.asn.country
            result.asn.website = asn_data.get("website")

            # Email contacts
            email_contacts = asn_data.get("email_contacts", [])
            if email_contacts:
                result.asn.email_contacts = email_contacts

            # Abuse contacts
            abuse_contacts = asn_data.get("abuse_contacts", [])
            if abuse_contacts:
                result.asn.abuse_contacts = abuse_contacts

        # RIR info
        rir = asn_data.get("rir_allocation", {})
        if rir:
            result.rir = rir.get("rir_name") or result.rir
            result.allocation_date = rir.get("date_allocated") or result.allocation_date

    def _process_bgpview_prefixes(self, data: dict, result: ASNResult) -> None:
        """Process BGPView prefixes response."""
        if data.get("status") != "ok":
            return

        prefixes_data = data.get("data", {})

        # IPv4 prefixes
        ipv4_prefixes = prefixes_data.get("ipv4_prefixes", [])
        for prefix in ipv4_prefixes[:50]:  # Limit to 50
            prefix_str = prefix.get("prefix")
            if prefix_str and not any(r.prefix == prefix_str for r in result.ip_ranges):
                result.ip_ranges.append(IPRange(
                    prefix=prefix_str,
                    name=prefix.get("name"),
                    description=prefix.get("description"),
                    is_ipv6=False,
                ))

        # IPv6 prefixes
        ipv6_prefixes = prefixes_data.get("ipv6_prefixes", [])
        for prefix in ipv6_prefixes[:20]:  # Limit to 20
            prefix_str = prefix.get("prefix")
            if prefix_str:
                result.ip_ranges.append(IPRange(
                    prefix=prefix_str,
                    name=prefix.get("name"),
                    description=prefix.get("description"),
                    is_ipv6=True,
                ))

    def _process_bgpview_peers(self, data: dict, result: ASNResult) -> None:
        """Process BGPView peers response."""
        if data.get("status") != "ok":
            return

        peers_data = data.get("data", {})

        # Upstream peers
        upstream = peers_data.get("ipv4_upstreams", [])
        for peer in upstream[:10]:  # Limit to 10
            result.bgp_peers.append(BGPPeer(
                asn=peer.get("asn"),
                name=peer.get("name"),
                description=peer.get("description"),
                country=peer.get("country_code"),
                relationship="upstream",
            ))

        # Downstream peers
        downstream = peers_data.get("ipv4_downstreams", [])
        for peer in downstream[:10]:  # Limit to 10
            result.bgp_peers.append(BGPPeer(
                asn=peer.get("asn"),
                name=peer.get("name"),
                description=peer.get("description"),
                country=peer.get("country_code"),
                relationship="downstream",
            ))

        # Lateral peers (peers)
        peers = peers_data.get("ipv4_peers", [])
        for peer in peers[:10]:  # Limit to 10
            result.bgp_peers.append(BGPPeer(
                asn=peer.get("asn"),
                name=peer.get("name"),
                description=peer.get("description"),
                country=peer.get("country_code"),
                relationship="peer",
            ))

    # RIPEstat processing methods

    def _process_ripestat_overview(self, data: dict, result: ASNResult) -> None:
        """Process RIPEstat AS overview response."""
        if data.get("status") != "ok":
            return

        asn_data = data.get("data", {})

        if result.asn:
            # Update holder name if available
            holder = asn_data.get("holder")
            if holder and not result.asn.description:
                result.asn.description = holder

    def _process_ripestat_prefixes(self, data: dict, result: ASNResult) -> None:
        """Process RIPEstat announced prefixes response."""
        if data.get("status") != "ok":
            return

        prefixes = data.get("data", {}).get("prefixes", [])

        for prefix_data in prefixes[:50]:  # Limit to 50
            prefix_str = prefix_data.get("prefix")
            if prefix_str and not any(r.prefix == prefix_str for r in result.ip_ranges):
                # Detect IPv6
                is_ipv6 = ":" in prefix_str

                result.ip_ranges.append(IPRange(
                    prefix=prefix_str,
                    is_ipv6=is_ipv6,
                ))

    def _process_ripestat_neighbours(self, data: dict, result: ASNResult) -> None:
        """Process RIPEstat ASN neighbours response."""
        if data.get("status") != "ok":
            return

        neighbours = data.get("data", {}).get("neighbours", [])

        for neighbour in neighbours[:30]:  # Limit to 30
            asn_num = neighbour.get("asn")
            peer_type = neighbour.get("type")

            # Map RIPEstat type to our relationship type
            # left = upstream (providers), right = downstream (customers)
            if peer_type == "left":
                relationship = "upstream"
            elif peer_type == "right":
                relationship = "downstream"
            else:
                relationship = "peer"

            result.bgp_peers.append(BGPPeer(
                asn=asn_num,
                relationship=relationship,
            ))
