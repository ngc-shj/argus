"""Port Scanner implementation."""

import asyncio
import socket
import time
from datetime import datetime

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.ports import PortResult, PortScanResult, ServiceInfo
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


# Port scan profiles
PORT_PROFILES = {
    "top_20": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    ],
    "top_100": [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
        465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
        993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
        1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
        3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
        5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
        49155, 49156, 49157,
    ],
    "top_1000": list(range(1, 1001)),
}

# Common port to service mapping
PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


@ScannerRegistry.register
class PortScanner(BaseScanner[PortScanResult]):
    """TCP port scanner."""

    @property
    def name(self) -> str:
        return "ports"

    @property
    def description(self) -> str:
        return "TCP port scanning and service detection"

    def get_capabilities(self) -> list[str]:
        return [
            "TCP connect scan",
            "Service detection",
            "Common port profiles",
            "Custom port ranges",
            "Banner grabbing",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate target."""
        return target.domain is not None or target.ip_address is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> PortScanResult:
        """Execute port scan."""
        options = options or ScanOptions()
        settings = get_settings()

        # Resolve target to IP if needed
        target_host = target.ip_address or target.domain
        if not target_host:
            raise ScanError("Domain or IP is required for port scan", scanner=self.name)

        # Resolve domain to IP
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror as e:
            raise ScanError(
                f"Failed to resolve {target_host}: {e}",
                scanner=self.name,
                target=target_host,
            ) from e

        start_time = time.time()
        self.logger.info("port_scan_started", target=target_host, ip=target_ip)

        # Get ports to scan
        if options.port_scan_profile == "custom" and options.port_scan_custom_ports:
            ports = options.port_scan_custom_ports
        else:
            ports = PORT_PROFILES.get(options.port_scan_profile, PORT_PROFILES["top_100"])

        # Scan ports concurrently
        semaphore = asyncio.Semaphore(settings.port_scans_per_second)
        timeout = settings.port_scan_timeout

        async def scan_port(port: int) -> PortResult:
            async with semaphore:
                return await self._check_port(target_ip, port, timeout)

        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks)

        duration = time.time() - start_time

        port_result = PortScanResult(
            target=target_host,
            target_ip=target_ip,
            ports=list(results),
            scan_profile=options.port_scan_profile,
            scanned_at=datetime.utcnow(),
            duration_seconds=duration,
        )

        self.logger.info(
            "port_scan_completed",
            target=target_host,
            open_ports=port_result.total_open,
            duration=duration,
        )

        return port_result

    async def _check_port(
        self,
        host: str,
        port: int,
        timeout: float,
    ) -> PortResult:
        """Check if a single port is open."""
        start_time = time.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            response_time = (time.time() - start_time) * 1000

            # Try to grab banner
            service_info = await self._detect_service(reader, writer, port)

            writer.close()
            await writer.wait_closed()

            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service_info,
                response_time_ms=response_time,
            )

        except asyncio.TimeoutError:
            return PortResult(
                port=port,
                protocol="tcp",
                state="filtered",
                service=None,
                response_time_ms=None,
            )
        except ConnectionRefusedError:
            return PortResult(
                port=port,
                protocol="tcp",
                state="closed",
                service=None,
                response_time_ms=None,
            )
        except Exception:
            return PortResult(
                port=port,
                protocol="tcp",
                state="filtered",
                service=None,
                response_time_ms=None,
            )

    async def _detect_service(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ) -> ServiceInfo:
        """Detect service running on port."""
        service_name = PORT_SERVICES.get(port, "unknown")
        banner = None

        try:
            # Try to read banner (for services that send one immediately)
            reader_task = asyncio.create_task(reader.read(1024))
            try:
                data = await asyncio.wait_for(reader_task, timeout=1.0)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()[:200]
            except asyncio.TimeoutError:
                reader_task.cancel()
                try:
                    await reader_task
                except asyncio.CancelledError:
                    pass

            # For HTTP, send a request
            if port in (80, 8080, 8000, 8008):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                await writer.drain()

                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").strip()[:200]
                except asyncio.TimeoutError:
                    banner = None  # Timeout during banner read is expected

        except Exception:
            banner = None  # Connection failures during banner grab are expected

        # Parse version from banner if possible
        version = None
        if banner:
            # Simple version extraction (could be enhanced)
            parts = banner.split()
            for part in parts:
                if any(c.isdigit() for c in part) and "." in part:
                    version = part[:20]
                    break

        return ServiceInfo(
            name=service_name,
            product=None,
            version=version,
            banner=banner,
        )
