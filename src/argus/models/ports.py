"""Port scan result models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


# Common high-risk ports
HIGH_RISK_PORTS = {
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    110,  # POP3
    135,  # MS RPC
    139,  # NetBIOS
    143,  # IMAP
    445,  # SMB
    1433,  # MS SQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    27017,  # MongoDB
}


class ServiceInfo(BaseSchema):
    """Detected service information."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    extra_info: str | None = None


class PortResult(BaseSchema):
    """Single port scan result."""

    port: int
    protocol: str = "tcp"
    state: str  # open, closed, filtered
    service: ServiceInfo | None = None
    response_time_ms: float | None = None

    @property
    def is_high_risk(self) -> bool:
        return self.port in HIGH_RISK_PORTS


class PortScanResult(BaseSchema):
    """Complete port scan results."""

    target: str
    target_ip: str
    ports: list[PortResult] = Field(default_factory=list)
    scan_profile: str = "top_100"
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def closed_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "closed"]

    @property
    def filtered_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "filtered"]

    @property
    def high_risk_ports(self) -> list[PortResult]:
        """Ports commonly associated with security concerns."""
        return [p for p in self.open_ports if p.is_high_risk]

    @property
    def total_open(self) -> int:
        return len(self.open_ports)
