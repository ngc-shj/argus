"""ASN and IP range lookup models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from argus.models.base import BaseSchema


class ASNInfo(BaseSchema):
    """Autonomous System Number information."""

    asn: int | None = None
    name: str | None = None
    description: str | None = None
    country: str | None = None
    website: str | None = None
    email_contacts: list[str] = Field(default_factory=list)
    abuse_contacts: list[str] = Field(default_factory=list)


class IPRange(BaseSchema):
    """IP range/prefix announced by ASN."""

    prefix: str
    name: str | None = None
    description: str | None = None
    is_ipv6: bool = False


class BGPPeer(BaseSchema):
    """BGP peering relationship."""

    asn: int | None = None
    name: str | None = None
    description: str | None = None
    country: str | None = None
    relationship: Literal["upstream", "downstream", "peer"] | None = None


class GeoLocation(BaseSchema):
    """Geolocation information."""

    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_name: str | None = None
    postal: str | None = None
    timezone: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class ASNResult(BaseSchema):
    """Complete ASN and network scan result."""

    target: str
    ip_address: str | None = None
    hostname: str | None = None

    # ASN information
    asn: ASNInfo | None = None

    # IP ranges
    ip_ranges: list[IPRange] = Field(default_factory=list)

    # BGP peers
    bgp_peers: list[BGPPeer] = Field(default_factory=list)

    # Geolocation
    geolocation: GeoLocation | None = None

    # Registry information
    rir: str | None = None  # ARIN, RIPE, APNIC, etc.
    allocation_date: str | None = None

    errors: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def total_ip_ranges(self) -> int:
        return len(self.ip_ranges)

    @property
    def total_ipv4_ranges(self) -> int:
        return len([r for r in self.ip_ranges if not r.is_ipv6])

    @property
    def total_ipv6_ranges(self) -> int:
        return len([r for r in self.ip_ranges if r.is_ipv6])
