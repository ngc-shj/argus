"""WHOIS and RDAP result models."""

from datetime import datetime

from pydantic import Field

from argus.models.base import BaseSchema


class RegistrarInfo(BaseSchema):
    """Domain registrar information."""

    name: str | None = None
    url: str | None = None
    abuse_email: str | None = None
    abuse_phone: str | None = None


class ContactInfo(BaseSchema):
    """Contact information (may be redacted)."""

    name: str | None = None
    organization: str | None = None
    email: str | None = None
    phone: str | None = None
    address: str | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None
    postal_code: str | None = None
    is_redacted: bool = False


class WHOISResult(BaseSchema):
    """WHOIS lookup result."""

    target: str
    domain_name: str | None = None
    registrar: RegistrarInfo | None = None

    registrant: ContactInfo | None = None
    admin_contact: ContactInfo | None = None
    tech_contact: ContactInfo | None = None

    creation_date: datetime | None = None
    updated_date: datetime | None = None
    expiration_date: datetime | None = None

    status: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)

    raw_text: str | None = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = "whois"

    @property
    def days_until_expiry(self) -> int | None:
        if self.expiration_date:
            now = datetime.utcnow()
            # Handle timezone-aware expiration_date
            if self.expiration_date.tzinfo is not None:
                now = now.replace(tzinfo=self.expiration_date.tzinfo)
            delta = self.expiration_date - now
            return delta.days
        return None


class RDAPResult(BaseSchema):
    """RDAP lookup result with enhanced structured data."""

    target: str
    handle: str | None = None

    # Domain information
    domain_name: str | None = None

    # Network information (for IP lookups)
    network_name: str | None = None
    network_cidr: str | None = None
    network_type: str | None = None
    network_start: str | None = None
    network_end: str | None = None

    # ASN information
    asn: int | None = None
    asn_name: str | None = None
    asn_country: str | None = None

    # Entities
    entities: list[ContactInfo] = Field(default_factory=list)

    # Events (registration, expiration, etc.)
    events: dict[str, datetime] = Field(default_factory=dict)

    # Links and references
    links: list[str] = Field(default_factory=list)

    raw_data: dict | None = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
