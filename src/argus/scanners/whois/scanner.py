"""WHOIS Scanner implementation."""

import asyncio
import time
from datetime import datetime
from typing import Any

import asyncwhois

from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.whois import (
    ContactInfo,
    RegistrarInfo,
    WHOISResult,
    RDAPResult,
)
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


@ScannerRegistry.register
class WHOISScanner(BaseScanner[WHOISResult]):
    """WHOIS information scanner."""

    @property
    def name(self) -> str:
        return "whois"

    @property
    def description(self) -> str:
        return "WHOIS and RDAP domain/IP registration data"

    def get_capabilities(self) -> list[str]:
        return [
            "Domain WHOIS lookup",
            "IP WHOIS lookup",
            "Registrar information",
            "Registration dates",
            "Contact information",
            "Nameserver information",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate target."""
        return target.domain is not None or target.ip_address is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> WHOISResult:
        """Execute WHOIS scan."""
        query = target.domain or target.ip_address
        if not query:
            raise ScanError("Domain or IP is required for WHOIS scan", scanner=self.name)

        start_time = time.time()
        self.logger.info("whois_scan_started", target=query)

        try:
            # Run WHOIS query
            result = await asyncio.to_thread(asyncwhois.whois, query)

            # Parse result
            whois_result = self._parse_whois_result(query, result)

            duration = time.time() - start_time
            self.logger.info(
                "whois_scan_completed",
                target=query,
                duration=duration,
            )

            return whois_result

        except Exception as e:
            self.logger.error("whois_scan_failed", target=query, error=str(e))
            raise ScanError(
                f"WHOIS scan failed: {e}",
                scanner=self.name,
                target=query,
            ) from e

    def _parse_whois_result(self, target: str, result: Any) -> WHOISResult:
        """Parse WHOIS result into structured data."""
        # asyncwhois.whois returns tuple: (raw_text, parsed_dict)
        if isinstance(result, tuple) and len(result) >= 2:
            raw_text = result[0]
            parser_output = result[1] if isinstance(result[1], dict) else {}
        elif hasattr(result, 'parser_output'):
            parser_output = result.parser_output or {}
            raw_text = result.query_output if hasattr(result, 'query_output') else None
        else:
            parser_output = {}
            raw_text = None

        # Extract registrar info
        registrar = None
        if parser_output.get("registrar"):
            registrar = RegistrarInfo(
                name=parser_output.get("registrar"),
                url=parser_output.get("registrar_url"),
                abuse_email=parser_output.get("registrar_abuse_email"),
                abuse_phone=parser_output.get("registrar_abuse_phone"),
            )

        # Extract contact info
        registrant = self._extract_contact(parser_output, "registrant")
        admin_contact = self._extract_contact(parser_output, "admin")
        tech_contact = self._extract_contact(parser_output, "tech")

        # Extract dates
        creation_date = self._parse_date(parser_output.get("created"))
        updated_date = self._parse_date(parser_output.get("updated"))
        expiration_date = self._parse_date(parser_output.get("expires"))

        # Extract status and nameservers
        status = parser_output.get("status", [])
        if isinstance(status, str):
            status = [status]

        nameservers = parser_output.get("name_servers", [])
        if isinstance(nameservers, str):
            nameservers = [nameservers]

        return WHOISResult(
            target=target,
            domain_name=parser_output.get("domain_name"),
            registrar=registrar,
            registrant=registrant,
            admin_contact=admin_contact,
            tech_contact=tech_contact,
            creation_date=creation_date,
            updated_date=updated_date,
            expiration_date=expiration_date,
            status=status,
            nameservers=nameservers,
            raw_text=raw_text,
            scanned_at=datetime.utcnow(),
            source="whois",
        )

    def _extract_contact(self, data: dict, prefix: str) -> ContactInfo | None:
        """Extract contact information with given prefix."""
        name = data.get(f"{prefix}_name")
        org = data.get(f"{prefix}_organization") or data.get(f"{prefix}_org")

        if not name and not org:
            return None

        return ContactInfo(
            name=name,
            organization=org,
            email=data.get(f"{prefix}_email"),
            phone=data.get(f"{prefix}_phone"),
            address=data.get(f"{prefix}_address"),
            city=data.get(f"{prefix}_city"),
            state=data.get(f"{prefix}_state"),
            country=data.get(f"{prefix}_country"),
            postal_code=data.get(f"{prefix}_postal_code"),
            is_redacted="redacted" in str(name or "").lower(),
        )

    def _parse_date(self, date_value: Any) -> datetime | None:
        """Parse date from various formats."""
        if date_value is None:
            return None

        if isinstance(date_value, datetime):
            return date_value

        if isinstance(date_value, list) and date_value:
            date_value = date_value[0]
            # After extraction, check if it's a datetime
            if isinstance(date_value, datetime):
                return date_value

        if isinstance(date_value, str):
            try:
                from dateutil import parser
                return parser.parse(date_value)
            except Exception:
                # Date parsing failures are expected for non-standard formats
                return None

        return None


@ScannerRegistry.register
class RDAPScanner(BaseScanner[RDAPResult]):
    """RDAP information scanner."""

    # RDAP bootstrap URLs
    DOMAIN_RDAP_URL = "https://rdap.org/domain/"
    IP_RDAP_URL = "https://rdap.org/ip/"

    @property
    def name(self) -> str:
        return "rdap"

    @property
    def description(self) -> str:
        return "RDAP (Registration Data Access Protocol) lookup"

    def get_capabilities(self) -> list[str]:
        return [
            "Domain RDAP lookup",
            "IP RDAP lookup",
            "ASN information",
            "Network CIDR",
            "Structured entity data",
        ]

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> RDAPResult:
        """Execute RDAP scan."""
        query = target.domain or target.ip_address
        if not query:
            raise ScanError("Domain or IP is required for RDAP scan", scanner=self.name)

        start_time = time.time()
        self.logger.info("rdap_scan_started", target=query)

        try:
            # Try asyncwhois first
            try:
                result = await asyncio.to_thread(asyncwhois.rdap, query)
                # asyncwhois.rdap returns tuple: (raw_text, parsed_dict)
                if isinstance(result, tuple) and len(result) >= 2:
                    rdap_result = self._parse_asyncwhois_rdap(query, result)
                else:
                    rdap_result = self._parse_rdap_result(query, result)
            except Exception as e:
                self.logger.debug("asyncwhois_rdap_failed", error=str(e))
                # Fallback to direct RDAP query
                rdap_result = await self._direct_rdap_query(query, target.domain is not None)

            duration = time.time() - start_time
            self.logger.info(
                "rdap_scan_completed",
                target=query,
                duration=duration,
            )

            return rdap_result

        except Exception as e:
            self.logger.error("rdap_scan_failed", target=query, error=str(e))
            raise ScanError(
                f"RDAP scan failed: {e}",
                scanner=self.name,
                target=query,
            ) from e

    async def _direct_rdap_query(self, query: str, is_domain: bool) -> RDAPResult:
        """Direct RDAP query using httpx."""
        import httpx

        base_url = self.DOMAIN_RDAP_URL if is_domain else self.IP_RDAP_URL
        url = f"{base_url}{query}"

        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        return self._parse_rdap_json(query, data)

    def _parse_asyncwhois_rdap(self, target: str, result: tuple) -> RDAPResult:
        """Parse asyncwhois.rdap() tuple result."""
        raw_text, parsed_data = result[0], result[1]

        # Extract contact info
        entities = []

        # Check for admin contact
        admin_name = parsed_data.get("admin_name")
        admin_org = parsed_data.get("admin_organization")
        if admin_name or admin_org:
            entities.append(ContactInfo(
                name=admin_name,
                organization=admin_org,
                email=parsed_data.get("admin_email"),
                phone=parsed_data.get("admin_phone"),
                address=parsed_data.get("admin_address"),
            ))

        # Check for tech contact
        tech_name = parsed_data.get("tech_name")
        tech_org = parsed_data.get("tech_organization")
        if tech_name or tech_org:
            entities.append(ContactInfo(
                name=tech_name,
                organization=tech_org,
                email=parsed_data.get("tech_email"),
                phone=parsed_data.get("tech_phone"),
            ))

        # Check for registrant
        registrant_name = parsed_data.get("registrant_name")
        registrant_org = parsed_data.get("registrant_organization")
        if registrant_name or registrant_org:
            entities.append(ContactInfo(
                name=registrant_name,
                organization=registrant_org,
                email=parsed_data.get("registrant_email"),
                country=parsed_data.get("registrant_country"),
            ))

        # Parse events
        events = {}
        for key, event_name in [("created", "registration"), ("expires", "expiration"), ("updated", "last changed")]:
            date_val = parsed_data.get(key)
            if date_val:
                if isinstance(date_val, datetime):
                    events[event_name] = date_val
                elif isinstance(date_val, str):
                    try:
                        events[event_name] = datetime.fromisoformat(date_val.replace("Z", "+00:00"))
                    except ValueError:
                        pass

        return RDAPResult(
            target=target,
            handle=parsed_data.get("handle"),
            domain_name=parsed_data.get("domain_name"),
            network_name=parsed_data.get("network_name") or parsed_data.get("name"),
            network_cidr=parsed_data.get("cidr"),
            network_type=parsed_data.get("type"),
            network_start=parsed_data.get("start_address"),
            network_end=parsed_data.get("end_address"),
            asn=int(parsed_data["asn"]) if parsed_data.get("asn") else None,
            asn_name=parsed_data.get("asn_name"),
            asn_country=parsed_data.get("asn_country") or parsed_data.get("country"),
            entities=entities,
            events=events,
            links=parsed_data.get("links", []),
            raw_data=parsed_data,
            scanned_at=datetime.utcnow(),
        )

    def _parse_rdap_result(self, target: str, result: Any) -> RDAPResult:
        """Parse RDAP result into structured data."""
        parser_output = result.parser_output if hasattr(result, 'parser_output') else {}
        raw_data = result.query_output if hasattr(result, 'query_output') else None

        # Extract network information (for IP lookups)
        network_name = parser_output.get("network_name")
        network_cidr = parser_output.get("cidr")

        # Try to get from raw data if not parsed
        if raw_data and isinstance(raw_data, dict):
            if not network_name:
                network_name = raw_data.get("name")
            if not network_cidr:
                network_cidr = raw_data.get("cidr0_cidrs", [{}])[0].get("v4prefix")

        # Extract ASN information
        asn = parser_output.get("asn")
        asn_name = parser_output.get("asn_name")
        asn_country = parser_output.get("asn_country")

        # Extract entities
        entities = []
        raw_entities = parser_output.get("entities", [])
        for entity in raw_entities:
            if isinstance(entity, dict):
                contact = ContactInfo(
                    name=entity.get("name"),
                    organization=entity.get("organization"),
                    email=entity.get("email"),
                    phone=entity.get("phone"),
                )
                entities.append(contact)

        # Extract events
        events = {}
        raw_events = parser_output.get("events", {})
        if isinstance(raw_events, dict):
            for event_type, date in raw_events.items():
                if isinstance(date, datetime):
                    events[event_type] = date

        return RDAPResult(
            target=target,
            handle=parser_output.get("handle"),
            domain_name=parser_output.get("domain_name"),
            network_name=network_name,
            network_cidr=network_cidr,
            network_type=parser_output.get("network_type"),
            network_start=parser_output.get("start_address"),
            network_end=parser_output.get("end_address"),
            asn=int(asn) if asn else None,
            asn_name=asn_name,
            asn_country=asn_country,
            entities=entities,
            events=events,
            links=parser_output.get("links", []),
            raw_data=raw_data if isinstance(raw_data, dict) else None,
            scanned_at=datetime.utcnow(),
        )

    def _parse_rdap_json(self, target: str, data: dict) -> RDAPResult:
        """Parse raw RDAP JSON response."""
        # Extract handle
        handle = data.get("handle")

        # Extract domain name (for domain queries)
        domain_name = data.get("ldhName") or data.get("unicodeName")

        # Extract network information (for IP queries)
        network_name = data.get("name")
        network_cidr = None
        network_start = data.get("startAddress")
        network_end = data.get("endAddress")

        # Try to get CIDR from cidr0_cidrs
        cidr_list = data.get("cidr0_cidrs", [])
        if cidr_list:
            first_cidr = cidr_list[0]
            v4prefix = first_cidr.get("v4prefix")
            length = first_cidr.get("length")
            if v4prefix and length:
                network_cidr = f"{v4prefix}/{length}"

        # Extract entities and contacts
        entities = []
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
            contact = self._parse_vcard(vcard)
            if contact:
                entities.append(contact)

        # Extract events
        events = {}
        for event in data.get("events", []):
            event_action = event.get("eventAction")
            event_date = event.get("eventDate")
            if event_action and event_date:
                try:
                    events[event_action] = datetime.fromisoformat(
                        event_date.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

        # Extract links
        links = [link.get("href") for link in data.get("links", []) if link.get("href")]

        return RDAPResult(
            target=target,
            handle=handle,
            domain_name=domain_name,
            network_name=network_name,
            network_cidr=network_cidr,
            network_type=data.get("type"),
            network_start=network_start,
            network_end=network_end,
            asn=None,  # ASN requires separate lookup
            asn_name=None,
            asn_country=data.get("country"),
            entities=entities,
            events=events,
            links=links,
            raw_data=data,
            scanned_at=datetime.utcnow(),
        )

    def _parse_vcard(self, vcard: list) -> ContactInfo | None:
        """Parse vCard array to ContactInfo."""
        if not vcard:
            return None

        name = None
        org = None
        email = None
        phone = None
        address = None

        for item in vcard:
            if not isinstance(item, list) or len(item) < 4:
                continue

            prop_name = item[0]
            prop_value = item[3]

            if prop_name == "fn":
                name = prop_value
            elif prop_name == "org":
                org = prop_value if isinstance(prop_value, str) else prop_value[0] if prop_value else None
            elif prop_name == "email":
                email = prop_value
            elif prop_name == "tel":
                phone = prop_value
            elif prop_name == "adr":
                if isinstance(prop_value, list):
                    address = ", ".join(str(v) for v in prop_value if v)

        if not name and not org:
            return None

        return ContactInfo(
            name=name,
            organization=org,
            email=email,
            phone=phone,
            address=address,
        )
