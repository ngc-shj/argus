"""Base AI provider class."""

from abc import ABC, abstractmethod
from typing import Any

from argus.core.interfaces import IAIProvider


class BaseAIProvider(IAIProvider, ABC):
    """Base class for AI providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        ...

    @abstractmethod
    async def analyze(
        self,
        scan_results: dict[str, Any],
        prompt_template: str,
        language: str = "English",
    ) -> str:
        """Run AI analysis on scan results."""
        ...

    @abstractmethod
    async def summarize(
        self, text: str, max_length: int = 500, language: str = "English"
    ) -> str:
        """Generate a summary of the provided text."""
        ...

    @abstractmethod
    async def assess_risk(
        self,
        scan_results: dict[str, Any],
        language: str = "English",
    ) -> dict[str, Any]:
        """Assess security risks from scan results."""
        ...

    def _build_scan_context(self, scan_results: dict[str, Any]) -> str:
        """Build context string from scan results."""
        parts = []

        if dns := scan_results.get("dns"):
            parts.append(f"DNS Records: {dns.get('total_records', 0)}")
            parts.append(f"Subdomains: {len(dns.get('subdomains', []))}")

        if whois := scan_results.get("whois"):
            if whois.get("registrar"):
                parts.append(f"Registrar: {whois['registrar'].get('name', 'Unknown')}")
            if whois.get("expiration_date"):
                parts.append(f"Expiration: {whois['expiration_date']}")

        if ports := scan_results.get("ports"):
            open_count = len([p for p in ports.get("ports", []) if p.get("state") == "open"])
            parts.append(f"Open Ports: {open_count}")

        if webtech := scan_results.get("webtech"):
            techs = [t.get("name") for t in webtech.get("technologies", [])]
            if techs:
                parts.append(f"Technologies: {', '.join(techs[:5])}")

        return "\n".join(parts)
