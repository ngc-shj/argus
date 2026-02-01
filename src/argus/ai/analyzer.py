"""AI analysis orchestrator."""

from datetime import datetime
from typing import Literal

from argus.ai.base import BaseAIProvider
from argus.ai.providers.anthropic import AnthropicProvider
from argus.ai.providers.openai import OpenAIProvider
from argus.ai.providers.ollama import OllamaProvider
from argus.ai.prompts.risk_assessment import RISK_ASSESSMENT_PROMPT
from argus.core.exceptions import AIProviderError
from argus.core.logging import get_logger
from argus.models import ScanSession
from argus.models.report import AIAnalysisResult, Finding, RiskScore, Severity


class AIAnalyzer:
    """Orchestrates AI analysis of scan results."""

    # Language code to full name mapping
    LANGUAGE_MAP = {
        "en": "English",
        "ja": "Japanese",
        "zh": "Chinese",
        "ko": "Korean",
        "es": "Spanish",
        "fr": "French",
        "de": "German",
        "pt": "Portuguese",
        "ru": "Russian",
        "ar": "Arabic",
    }

    def __init__(
        self,
        provider: Literal["anthropic", "openai", "ollama"] = "anthropic",
        language: str = "en",
    ) -> None:
        self.logger = get_logger("ai_analyzer")
        self._provider_name = provider
        self._provider: BaseAIProvider | None = None
        self._language = self.LANGUAGE_MAP.get(language, language)

    def _get_provider(self) -> BaseAIProvider:
        """Get or create the AI provider."""
        if self._provider is None:
            if self._provider_name == "anthropic":
                self._provider = AnthropicProvider()
            elif self._provider_name == "openai":
                self._provider = OpenAIProvider()
            elif self._provider_name == "ollama":
                self._provider = OllamaProvider()
            else:
                raise AIProviderError(
                    f"Unknown provider: {self._provider_name}",
                    provider=self._provider_name,
                )

        return self._provider

    async def analyze_session(self, session: ScanSession) -> AIAnalysisResult:
        """Analyze a complete scan session."""
        self.logger.info(
            "ai_analysis_started",
            scan_id=str(session.id),
            provider=self._provider_name,
        )

        provider = self._get_provider()

        # Build results dictionary
        results = self._build_results_dict(session)

        try:
            # Get risk assessment
            risk_data = await provider.assess_risk(results, language=self._language)

            # Get detailed analysis
            analysis_text = await provider.analyze(
                results, RISK_ASSESSMENT_PROMPT, language=self._language
            )

            # Get summary
            summary = await provider.summarize(
                analysis_text, max_length=500, language=self._language
            )

            # Build findings from analysis
            findings = self._extract_findings(risk_data)

            # Build risk score
            risk_score = RiskScore(
                overall=risk_data.get("overall_score", 0),
                dns_security=risk_data.get("dns_security", 0),
                network_exposure=risk_data.get("network_exposure", 0),
                web_security=risk_data.get("web_security", 0),
                infrastructure=risk_data.get("infrastructure", 0),
            )

            result = AIAnalysisResult(
                summary=summary,
                key_findings=risk_data.get("critical_findings", []),
                risk_score=risk_score,
                findings=findings,
                attack_vectors=risk_data.get("attack_vectors", []),
                recommendations=risk_data.get("recommendations", []),
                executive_summary=summary,
                technical_details=analysis_text,
                analyzed_at=datetime.utcnow(),
                model_used=self._get_model_name(),
                provider=self._provider_name,
                confidence=0.85,  # Could be dynamically determined
            )

            self.logger.info(
                "ai_analysis_completed",
                scan_id=str(session.id),
                risk_score=risk_score.overall,
            )

            return result

        except Exception as e:
            self.logger.error(
                "ai_analysis_failed",
                scan_id=str(session.id),
                error=str(e),
            )
            raise

    def _build_results_dict(self, session: ScanSession) -> dict:
        """Build results dictionary from session."""
        results = {}

        if session.dns_result:
            results["dns"] = session.dns_result.model_dump(mode="json")

        if session.whois_result:
            results["whois"] = session.whois_result.model_dump(mode="json")

        if session.rdap_result:
            results["rdap"] = session.rdap_result.model_dump(mode="json")

        if session.port_result:
            results["ports"] = session.port_result.model_dump(mode="json")

        if session.webtech_result:
            results["webtech"] = session.webtech_result.model_dump(mode="json")

        if session.ssl_result:
            results["ssl"] = session.ssl_result.model_dump(mode="json")

        if session.email_result:
            results["email"] = session.email_result.model_dump(mode="json")

        if session.security_result:
            results["security"] = session.security_result.model_dump(mode="json")

        if session.headers_result:
            results["headers"] = session.headers_result.model_dump(mode="json")

        if session.vuln_result:
            results["vulnerabilities"] = session.vuln_result.model_dump(mode="json")

        if session.crtsh_result:
            results["certificate_transparency"] = session.crtsh_result.model_dump(
                mode="json"
            )

        if session.discovery_result:
            results["discovery"] = session.discovery_result.model_dump(mode="json")

        if session.favicon_result:
            results["favicon"] = session.favicon_result.model_dump(mode="json")

        if session.asn_result:
            results["asn"] = session.asn_result.model_dump(mode="json")

        if session.wayback_result:
            results["wayback"] = session.wayback_result.model_dump(mode="json")

        if session.graphql_result:
            results["graphql"] = session.graphql_result.model_dump(mode="json")

        if session.kev_matches:
            results["kev_matches"] = session.kev_matches

        if session.takeover_results:
            results["takeover"] = session.takeover_results

        if session.js_analysis:
            results["js_analysis"] = session.js_analysis

        if session.subdomain_enum:
            results["subdomain_enumeration"] = session.subdomain_enum

        return results

    def _extract_findings(self, risk_data: dict) -> list[Finding]:
        """Extract findings from risk assessment data."""
        findings = []

        for finding_text in risk_data.get("critical_findings", []):
            # Determine severity based on keywords
            severity = Severity.MEDIUM
            text_lower = finding_text.lower()

            if any(w in text_lower for w in ["critical", "severe", "urgent"]):
                severity = Severity.CRITICAL
            elif any(w in text_lower for w in ["high", "important", "significant"]):
                severity = Severity.HIGH
            elif any(w in text_lower for w in ["low", "minor", "informational"]):
                severity = Severity.LOW

            # Determine category
            category = "infrastructure"
            if any(w in text_lower for w in ["dns", "subdomain", "nameserver"]):
                category = "dns"
            elif any(w in text_lower for w in ["port", "service", "network"]):
                category = "network"
            elif any(w in text_lower for w in ["web", "http", "header", "ssl"]):
                category = "web"

            findings.append(
                Finding(
                    title=finding_text[:100],
                    description=finding_text,
                    severity=severity,
                    category=category,
                    affected_asset="target",
                )
            )

        return findings

    def _get_model_name(self) -> str:
        """Get the model name for the current provider."""
        if self._provider_name == "anthropic":
            return "claude-sonnet-4-20250514"
        elif self._provider_name == "openai":
            return "gpt-4o"
        elif self._provider_name == "ollama":
            from argus.core.config import get_settings

            return get_settings().ollama_model
        return "unknown"
