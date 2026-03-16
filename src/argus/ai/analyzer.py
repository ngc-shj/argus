"""AI analysis orchestrator."""

from datetime import datetime
from typing import Literal

from argus.ai.base import BaseAIProvider
from argus.ai.prompts.risk_assessment import RISK_ASSESSMENT_PROMPT
from argus.ai.providers.anthropic import AnthropicProvider
from argus.ai.providers.ollama import OllamaProvider
from argus.ai.providers.openai import OpenAIProvider
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
            subdomain_data = self._build_subdomain_scan_data(session)
            prompt = RISK_ASSESSMENT_PROMPT.replace("{subdomain_scan_data}", subdomain_data)
            analysis_text = await provider.analyze(results, prompt, language=self._language)

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

    def _build_subdomain_scan_data(self, session: ScanSession) -> str:
        """Build subdomain scan summary for AI prompt with token limit protection."""
        results = session.subdomain_scan_results
        if not results:
            return "No subdomain scan data available."

        total = len(results)
        completed = sum(1 for r in results if r.status == "completed")
        failed = sum(1 for r in results if r.status == "failed")

        lines = [
            f"Total subdomains scanned: {total} (completed: {completed}, failed: {failed})",
            "",
        ]

        # Full detail for up to 5 subdomains
        detail_results = results[:5]
        for result in detail_results:
            lines.append(f"Subdomain: {result.domain}")
            lines.append(f"  Status: {result.status}")

            if result.resolved_ips:
                lines.append(f"  Resolved IPs: {', '.join(result.resolved_ips[:3])}")

            if result.ssl_result:
                ssl = result.ssl_result
                lines.append(f"  SSL Grade: {ssl.grade or 'N/A'}")
                lines.append(f"  SSL Enabled: {ssl.ssl_enabled}")
                if ssl.certificate and ssl.certificate.days_until_expiry is not None:
                    lines.append(f"  Cert Days Until Expiry: {ssl.certificate.days_until_expiry}")
                if ssl.vulnerabilities:
                    critical_high = [
                        v.name for v in ssl.vulnerabilities if v.severity in ("critical", "high")
                    ]
                    if critical_high:
                        issues = ", ".join(critical_high[:3])
                        lines.append(f"  SSL Issues (critical/high): {issues}")

            if result.headers_result:
                hdr = result.headers_result
                lines.append(f"  Headers Grade: {hdr.grade or 'N/A'}")
                lines.append(f"  Headers Score: {hdr.score}")
                if hdr.missing_headers:
                    missing = [h.header_name for h in hdr.missing_headers[:5]]
                    lines.append(f"  Missing Headers: {', '.join(missing)}")

            if result.port_result:
                lines.append(f"  Open Ports: {result.port_result.total_open}")
                high_risk = result.port_result.high_risk_ports
                if high_risk:
                    ports = ", ".join(str(p.port) for p in high_risk[:5])
                    lines.append(f"  High Risk Ports: {ports}")

            if result.error:
                lines.append(f"  Error: {result.error}")

            lines.append("")

        # Summary statistics for remaining subdomains
        remaining = results[5:]
        if remaining:
            ssl_grades: dict[str, int] = {}
            headers_grades: dict[str, int] = {}
            total_open_ports = 0
            ssl_issues_count = 0

            for r in remaining:
                if r.ssl_result and r.ssl_result.grade:
                    grade = r.ssl_result.grade
                    ssl_grades[grade] = ssl_grades.get(grade, 0) + 1
                if r.headers_result and r.headers_result.grade:
                    grade = r.headers_result.grade
                    headers_grades[grade] = headers_grades.get(grade, 0) + 1
                if r.port_result:
                    total_open_ports += r.port_result.total_open
                if r.ssl_result:
                    ssl_issues_count += len(
                        [
                            v
                            for v in r.ssl_result.vulnerabilities
                            if v.severity in ("critical", "high")
                        ]
                    )

            lines.append(f"Remaining {len(remaining)} subdomains (summary only):")
            if ssl_grades:
                grade_summary = ", ".join(f"{g}: {c}" for g, c in sorted(ssl_grades.items()))
                lines.append(f"  SSL Grades: {grade_summary}")
            if headers_grades:
                grade_summary = ", ".join(f"{g}: {c}" for g, c in sorted(headers_grades.items()))
                lines.append(f"  Headers Grades: {grade_summary}")
            lines.append(f"  Total Open Ports: {total_open_ports}")
            if ssl_issues_count:
                lines.append(f"  SSL Critical/High Issues: {ssl_issues_count}")

        return "\n".join(lines)

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
            results["certificate_transparency"] = session.crtsh_result.model_dump(mode="json")

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
