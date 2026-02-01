"""Anthropic (Claude) AI provider."""

import json
from typing import Any

from argus.ai.base import BaseAIProvider
from argus.core.config import get_settings
from argus.core.exceptions import AIProviderError


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude AI provider."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None

    @property
    def name(self) -> str:
        return "anthropic"

    def _get_client(self):
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                import anthropic

                api_key = self.settings.get_anthropic_key()
                if not api_key:
                    raise AIProviderError(
                        "ANTHROPIC_API_KEY not configured",
                        provider=self.name,
                    )

                self._client = anthropic.AsyncAnthropic(api_key=api_key)
            except ImportError as e:
                raise AIProviderError(
                    "anthropic package not installed",
                    provider=self.name,
                ) from e

        return self._client

    async def analyze(
        self,
        scan_results: dict[str, Any],
        prompt_template: str,
        language: str = "English",
    ) -> str:
        """Run AI analysis using Claude."""
        client = self._get_client()

        context = self._build_scan_context(scan_results)
        prompt = prompt_template.format(
            context=context,
            results=json.dumps(scan_results, indent=2, default=str),
            language=language,
        )

        try:
            message = await client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )

            return message.content[0].text

        except Exception as e:
            raise AIProviderError(
                f"Claude analysis failed: {e}",
                provider=self.name,
            ) from e

    async def summarize(
        self, text: str, max_length: int = 500, language: str = "English"
    ) -> str:
        """Generate summary using Claude."""
        client = self._get_client()

        prompt = f"""Summarize the following security scan results in {max_length} characters or less.
Focus on the most critical findings and recommendations.

IMPORTANT: Write the summary in {language}.

{text}"""

        try:
            message = await client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )

            return message.content[0].text[:max_length]

        except Exception as e:
            raise AIProviderError(
                f"Claude summarization failed: {e}",
                provider=self.name,
            ) from e

    async def assess_risk(
        self,
        scan_results: dict[str, Any],
        language: str = "English",
    ) -> dict[str, Any]:
        """Assess risks using Claude."""
        client = self._get_client()

        prompt = f"""Analyze the following security scan results and provide a risk assessment.

Return a JSON object with the following structure:
{{
    "overall_score": <0-100>,
    "dns_security": <0-100>,
    "network_exposure": <0-100>,
    "web_security": <0-100>,
    "infrastructure": <0-100>,
    "critical_findings": ["finding1", "finding2"],
    "recommendations": ["rec1", "rec2"],
    "attack_vectors": ["vector1", "vector2"]
}}

IMPORTANT: Write all text values (critical_findings, recommendations, attack_vectors) in {language}.

Scan Results:
{json.dumps(scan_results, indent=2, default=str)}

Return ONLY the JSON object, no other text."""

        try:
            message = await client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )

            response_text = message.content[0].text

            # Extract JSON from response
            try:
                # Try to parse directly
                return json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code block
                import re
                json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
                if json_match:
                    return json.loads(json_match.group(1))
                raise

        except Exception as e:
            raise AIProviderError(
                f"Claude risk assessment failed: {e}",
                provider=self.name,
            ) from e
