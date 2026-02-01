"""OpenAI GPT AI provider."""

import json
from typing import Any

from argus.ai.base import BaseAIProvider
from argus.core.config import get_settings
from argus.core.exceptions import AIProviderError


class OpenAIProvider(BaseAIProvider):
    """OpenAI GPT AI provider."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None

    @property
    def name(self) -> str:
        return "openai"

    def _get_client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI

                api_key = self.settings.get_openai_key()
                if not api_key:
                    raise AIProviderError(
                        "OPENAI_API_KEY not configured",
                        provider=self.name,
                    )

                self._client = AsyncOpenAI(api_key=api_key)
            except ImportError as e:
                raise AIProviderError(
                    "openai package not installed",
                    provider=self.name,
                ) from e

        return self._client

    async def analyze(
        self,
        scan_results: dict[str, Any],
        prompt_template: str,
        language: str = "English",
    ) -> str:
        """Run AI analysis using GPT."""
        client = self._get_client()

        context = self._build_scan_context(scan_results)
        prompt = prompt_template.format(
            context=context,
            results=json.dumps(scan_results, indent=2, default=str),
            language=language,
        )

        try:
            response = await client.chat.completions.create(
                model="gpt-4o",
                max_tokens=4096,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a security analyst. Analyze the provided scan results and provide insights. Respond in {language}.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )

            return response.choices[0].message.content or ""

        except Exception as e:
            raise AIProviderError(
                f"OpenAI analysis failed: {e}",
                provider=self.name,
            ) from e

    async def summarize(
        self, text: str, max_length: int = 500, language: str = "English"
    ) -> str:
        """Generate summary using GPT."""
        client = self._get_client()

        try:
            response = await client.chat.completions.create(
                model="gpt-4o",
                max_tokens=1024,
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a security analyst. Provide concise summaries in {language}.",
                    },
                    {
                        "role": "user",
                        "content": f"Summarize the following security scan results in {max_length} characters or less. Write in {language}:\n\n{text}",
                    },
                ],
            )

            content = response.choices[0].message.content or ""
            return content[:max_length]

        except Exception as e:
            raise AIProviderError(
                f"OpenAI summarization failed: {e}",
                provider=self.name,
            ) from e

    async def assess_risk(
        self,
        scan_results: dict[str, Any],
        language: str = "English",
    ) -> dict[str, Any]:
        """Assess risks using GPT."""
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
{json.dumps(scan_results, indent=2, default=str)}"""

        try:
            response = await client.chat.completions.create(
                model="gpt-4o",
                max_tokens=2048,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a security analyst. Return only valid JSON. Write text content in {language}.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )

            content = response.choices[0].message.content or "{}"
            return json.loads(content)

        except Exception as e:
            raise AIProviderError(
                f"OpenAI risk assessment failed: {e}",
                provider=self.name,
            ) from e
