"""Ollama local LLM provider."""

import json
from typing import Any

from argus.ai.base import BaseAIProvider
from argus.core.config import get_settings
from argus.core.exceptions import AIProviderError


class OllamaProvider(BaseAIProvider):
    """Ollama local LLM provider for privacy-focused analysis."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None

    @property
    def name(self) -> str:
        return "ollama"

    def _get_client(self):
        """Get or create Ollama client."""
        if self._client is None:
            try:
                from ollama import AsyncClient

                self._client = AsyncClient(host=self.settings.ollama_host)
            except ImportError as e:
                raise AIProviderError(
                    "ollama package not installed. Install with: pip install ollama",
                    provider=self.name,
                ) from e

        return self._client

    async def analyze(
        self,
        scan_results: dict[str, Any],
        prompt_template: str,
    ) -> str:
        """Run AI analysis using local Ollama model."""
        client = self._get_client()

        context = self._build_scan_context(scan_results)
        prompt = prompt_template.format(
            context=context,
            results=json.dumps(scan_results, indent=2, default=str),
        )

        try:
            response = await client.chat(
                model=self.settings.ollama_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security analyst. Analyze the provided scan results and provide insights. Be concise and focus on actionable findings.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )

            return response["message"]["content"]

        except Exception as e:
            raise AIProviderError(
                f"Ollama analysis failed: {e}. Make sure Ollama is running at {self.settings.ollama_host}",
                provider=self.name,
            ) from e

    async def summarize(self, text: str, max_length: int = 500) -> str:
        """Generate summary using local Ollama model."""
        client = self._get_client()

        try:
            response = await client.chat(
                model=self.settings.ollama_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security analyst. Provide concise summaries focused on critical findings.",
                    },
                    {
                        "role": "user",
                        "content": f"Summarize the following security scan results in {max_length} characters or less. Focus on the most critical findings:\n\n{text}",
                    },
                ],
            )

            content = response["message"]["content"]
            return content[:max_length]

        except Exception as e:
            raise AIProviderError(
                f"Ollama summarization failed: {e}",
                provider=self.name,
            ) from e

    async def assess_risk(
        self,
        scan_results: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess risks using local Ollama model."""
        client = self._get_client()

        prompt = f"""Analyze the following security scan results and provide a risk assessment.

Return ONLY a valid JSON object with exactly this structure (no markdown, no explanation):
{{
    "overall_score": <number 0-100>,
    "dns_security": <number 0-100>,
    "network_exposure": <number 0-100>,
    "web_security": <number 0-100>,
    "infrastructure": <number 0-100>,
    "critical_findings": ["finding1", "finding2"],
    "recommendations": ["rec1", "rec2"],
    "attack_vectors": ["vector1", "vector2"]
}}

Higher scores mean higher risk.

Scan Results:
{json.dumps(scan_results, indent=2, default=str)}

IMPORTANT: Return ONLY the JSON object, no other text or markdown."""

        try:
            response = await client.chat(
                model=self.settings.ollama_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security analyst. Return only valid JSON with no additional text or markdown formatting.",
                    },
                    {"role": "user", "content": prompt},
                ],
            )

            content = response["message"]["content"]

            # Try to parse JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                import re

                # Remove markdown code blocks if present
                content = re.sub(r"```(?:json)?\s*", "", content)
                content = re.sub(r"```", "", content)
                content = content.strip()

                # Try parsing again
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Return default structure if parsing fails
                    return {
                        "overall_score": 50,
                        "dns_security": 50,
                        "network_exposure": 50,
                        "web_security": 50,
                        "infrastructure": 50,
                        "critical_findings": ["Analysis parsing failed"],
                        "recommendations": ["Re-run analysis with different model"],
                        "attack_vectors": [],
                    }

        except Exception as e:
            raise AIProviderError(
                f"Ollama risk assessment failed: {e}. Make sure Ollama is running and model '{self.settings.ollama_model}' is available.",
                provider=self.name,
            ) from e
