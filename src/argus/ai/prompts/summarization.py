"""Summarization prompt template."""

SUMMARIZATION_PROMPT = """Summarize the following security scan analysis for an executive audience.

Focus on:
- Overall risk level (Critical/High/Medium/Low)
- Top 3 most important findings
- Key recommended actions

Keep the summary concise (under {max_length} characters).

Analysis to summarize:
{text}
"""
