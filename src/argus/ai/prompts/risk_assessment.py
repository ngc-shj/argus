"""Risk assessment prompt template."""

RISK_ASSESSMENT_PROMPT = """You are a security analyst performing an attack surface assessment.

Analyze the following reconnaissance scan results and provide a comprehensive security assessment.

## Target Information
{context}

## Scan Results (JSON)
{results}

## CRITICAL INSTRUCTIONS:

**ONLY analyze data that is actually present in the Scan Results above.**
- If a scan module result is null or missing, do NOT make assumptions about that category.
- If email_result is null/missing, do NOT claim SPF/DKIM/DMARC are misconfigured - they simply weren't scanned.
- If ssl_result is null/missing, do NOT make claims about SSL/TLS security.
- Base your findings ONLY on evidence in the provided data.
- Clearly distinguish between "not scanned" and "misconfigured".

## Your Analysis Should Include:

1. **Executive Summary** (2-3 sentences)
   - Overall security posture
   - Most critical findings

2. **Critical Findings** (prioritized list)
   - Security vulnerabilities discovered
   - Misconfigurations identified
   - Information disclosure issues

3. **Risk Assessment** (analyze only categories with available data)
   - DNS Security: Evaluate zone security, DNSSEC, subdomain exposure
   - Network Exposure: Open ports, exposed services, attack surface
   - Web Security: Missing headers, technology risks, version disclosure
   - Email Security: SPF/DKIM/DMARC configuration, MTA-STS, email spoofing risks
   - SSL/TLS Security: Certificate validity, protocol versions, cipher strength
   - Infrastructure: Registration issues, expiring domains, configuration problems

4. **Attack Vectors**
   - How could an attacker exploit these findings?
   - What are the potential attack chains?

5. **Recommendations** (actionable, prioritized)
   - Immediate actions needed
   - Short-term improvements
   - Long-term security enhancements

Focus on actionable insights. Be specific about risks and remediation steps.
Analyze the actual data provided in the Scan Results section above.

IMPORTANT: Provide your entire response in {language}.
"""
