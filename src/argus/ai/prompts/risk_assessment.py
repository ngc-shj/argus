"""Risk assessment prompt template."""

RISK_ASSESSMENT_PROMPT = """You are a security analyst performing an attack surface assessment.

Analyze the following reconnaissance scan results and provide a comprehensive security assessment.

## Target Information
{context}

## Scan Results (JSON)
{results}

## Your Analysis Should Include:

1. **Executive Summary** (2-3 sentences)
   - Overall security posture
   - Most critical findings

2. **Critical Findings** (prioritized list)
   - Security vulnerabilities discovered
   - Misconfigurations identified
   - Information disclosure issues

3. **Risk Assessment**
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
"""
