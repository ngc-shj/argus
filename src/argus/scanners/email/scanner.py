"""Email Security Scanner (SPF, DKIM, DMARC, MTA-STS, BIMI)."""

import asyncio
import re
import time
from datetime import datetime
from typing import Any

import dns.resolver

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.email import (
    BIMIRecord,
    DKIMRecord,
    DMARCRecord,
    EmailSecurityResult,
    MTASTSRecord,
    SPFRecord,
    TLSRPTRecord,
)
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


@ScannerRegistry.register
class EmailSecurityScanner(BaseScanner[EmailSecurityResult]):
    """Email security configuration scanner (SPF, DKIM, DMARC, etc.)."""

    # Common DKIM selectors to test
    COMMON_DKIM_SELECTORS = [
        "default", "google", "selector1", "selector2", "k1", "k2",
        "mail", "email", "dkim", "s1", "s2", "mx", "smtp",
        "mailjet", "mandrill", "amazonses", "sendgrid", "mailchimp",
        "mailgun", "postmark", "sparkpost", "ses",
    ]

    @property
    def name(self) -> str:
        return "email"

    @property
    def description(self) -> str:
        return "Email security analysis (SPF, DKIM, DMARC)"

    def get_capabilities(self) -> list[str]:
        return [
            "SPF record validation",
            "DKIM record discovery",
            "DMARC policy analysis",
            "MTA-STS checking",
            "TLS-RPT checking",
            "BIMI record checking",
            "MX record analysis",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate target for email scanning."""
        return target.domain is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> EmailSecurityResult:
        """Execute email security scan."""
        if not target.domain:
            raise ScanError("Domain is required for email scan", scanner=self.name)

        domain = target.domain
        start_time = time.time()

        self.logger.info("email_scan_started", target=domain)

        result = EmailSecurityResult(target=domain)

        # Run all checks concurrently
        tasks = [
            self._check_mx_records(domain),
            self._check_spf(domain),
            self._check_dmarc(domain),
            self._check_mta_sts(domain),
            self._check_tls_rpt(domain),
            self._check_bimi(domain),
        ]

        mx_result, spf, dmarc, mta_sts, tls_rpt, bimi = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        # Process results
        if not isinstance(mx_result, Exception):
            result.mx_records = mx_result
        else:
            self.logger.warning("mx_check_failed", error=str(mx_result))

        if not isinstance(spf, Exception):
            result.spf = spf
        else:
            self.logger.warning("spf_check_failed", error=str(spf))

        if not isinstance(dmarc, Exception):
            result.dmarc = dmarc
        else:
            self.logger.warning("dmarc_check_failed", error=str(dmarc))

        if not isinstance(mta_sts, Exception):
            result.mta_sts = mta_sts
        else:
            self.logger.debug("mta_sts_check_failed", error=str(mta_sts))

        if not isinstance(tls_rpt, Exception):
            result.tls_rpt = tls_rpt
        else:
            self.logger.debug("tls_rpt_check_failed", error=str(tls_rpt))

        if not isinstance(bimi, Exception):
            result.bimi = bimi
        else:
            self.logger.debug("bimi_check_failed", error=str(bimi))

        # Check DKIM with common selectors
        dkim_records = await self._check_dkim(domain)
        result.dkim_records = dkim_records

        # Calculate security score and issues
        result.security_score, result.security_grade = self._calculate_score(result)
        result.issues, result.recommendations = self._generate_recommendations(result)

        duration = time.time() - start_time
        self.logger.info(
            "email_scan_completed",
            target=domain,
            has_spf=result.has_spf,
            has_dkim=result.has_dkim,
            has_dmarc=result.has_dmarc,
            score=result.security_score,
            duration=duration,
        )

        return result

    async def _check_mx_records(self, domain: str) -> list[str]:
        """Get MX records for domain."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "MX")
            mx_records = []
            for rdata in answers:
                mx_records.append(str(rdata.exchange).rstrip("."))
            return sorted(mx_records, key=lambda x: x)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except Exception as e:
            self.logger.debug("mx_lookup_failed", domain=domain, error=str(e))
            return []

    async def _check_spf(self, domain: str) -> SPFRecord:
        """Check SPF record."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        record = SPFRecord()

        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    record.raw_record = txt
                    record = self._parse_spf(txt, record)
                    break
        except Exception as e:
            record.errors.append(f"SPF lookup failed: {e}")

        return record

    def _parse_spf(self, raw: str, record: SPFRecord) -> SPFRecord:
        """Parse SPF record."""
        record.is_valid = True
        parts = raw.split()

        if parts[0] == "v=spf1":
            record.version = "spf1"

        for part in parts[1:]:
            part_lower = part.lower()

            # Check for all mechanism
            if part_lower in ("+all", "-all", "~all", "?all"):
                record.all_mechanism = part_lower
                if part_lower == "+all":
                    record.allows_any_sender = True
                    record.warnings.append("SPF allows any sender (+all)")
                elif part_lower in ("-all", "~all"):
                    record.is_restrictive = True
            elif part_lower.startswith("include:"):
                record.includes.append(part[8:])
                record.mechanisms.append(part)
            elif part_lower.startswith("redirect="):
                record.mechanisms.append(part)
            else:
                record.mechanisms.append(part)

        # Check for too many DNS lookups
        lookup_count = len(record.includes)
        for mech in record.mechanisms:
            if any(mech.lower().startswith(p) for p in ["a:", "mx:", "ptr:", "exists:"]):
                lookup_count += 1
        if lookup_count > 10:
            record.too_many_lookups = True
            record.warnings.append(f"SPF may exceed 10 DNS lookup limit ({lookup_count} lookups)")

        return record

    async def _check_dkim(self, domain: str) -> list[DKIMRecord]:
        """Check DKIM records with common selectors."""
        records = []

        async def check_selector(selector: str) -> DKIMRecord | None:
            dkim_domain = f"{selector}._domainkey.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5

            try:
                answers = await asyncio.to_thread(resolver.resolve, dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"').replace('" "', "")
                    if "v=DKIM1" in txt or "k=" in txt or "p=" in txt:
                        record = DKIMRecord(selector=selector, raw_record=txt)
                        return self._parse_dkim(txt, record)
            except Exception:
                pass
            return None

        # Check selectors concurrently
        tasks = [check_selector(s) for s in self.COMMON_DKIM_SELECTORS]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result is not None:
                records.append(result)

        return records

    def _parse_dkim(self, raw: str, record: DKIMRecord) -> DKIMRecord:
        """Parse DKIM record."""
        record.is_valid = True

        # Parse key-value pairs
        parts = raw.replace(" ", "").split(";")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "v":
                    record.version = value
                elif key == "k":
                    record.key_type = value
                elif key == "p":
                    record.public_key = value
                    if value:
                        # Estimate key size (base64 encoded)
                        key_bits = len(value) * 6 // 8 * 8
                        record.key_size = key_bits
                        if key_bits < 1024:
                            record.key_strength = "weak"
                            record.warnings.append(f"DKIM key is weak ({key_bits} bits)")
                        elif key_bits < 2048:
                            record.key_strength = "acceptable"
                        else:
                            record.key_strength = "strong"
                elif key == "h":
                    record.hash_algorithms = value.split(":")
                elif key == "s":
                    record.service_type = value
                elif key == "t":
                    record.flags = value.split(":")

        return record

    async def _check_dmarc(self, domain: str) -> DMARCRecord:
        """Check DMARC record."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        record = DMARCRecord()
        dmarc_domain = f"_dmarc.{domain}"

        try:
            answers = await asyncio.to_thread(resolver.resolve, dmarc_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"').replace('" "', "")
                if txt.startswith("v=DMARC1"):
                    record.raw_record = txt
                    record = self._parse_dmarc(txt, record)
                    break
        except Exception as e:
            record.errors.append(f"DMARC lookup failed: {e}")

        return record

    def _parse_dmarc(self, raw: str, record: DMARCRecord) -> DMARCRecord:
        """Parse DMARC record."""
        record.is_valid = True

        parts = raw.replace(" ", "").split(";")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "v":
                    record.version = value
                elif key == "p":
                    if value.lower() in ("none", "quarantine", "reject"):
                        record.policy = value.lower()  # type: ignore
                        if value.lower() in ("quarantine", "reject"):
                            record.is_enforcing = True
                elif key == "sp":
                    if value.lower() in ("none", "quarantine", "reject"):
                        record.subdomain_policy = value.lower()  # type: ignore
                elif key == "pct":
                    try:
                        record.percentage = int(value)
                    except ValueError:
                        pass
                elif key == "rua":
                    record.rua = [uri.strip() for uri in value.split(",")]
                elif key == "ruf":
                    record.ruf = [uri.strip() for uri in value.split(",")]
                elif key == "aspf":
                    if value.lower() in ("r", "s"):
                        record.aspf = value.lower()  # type: ignore
                elif key == "adkim":
                    if value.lower() in ("r", "s"):
                        record.adkim = value.lower()  # type: ignore
                elif key == "ri":
                    try:
                        record.report_interval = int(value)
                    except ValueError:
                        pass
                elif key == "rf":
                    record.report_format = value

        # Warnings
        if record.policy == "none":
            record.warnings.append("DMARC policy is set to 'none' (monitoring only)")
        if record.percentage < 100:
            record.warnings.append(f"DMARC policy applies to only {record.percentage}% of messages")
        if not record.rua:
            record.warnings.append("No aggregate report URI (rua) configured")

        return record

    async def _check_mta_sts(self, domain: str) -> MTASTSRecord:
        """Check MTA-STS record and policy."""
        import httpx

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        record = MTASTSRecord()
        mta_sts_domain = f"_mta-sts.{domain}"

        try:
            # Check DNS record
            answers = await asyncio.to_thread(resolver.resolve, mta_sts_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=STSv1" in txt:
                    parts = txt.split(";")
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            key = key.strip().lower()
                            value = value.strip()
                            if key == "v":
                                record.version = value
                            elif key == "id":
                                record.id = value
                    record.is_valid = True
                    break
        except Exception:
            pass

        # Fetch policy file if DNS record exists
        if record.is_valid:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(
                        f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                    )
                    if response.status_code == 200:
                        for line in response.text.split("\n"):
                            line = line.strip()
                            if ":" in line:
                                key, value = line.split(":", 1)
                                key = key.strip().lower()
                                value = value.strip()
                                if key == "mode":
                                    if value in ("enforce", "testing", "none"):
                                        record.policy_mode = value  # type: ignore
                                elif key == "mx":
                                    record.policy_mx.append(value)
                                elif key == "max_age":
                                    try:
                                        record.policy_max_age = int(value)
                                    except ValueError:
                                        pass
            except Exception as e:
                record.errors.append(f"Failed to fetch MTA-STS policy: {e}")

        return record

    async def _check_tls_rpt(self, domain: str) -> TLSRPTRecord:
        """Check TLS-RPT record."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        record = TLSRPTRecord()
        tls_rpt_domain = f"_smtp._tls.{domain}"

        try:
            answers = await asyncio.to_thread(resolver.resolve, tls_rpt_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=TLSRPTv1" in txt:
                    parts = txt.split(";")
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            key = key.strip().lower()
                            value = value.strip()
                            if key == "v":
                                record.version = value
                            elif key == "rua":
                                record.rua = [uri.strip() for uri in value.split(",")]
                    record.is_valid = True
                    break
        except Exception:
            pass

        return record

    async def _check_bimi(self, domain: str) -> BIMIRecord:
        """Check BIMI record."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        record = BIMIRecord()
        bimi_domain = f"default._bimi.{domain}"

        try:
            answers = await asyncio.to_thread(resolver.resolve, bimi_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=BIMI1" in txt:
                    parts = txt.split(";")
                    for part in parts:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            key = key.strip().lower()
                            value = value.strip()
                            if key == "v":
                                record.version = value
                            elif key == "l":
                                record.location = value
                            elif key == "a":
                                record.authority = value
                    record.is_valid = True
                    break
        except Exception:
            pass

        return record

    def _calculate_score(self, result: EmailSecurityResult) -> tuple[int, str]:
        """Calculate email security score (0-100)."""
        score = 0

        # SPF (max 25 points)
        if result.has_spf:
            score += 15
            if result.spf and result.spf.is_restrictive:
                score += 10

        # DKIM (max 25 points)
        if result.has_dkim:
            score += 15
            strong_keys = len([d for d in result.dkim_records if d.key_strength == "strong"])
            if strong_keys > 0:
                score += 10

        # DMARC (max 30 points)
        if result.has_dmarc:
            score += 15
            if result.is_dmarc_enforcing:
                score += 15

        # Additional protocols (max 20 points)
        if result.mta_sts and result.mta_sts.is_valid:
            score += 10
            if result.mta_sts.policy_mode == "enforce":
                score += 5

        if result.tls_rpt and result.tls_rpt.is_valid:
            score += 5

        # Calculate grade
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 25:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _generate_recommendations(
        self, result: EmailSecurityResult
    ) -> tuple[list[str], list[str]]:
        """Generate issues and recommendations."""
        issues = []
        recommendations = []

        if not result.has_spf:
            issues.append("No SPF record found")
            recommendations.append("Add an SPF record to prevent email spoofing")
        elif result.spf and result.spf.allows_any_sender:
            issues.append("SPF allows any sender (+all)")
            recommendations.append("Change SPF to use -all or ~all")

        if not result.has_dkim:
            issues.append("No DKIM records found")
            recommendations.append("Configure DKIM signing for your email")
        else:
            weak_keys = [d for d in result.dkim_records if d.key_strength == "weak"]
            if weak_keys:
                issues.append(f"{len(weak_keys)} DKIM key(s) are weak")
                recommendations.append("Upgrade DKIM keys to at least 2048 bits")

        if not result.has_dmarc:
            issues.append("No DMARC record found")
            recommendations.append("Add a DMARC record to protect against spoofing")
        elif not result.is_dmarc_enforcing:
            issues.append("DMARC policy is not enforcing")
            recommendations.append("Change DMARC policy to 'quarantine' or 'reject'")

        if not result.mta_sts or not result.mta_sts.is_valid:
            recommendations.append("Consider implementing MTA-STS for encrypted mail delivery")

        if not result.tls_rpt or not result.tls_rpt.is_valid:
            recommendations.append("Consider implementing TLS-RPT for delivery monitoring")

        return issues, recommendations
