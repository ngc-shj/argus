"""SSL/TLS Certificate Scanner implementation."""

import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone

from argus.core.config import get_settings
from argus.core.exceptions import ScanError
from argus.models import ScanTarget, ScanOptions
from argus.models.ssl import (
    CertificateInfo,
    SSLScanResult,
    SSLVulnerability,
    TLSInfo,
)
from argus.scanners.base import BaseScanner
from argus.scanners.registry import ScannerRegistry


@ScannerRegistry.register
class SSLScanner(BaseScanner[SSLScanResult]):
    """SSL/TLS Certificate and configuration scanner."""

    # Weak cipher suites patterns
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"
    ]

    @property
    def name(self) -> str:
        return "ssl"

    @property
    def description(self) -> str:
        return "SSL/TLS certificate and configuration analysis"

    def get_capabilities(self) -> list[str]:
        return [
            "Certificate analysis",
            "TLS version detection",
            "Cipher suite analysis",
            "Certificate chain validation",
            "Expiration checking",
            "Security grading",
        ]

    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate target for SSL scanning."""
        return target.domain is not None

    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> SSLScanResult:
        """Execute SSL/TLS scan."""
        if not target.domain:
            raise ScanError("Domain is required for SSL scan", scanner=self.name)

        hostname = target.domain
        port = 443
        start_time = time.time()

        self.logger.info("ssl_scan_started", target=hostname, port=port)

        result = SSLScanResult(
            target=hostname,
            port=port,
            hostname=hostname,
        )

        try:
            # Get certificate and connection info
            cert_info, tls_info = await self._get_ssl_info(hostname, port)
            result.ssl_enabled = True
            result.certificate = cert_info
            result.tls_info = tls_info

            # Check for vulnerabilities
            result.vulnerabilities = self._check_vulnerabilities(cert_info, tls_info)

            # Calculate grade
            result.grade, result.grade_reasons = self._calculate_grade(
                cert_info, tls_info, result.vulnerabilities
            )

            # Add warnings
            result.warnings = self._generate_warnings(cert_info, tls_info)

        except ssl.SSLError as e:
            result.ssl_enabled = False
            result.connection_error = f"SSL error: {e}"
            self.logger.warning("ssl_error", target=hostname, error=str(e))
        except socket.error as e:
            result.ssl_enabled = False
            result.connection_error = f"Connection error: {e}"
            self.logger.warning("connection_error", target=hostname, error=str(e))
        except Exception as e:
            result.connection_error = f"Unexpected error: {e}"
            self.logger.error("ssl_scan_error", target=hostname, error=str(e))

        duration = time.time() - start_time
        self.logger.info(
            "ssl_scan_completed",
            target=hostname,
            ssl_enabled=result.ssl_enabled,
            grade=result.grade,
            duration=duration,
        )

        return result

    async def _get_ssl_info(
        self, hostname: str, port: int
    ) -> tuple[CertificateInfo, TLSInfo]:
        """Get SSL certificate and TLS information."""
        import asyncio

        settings = get_settings()

        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        def get_cert_info():
            with socket.create_connection(
                (hostname, port), timeout=settings.http_timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return cert, cert_bin, cipher, version

        cert, cert_bin, cipher, version = await asyncio.to_thread(get_cert_info)

        # Parse certificate
        cert_info = self._parse_certificate(cert, cert_bin, hostname)

        # Parse TLS info
        tls_info = self._parse_tls_info(cipher, version)

        # Test protocol support
        tls_info = await self._test_protocol_support(hostname, port, tls_info)

        return cert_info, tls_info

    def _parse_certificate(
        self, cert: dict, cert_bin: bytes, hostname: str
    ) -> CertificateInfo:
        """Parse certificate information."""
        # Subject
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                subject_parts.append(f"{key}={value}")
        subject = ", ".join(subject_parts)

        # Issuer
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for key, value in rdn:
                issuer_parts.append(f"{key}={value}")
        issuer = ", ".join(issuer_parts)

        # Validity dates
        not_before = None
        not_after = None
        if cert.get("notBefore"):
            not_before = datetime.strptime(
                cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
        if cert.get("notAfter"):
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

        # Check expiration
        now = datetime.now(timezone.utc)
        is_expired = not_after < now if not_after else False
        days_until_expiry = None
        if not_after:
            delta = not_after - now
            days_until_expiry = delta.days

        # Subject Alternative Names
        san_domains = []
        san_ips = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_domains.append(san_value)
            elif san_type == "IP Address":
                san_ips.append(san_value)

        # Fingerprints
        fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest().upper()
        fingerprint_sha1 = hashlib.sha1(cert_bin).hexdigest().upper()

        # Check if self-signed
        is_self_signed = subject == issuer

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=cert.get("serialNumber"),
            version=cert.get("version"),
            not_before=not_before,
            not_after=not_after,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            san_domains=san_domains,
            san_ips=san_ips,
            fingerprint_sha256=fingerprint_sha256,
            fingerprint_sha1=fingerprint_sha1,
            is_self_signed=is_self_signed,
        )

    def _parse_tls_info(self, cipher: tuple, version: str) -> TLSInfo:
        """Parse TLS connection information."""
        cipher_name = cipher[0] if cipher else None
        cipher_version = cipher[1] if cipher and len(cipher) > 1 else None
        cipher_bits = cipher[2] if cipher and len(cipher) > 2 else None

        return TLSInfo(
            protocol_version=version,
            cipher_suite=cipher_name,
            cipher_bits=cipher_bits,
        )

    async def _test_protocol_support(
        self, hostname: str, port: int, tls_info: TLSInfo
    ) -> TLSInfo:
        """Test support for various TLS/SSL versions."""
        import asyncio

        protocols = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "supports_tls13"),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "supports_tls12"),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "supports_tls11"),
            ("TLSv1.0", ssl.TLSVersion.TLSv1, "supports_tls10"),
        ]

        for name, version, attr in protocols:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = version
                context.maximum_version = version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                def test_version():
                    try:
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname):
                                return True
                    except Exception:
                        return False

                supported = await asyncio.to_thread(test_version)
                setattr(tls_info, attr, supported)
            except Exception:
                setattr(tls_info, attr, False)

        return tls_info

    def _check_vulnerabilities(
        self, cert: CertificateInfo, tls: TLSInfo
    ) -> list[SSLVulnerability]:
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []

        # Certificate issues
        if cert.is_expired:
            vulnerabilities.append(
                SSLVulnerability(
                    name="Expired Certificate",
                    severity="critical",
                    description="The SSL certificate has expired",
                    recommendation="Renew the certificate immediately",
                )
            )

        if cert.is_self_signed:
            vulnerabilities.append(
                SSLVulnerability(
                    name="Self-Signed Certificate",
                    severity="high",
                    description="Certificate is self-signed and not trusted by default",
                    recommendation="Use a certificate from a trusted CA",
                )
            )

        if cert.days_until_expiry and cert.days_until_expiry <= 30:
            vulnerabilities.append(
                SSLVulnerability(
                    name="Certificate Expiring Soon",
                    severity="medium",
                    description=f"Certificate expires in {cert.days_until_expiry} days",
                    recommendation="Renew the certificate before expiration",
                )
            )

        # Protocol issues
        if tls.supports_ssl2 or tls.supports_ssl3:
            vulnerabilities.append(
                SSLVulnerability(
                    name="Insecure Protocol Support",
                    severity="critical",
                    description="Server supports deprecated SSL 2.0 or SSL 3.0",
                    recommendation="Disable SSL 2.0 and SSL 3.0",
                )
            )

        if tls.supports_tls10:
            vulnerabilities.append(
                SSLVulnerability(
                    name="TLS 1.0 Supported",
                    severity="medium",
                    description="Server supports deprecated TLS 1.0",
                    recommendation="Disable TLS 1.0 and use TLS 1.2 or higher",
                )
            )

        if tls.supports_tls11:
            vulnerabilities.append(
                SSLVulnerability(
                    name="TLS 1.1 Supported",
                    severity="low",
                    description="Server supports deprecated TLS 1.1",
                    recommendation="Disable TLS 1.1 and use TLS 1.2 or higher",
                )
            )

        if not tls.supports_tls12 and not tls.supports_tls13:
            vulnerabilities.append(
                SSLVulnerability(
                    name="No Modern TLS Support",
                    severity="high",
                    description="Server does not support TLS 1.2 or TLS 1.3",
                    recommendation="Enable TLS 1.2 and/or TLS 1.3",
                )
            )

        # Cipher issues
        if tls.cipher_suite:
            for weak in self.WEAK_CIPHERS:
                if weak.upper() in tls.cipher_suite.upper():
                    vulnerabilities.append(
                        SSLVulnerability(
                            name="Weak Cipher Suite",
                            severity="high",
                            description=f"Weak cipher in use: {tls.cipher_suite}",
                            recommendation="Configure server to use strong cipher suites",
                        )
                    )
                    break

        if tls.cipher_bits and tls.cipher_bits < 128:
            vulnerabilities.append(
                SSLVulnerability(
                    name="Weak Encryption",
                    severity="high",
                    description=f"Cipher uses only {tls.cipher_bits} bits",
                    recommendation="Use ciphers with at least 128-bit encryption",
                )
            )

        return vulnerabilities

    def _calculate_grade(
        self,
        cert: CertificateInfo,
        tls: TLSInfo,
        vulnerabilities: list[SSLVulnerability],
    ) -> tuple[str, list[str]]:
        """Calculate SSL grade (A+, A, B, C, D, F, T)."""
        grade = "A"
        reasons = []

        # Critical issues -> F
        critical_count = len([v for v in vulnerabilities if v.severity == "critical"])
        if critical_count > 0:
            grade = "F"
            reasons.append(f"{critical_count} critical vulnerabilities")
            return grade, reasons

        # Trust issues -> T
        if cert.is_self_signed:
            grade = "T"
            reasons.append("Self-signed certificate")
            return grade, reasons

        # High issues -> C or D
        high_count = len([v for v in vulnerabilities if v.severity == "high"])
        if high_count >= 2:
            grade = "D"
            reasons.append(f"{high_count} high severity issues")
        elif high_count == 1:
            grade = "C"
            reasons.append("1 high severity issue")

        # Medium issues -> B
        medium_count = len([v for v in vulnerabilities if v.severity == "medium"])
        if medium_count > 0 and grade == "A":
            grade = "B"
            reasons.append(f"{medium_count} medium severity issues")

        # Check for A+
        if grade == "A":
            if tls.supports_tls13 and not tls.supports_tls10 and not tls.supports_tls11:
                if tls.supports_hsts and tls.hsts_preload:
                    grade = "A+"
                    reasons.append("Excellent configuration with HSTS preload")
                else:
                    reasons.append("Good configuration")
            else:
                reasons.append("Minor improvements possible")

        return grade, reasons

    def _generate_warnings(
        self, cert: CertificateInfo, tls: TLSInfo
    ) -> list[str]:
        """Generate warnings for the certificate/TLS configuration."""
        warnings = []

        if cert.days_until_expiry:
            if cert.days_until_expiry <= 7:
                warnings.append(f"Certificate expires in {cert.days_until_expiry} days!")
            elif cert.days_until_expiry <= 30:
                warnings.append(f"Certificate expires in {cert.days_until_expiry} days")

        if not tls.supports_tls13:
            warnings.append("TLS 1.3 not supported - consider enabling for better security")

        if not tls.supports_hsts:
            warnings.append("HSTS not enabled - consider adding Strict-Transport-Security header")

        if len(cert.san_domains) == 0:
            warnings.append("No Subject Alternative Names found")

        return warnings
