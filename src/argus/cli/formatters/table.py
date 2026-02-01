"""Table formatter for CLI output."""

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus.models import ScanSession


def _format_date(date_value: Any) -> str:
    """Safely format a date value to string."""
    if date_value is None:
        return "N/A"
    if isinstance(date_value, datetime):
        return str(date_value.date())
    if isinstance(date_value, list) and date_value:
        return _format_date(date_value[0])
    return str(date_value)


def format_scan_result(console: Console, result: ScanSession) -> None:
    """Format and display scan results as tables."""
    console.print()
    console.print(
        Panel(
            f"[bold green]Scan Complete[/bold green]\n"
            f"Target: [cyan]{result.target.identifier}[/cyan]\n"
            f"Status: [{'green' if result.is_completed else 'red'}]{result.status.value}[/]",
            title="Results",
        )
    )

    # DNS Results
    if result.dns_result:
        _format_dns_results(console, result.dns_result)

    # WHOIS Results
    if result.whois_result:
        _format_whois_results(console, result.whois_result)

    # RDAP Results
    if result.rdap_result:
        _format_rdap_results(console, result.rdap_result)

    # Port Results
    if result.port_result:
        _format_port_results(console, result.port_result)

    # Web Tech Results
    if result.webtech_result:
        _format_webtech_results(console, result.webtech_result)

    # CT Log Results
    if result.crtsh_result:
        _format_crtsh_results(console, result.crtsh_result)

    # Vulnerability Results
    if result.vuln_result:
        _format_vuln_results(console, result.vuln_result)

    # SSL Results
    if result.ssl_result:
        _format_ssl_results(console, result.ssl_result)

    # Email Security Results
    if result.email_result:
        _format_email_results(console, result.email_result)

    # Security Scan Results
    if result.security_result:
        _format_security_results(console, result.security_result)

    # HTTP Security Headers Results
    if result.headers_result:
        _format_headers_results(console, result.headers_result)

    # Discovery Results
    if result.discovery_result:
        _format_discovery_results(console, result.discovery_result)

    # Favicon Results
    if result.favicon_result:
        _format_favicon_results(console, result.favicon_result)

    # ASN Results
    if result.asn_result:
        _format_asn_results(console, result.asn_result)

    # GraphQL Results
    if result.graphql_result:
        _format_graphql_results(console, result.graphql_result)

    # Wayback Results
    if result.wayback_result:
        _format_wayback_results(console, result.wayback_result)

    # Summary
    _format_summary(console, result)


def _format_dns_results(console: Console, dns) -> None:
    """Format DNS results."""
    table = Table(title="DNS Records", show_header=True)
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Value")
    table.add_column("TTL")

    for _record_type, records in dns.records.items():
        for record in records:
            table.add_row(
                record.record_type,
                record.name,
                record.value[:50] + "..." if len(record.value) > 50 else record.value,
                str(record.ttl),
            )

    console.print(table)

    if dns.subdomains:
        sub_table = Table(title="Subdomains", show_header=True)
        sub_table.add_column("Subdomain", style="cyan")
        sub_table.add_column("IPs", style="green")
        sub_table.add_column("Status")

        for sub in dns.subdomains[:20]:  # Limit display
            sub_table.add_row(
                sub.full_domain,
                ", ".join(sub.resolved_ips[:3]),
                sub.status,
            )

        if len(dns.subdomains) > 20:
            sub_table.add_row("...", f"({len(dns.subdomains) - 20} more)", "")

        console.print(sub_table)

    # Zone Transfer and DNSSEC status
    if dns.zone_transfer_vulnerable:
        console.print("\n[red bold]⚠ CRITICAL: DNS Zone Transfer (AXFR) is ENABLED![/red bold]")
        console.print("[red]  This allows attackers to download all DNS records for the domain.[/red]")
        console.print("[red]  Recommendation: Restrict zone transfers to authorized secondary DNS servers only.[/red]")

    dnssec_status = "[green]✓ Enabled[/green]" if dns.dnssec_enabled else "[yellow]✗ Not enabled[/yellow]"
    console.print(f"\nDNSSEC: {dnssec_status}")


def _format_whois_results(console: Console, whois) -> None:
    """Format WHOIS results."""
    table = Table(title="WHOIS Information", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    has_data = False

    if whois.domain_name:
        table.add_row("Domain", whois.domain_name)
        has_data = True
    if whois.registrar and whois.registrar.name:
        table.add_row("Registrar", whois.registrar.name)
        has_data = True
    if whois.creation_date:
        table.add_row("Created", _format_date(whois.creation_date))
        has_data = True
    if whois.expiration_date:
        table.add_row("Expires", _format_date(whois.expiration_date))
        if whois.days_until_expiry:
            table.add_row("Days Until Expiry", str(whois.days_until_expiry))
        has_data = True
    if whois.updated_date:
        table.add_row("Updated", _format_date(whois.updated_date))
        has_data = True
    if whois.nameservers:
        table.add_row("Nameservers", ", ".join(whois.nameservers[:5]))
        has_data = True
    if whois.status:
        table.add_row("Status", ", ".join(whois.status[:3]))
        has_data = True
    if whois.registrant and whois.registrant.organization:
        table.add_row("Registrant Org", whois.registrant.organization)
        has_data = True
    if whois.registrant and whois.registrant.country:
        table.add_row("Registrant Country", whois.registrant.country)
        has_data = True

    if has_data:
        console.print(table)
    else:
        console.print("[yellow]WHOIS: No detailed information available (may be redacted)[/yellow]")


def _format_rdap_results(console: Console, rdap) -> None:
    """Format RDAP results."""
    table = Table(title="RDAP Information", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    has_data = False

    if rdap.handle:
        table.add_row("Handle", rdap.handle)
        has_data = True
    if rdap.domain_name:
        table.add_row("Domain", rdap.domain_name)
        has_data = True
    if rdap.network_name:
        table.add_row("Network", rdap.network_name)
        has_data = True
    if rdap.network_cidr:
        table.add_row("CIDR", rdap.network_cidr)
        has_data = True
    if rdap.network_start and rdap.network_end:
        table.add_row("IP Range", f"{rdap.network_start} - {rdap.network_end}")
        has_data = True
    if rdap.asn:
        table.add_row("ASN", f"AS{rdap.asn}")
        has_data = True
    if rdap.asn_name:
        table.add_row("ASN Name", rdap.asn_name)
        has_data = True
    if rdap.asn_country:
        table.add_row("Country", rdap.asn_country)
        has_data = True
    if rdap.events:
        for event_type, event_date in list(rdap.events.items())[:3]:
            table.add_row(f"Event: {event_type}", _format_date(event_date))
            has_data = True
    if rdap.entities:
        for entity in rdap.entities[:2]:
            if entity.name or entity.organization:
                table.add_row("Entity", entity.name or entity.organization or "N/A")
                has_data = True

    if has_data:
        console.print(table)
    else:
        console.print("[yellow]RDAP: No detailed information available[/yellow]")


def _format_port_results(console: Console, ports) -> None:
    """Format port scan results."""
    if not ports.open_ports:
        console.print("[yellow]No open ports found[/yellow]")
        return

    table = Table(title=f"Open Ports ({len(ports.open_ports)} found)", show_header=True)
    table.add_column("Port", style="cyan")
    table.add_column("Protocol")
    table.add_column("Service", style="green")
    table.add_column("Version")
    table.add_column("Risk", style="red")

    for port in ports.open_ports:
        risk = "[red]HIGH[/red]" if port.is_high_risk else "[green]LOW[/green]"
        service_name = port.service.name if port.service else "unknown"
        service_version = port.service.version if port.service else ""

        table.add_row(
            str(port.port),
            port.protocol.upper(),
            service_name,
            service_version or "",
            risk,
        )

    console.print(table)


def _format_webtech_results(console: Console, webtech) -> None:
    """Format web technology results."""
    table = Table(title="Web Technologies", show_header=True)
    table.add_column("Technology", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Version")
    table.add_column("Confidence")

    for tech in webtech.technologies:
        table.add_row(
            tech.name,
            ", ".join(tech.categories[:2]),
            tech.version or "",
            f"{tech.confidence}%",
        )

    console.print(table)

    # Security headers
    if webtech.missing_security_headers:
        console.print(
            f"\n[yellow]Missing Security Headers:[/yellow] "
            f"{', '.join(webtech.missing_security_headers)}"
        )


def _format_crtsh_results(console: Console, crtsh) -> None:
    """Format Certificate Transparency results."""
    if not crtsh.unique_subdomains:
        console.print("[yellow]CT Logs: No subdomains discovered[/yellow]")
        return

    table = Table(
        title=f"CT Log Subdomains ({len(crtsh.unique_subdomains)} found from {crtsh.total_certificates} certs)",
        show_header=True,
    )
    table.add_column("Subdomain", style="cyan")
    table.add_column("Certificates", style="green")
    table.add_column("First Seen")
    table.add_column("Wildcard")

    for sub in crtsh.discovered_subdomains[:20]:
        table.add_row(
            sub.full_domain,
            str(len(sub.certificate_ids)),
            _format_date(sub.first_seen),
            "[yellow]*[/yellow]" if sub.is_wildcard else "",
        )

    if len(crtsh.discovered_subdomains) > 20:
        table.add_row(
            f"... ({len(crtsh.discovered_subdomains) - 20} more)",
            "",
            "",
            "",
        )

    console.print(table)

    if crtsh.wildcard_domains:
        console.print(
            f"\n[yellow]Wildcard Domains:[/yellow] {', '.join(crtsh.wildcard_domains[:5])}"
        )


def _format_vuln_results(console: Console, vuln) -> None:
    """Format vulnerability scan results."""
    if vuln.total_vulnerabilities == 0:
        console.print("[green]No known vulnerabilities found for detected technologies[/green]")
        return

    # Summary
    summary = []
    if vuln.critical_count > 0:
        summary.append(f"[red]Critical: {vuln.critical_count}[/red]")
    if vuln.high_count > 0:
        summary.append(f"[orange1]High: {vuln.high_count}[/orange1]")
    if vuln.medium_count > 0:
        summary.append(f"[yellow]Medium: {vuln.medium_count}[/yellow]")
    if vuln.low_count > 0:
        summary.append(f"[green]Low: {vuln.low_count}[/green]")

    console.print(
        f"\n[bold]Vulnerabilities Found:[/bold] {vuln.total_vulnerabilities} ({', '.join(summary)})"
    )

    # Details per technology
    for tech_vuln in vuln.technology_vulnerabilities:
        if not tech_vuln.vulnerabilities:
            continue

        table = Table(
            title=f"{tech_vuln.technology} ({tech_vuln.version or 'unknown version'})",
            show_header=True,
        )
        table.add_column("CVE", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("CVSS")
        table.add_column("Description")

        for v in tech_vuln.vulnerabilities[:10]:
            severity_style = {
                "critical": "[red]CRITICAL[/red]",
                "high": "[orange1]HIGH[/orange1]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[green]LOW[/green]",
            }.get(v.severity, v.severity.upper())

            desc = v.description[:60] + "..." if v.description and len(v.description) > 60 else (v.description or "N/A")

            table.add_row(
                v.cve_id,
                severity_style,
                f"{v.cvss_score:.1f}" if v.cvss_score else "N/A",
                desc,
            )

        if len(tech_vuln.vulnerabilities) > 10:
            table.add_row(
                f"... ({len(tech_vuln.vulnerabilities) - 10} more)",
                "",
                "",
                "",
            )

        console.print(table)


def _format_ssl_results(console: Console, ssl) -> None:
    """Format SSL/TLS scan results."""
    if not ssl.ssl_enabled:
        console.print(f"[yellow]SSL/TLS: Not enabled or connection failed[/yellow]")
        if ssl.connection_error:
            console.print(f"[dim]Error: {ssl.connection_error}[/dim]")
        return

    table = Table(title="SSL/TLS Certificate", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    # Grade
    grade = ssl.grade or "N/A"
    grade_style = {
        "A+": "[bold green]A+[/bold green]",
        "A": "[green]A[/green]",
        "B": "[blue]B[/blue]",
        "C": "[yellow]C[/yellow]",
        "D": "[orange1]D[/orange1]",
        "F": "[red]F[/red]",
        "T": "[red]T (Trust issues)[/red]",
    }.get(grade, grade)
    table.add_row("Grade", grade_style)

    if ssl.certificate:
        cert = ssl.certificate
        table.add_row("Subject", cert.subject or "N/A")
        table.add_row("Issuer", cert.issuer or "N/A")
        if cert.not_after:
            expiry = _format_date(cert.not_after)
            days = cert.days_until_expiry
            if days is not None:
                if days < 30:
                    expiry = f"[red]{expiry} ({days} days)[/red]"
                elif days < 90:
                    expiry = f"[yellow]{expiry} ({days} days)[/yellow]"
                else:
                    expiry = f"{expiry} ({days} days)"
            table.add_row("Expires", expiry)
        table.add_row("Self-signed", "Yes" if cert.is_self_signed else "No")
        if cert.san_domains:
            table.add_row("SANs", ", ".join(cert.san_domains[:5]))

    if ssl.tls_info:
        tls = ssl.tls_info
        table.add_row("Protocol", tls.protocol_version or "N/A")
        table.add_row("Cipher", tls.cipher_suite or "N/A")
        protocols = []
        if tls.supports_tls13:
            protocols.append("[green]TLS 1.3[/green]")
        if tls.supports_tls12:
            protocols.append("TLS 1.2")
        if tls.supports_tls11:
            protocols.append("[yellow]TLS 1.1[/yellow]")
        if tls.supports_tls10:
            protocols.append("[red]TLS 1.0[/red]")
        if protocols:
            table.add_row("Supported", ", ".join(protocols))

    console.print(table)

    # Vulnerabilities
    if ssl.vulnerabilities:
        console.print(f"\n[bold]SSL Vulnerabilities ({len(ssl.vulnerabilities)}):[/bold]")
        for vuln in ssl.vulnerabilities[:5]:
            severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}.get(vuln.severity, "white")
            console.print(f"  [{severity_color}]{vuln.severity.upper()}[/{severity_color}]: {vuln.name}")


def _format_email_results(console: Console, email) -> None:
    """Format email security scan results."""
    table = Table(title="Email Security", show_header=True)
    table.add_column("Protocol", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # SPF
    spf_status = "[green]✓[/green]" if email.has_spf else "[red]✗[/red]"
    spf_details = ""
    if email.spf:
        if email.spf.all_mechanism:
            spf_details = f"Policy: {email.spf.all_mechanism}"
    table.add_row("SPF", spf_status, spf_details)

    # DKIM
    dkim_status = "[green]✓[/green]" if email.has_dkim else "[red]✗[/red]"
    dkim_details = f"{len([d for d in email.dkim_records if d.is_valid])} valid selectors" if email.dkim_records else ""
    table.add_row("DKIM", dkim_status, dkim_details)

    # DMARC
    dmarc_status = "[green]✓[/green]" if email.has_dmarc else "[red]✗[/red]"
    dmarc_details = ""
    if email.dmarc and email.dmarc.policy:
        policy_color = "green" if email.dmarc.policy == "reject" else ("yellow" if email.dmarc.policy == "quarantine" else "red")
        dmarc_details = f"Policy: [{policy_color}]{email.dmarc.policy}[/{policy_color}]"
    table.add_row("DMARC", dmarc_status, dmarc_details)

    # MTA-STS
    if email.mta_sts:
        mta_status = "[green]✓[/green]" if email.mta_sts.is_valid else "[yellow]○[/yellow]"
        mta_details = f"Mode: {email.mta_sts.policy_mode}" if email.mta_sts.policy_mode else ""
        table.add_row("MTA-STS", mta_status, mta_details)

    console.print(table)

    # Score
    grade = email.security_grade or "N/A"
    grade_color = {"A": "green", "B": "blue", "C": "yellow", "D": "orange1", "F": "red"}.get(grade, "white")
    console.print(f"\nEmail Security Score: [{grade_color}]{email.security_score}/100 (Grade: {grade})[/{grade_color}]")

    if email.issues:
        console.print(f"\n[yellow]Issues:[/yellow] {', '.join(email.issues[:3])}")


def _format_security_results(console: Console, security) -> None:
    """Format security scan results."""
    if security.total_findings == 0:
        console.print("[green]No security issues found[/green]")
        return

    # Summary
    summary = []
    if security.critical_count > 0:
        summary.append(f"[red]Critical: {security.critical_count}[/red]")
    if security.high_count > 0:
        summary.append(f"[orange1]High: {security.high_count}[/orange1]")
    if security.medium_count > 0:
        summary.append(f"[yellow]Medium: {security.medium_count}[/yellow]")
    if security.low_count > 0:
        summary.append(f"[green]Low: {security.low_count}[/green]")

    console.print(f"\n[bold]Security Findings:[/bold] {security.total_findings} ({', '.join(summary)})")

    # Exposed files
    if security.exposed_files:
        table = Table(title="Exposed Files/Directories", show_header=True)
        table.add_column("Path", style="cyan")
        table.add_column("Type")
        table.add_column("Severity")

        for ef in security.exposed_files[:10]:
            severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}.get(ef.severity, "white")
            table.add_row(ef.path, ef.file_type, f"[{severity_color}]{ef.severity.upper()}[/{severity_color}]")

        console.print(table)

    # CORS issues
    if security.cors_misconfigurations:
        console.print(f"\n[yellow]CORS Misconfigurations: {len(security.cors_misconfigurations)}[/yellow]")
        for cors in security.cors_misconfigurations[:3]:
            console.print(f"  - {cors.issue_type}: {cors.description}")

    # WAF
    if security.waf and security.waf.detected:
        console.print(f"\n[blue]WAF Detected:[/blue] {security.waf.waf_name} ({security.waf.confidence} confidence)")

    # HTTP Method findings
    if security.http_method_findings:
        console.print("\n[bold]HTTP Methods:[/bold]")
        for finding in security.http_method_findings:
            if finding.dangerous_methods:
                severity_color = {"high": "red", "medium": "yellow", "low": "green"}.get(finding.severity, "white")
                console.print(f"  [{severity_color}][{finding.severity.upper()}][/{severity_color}] {finding.description}")
            else:
                console.print(f"  [info] Allowed: {', '.join(finding.allowed_methods)}")

    # Cloud providers
    if security.cloud_providers:
        providers = [f"{p.provider}" + (f" ({p.service})" if p.service else "") for p in security.cloud_providers]
        console.print(f"\n[blue]Cloud Providers:[/blue] {', '.join(providers)}")

    # Cloud Storage findings
    if security.cloud_storage_findings:
        table = Table(title="Cloud Storage Buckets", show_header=True)
        table.add_column("Provider", style="cyan")
        table.add_column("Bucket/Account")
        table.add_column("Public")
        table.add_column("Listing")
        table.add_column("Severity")

        for cs in security.cloud_storage_findings:
            provider_names = {"aws_s3": "AWS S3", "azure_blob": "Azure Blob", "gcp_storage": "GCP Storage"}
            provider = provider_names.get(cs.provider, cs.provider)
            is_public = "[red]Yes[/red]" if cs.is_public else "[green]No[/green]"
            allows_listing = "[red]Yes[/red]" if cs.allows_listing else "[green]No[/green]"
            severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green", "info": "dim"}.get(cs.severity, "white")
            table.add_row(
                provider,
                cs.bucket_name,
                is_public,
                allows_listing,
                f"[{severity_color}]{cs.severity.upper()}[/{severity_color}]",
            )

        console.print(table)

        # Show sensitive files found
        for cs in security.cloud_storage_findings:
            if cs.sensitive_files_found:
                console.print(f"\n[red]Sensitive files in {cs.bucket_name}:[/red]")
                for f in cs.sensitive_files_found[:5]:
                    console.print(f"  - {f}")

    # Spring Boot Actuator findings
    if security.actuator_findings:
        table = Table(title="Spring Boot Actuator Endpoints", show_header=True)
        table.add_column("Endpoint", style="cyan")
        table.add_column("Framework")
        table.add_column("Severity")

        for af in security.actuator_findings:
            severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green", "info": "dim"}.get(af.severity, "white")
            framework_names = {"spring_boot": "Spring Boot 2.x", "spring_boot_legacy": "Spring Boot 1.x", "management": "Management"}
            table.add_row(
                af.endpoint,
                framework_names.get(af.framework, af.framework),
                f"[{severity_color}]{af.severity.upper()}[/{severity_color}]",
            )

        console.print(table)

    # Source map findings
    if security.source_map_findings:
        console.print(f"\n[yellow]Source Maps Exposed ({len(security.source_map_findings)}):[/yellow]")
        for sm in security.source_map_findings[:5]:
            console.print(f"  - {sm.js_file.split('/')[-1]}.map")
            if sm.sources_exposed:
                console.print(f"    Sources: {', '.join(sm.sources_exposed[:3])}")

    # Docker/K8s findings
    if security.docker_k8s_findings:
        accessible = [f for f in security.docker_k8s_findings if f.is_accessible]
        if accessible:
            console.print(f"\n[red]Docker/Kubernetes APIs Exposed ({len(accessible)}):[/red]")
            for dk in accessible[:5]:
                service_names = {"docker_api": "Docker API", "kubernetes_api": "Kubernetes API", "docker_registry": "Docker Registry"}
                severity_color = {"critical": "red", "high": "orange1", "medium": "yellow"}.get(dk.severity, "white")
                console.print(f"  [{severity_color}][{dk.severity.upper()}][/{severity_color}] {service_names.get(dk.service_type, dk.service_type)}: {dk.path}")

    # Host Header Injection findings
    if security.host_header_findings:
        console.print(f"\n[red]Host Header Injection Vulnerabilities ({len(security.host_header_findings)}):[/red]")
        for hh in security.host_header_findings:
            severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}.get(hh.severity, "white")
            injection_types = {
                "reflection_in_body": "Body Reflection",
                "reflection_in_headers": "Header Reflection",
                "cache_poisoning": "Cache Poisoning",
                "password_reset_poisoning": "Password Reset Poisoning",
                "redirect": "Open Redirect",
            }
            console.print(f"  [{severity_color}][{hh.severity.upper()}][/{severity_color}] {injection_types.get(hh.injection_type, hh.injection_type)}")
            if hh.evidence:
                console.print(f"    Evidence: {hh.evidence[:80]}")

    # CMS findings
    if security.cms_findings:
        # Group by CMS type
        cms_groups: dict[str, list] = {}
        for cf in security.cms_findings:
            if cf.cms_type not in cms_groups:
                cms_groups[cf.cms_type] = []
            cms_groups[cf.cms_type].append(cf)

        for cms_type, cms_list in cms_groups.items():
            critical_high = [f for f in cms_list if f.severity in ("critical", "high")]
            if critical_high:
                console.print(f"\n[yellow]{cms_type} Findings ({len(cms_list)}):[/yellow]")
                for cf in cms_list[:10]:
                    severity_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green", "info": "dim"}.get(cf.severity, "white")
                    console.print(f"  [{severity_color}][{cf.severity.upper()}][/{severity_color}] {cf.path}")
                    if cf.version:
                        console.print(f"    Version: {cf.version}")
                    if cf.evidence:
                        console.print(f"    {cf.evidence[:60]}")


def _format_headers_results(console: Console, headers) -> None:
    """Format HTTP security headers results."""
    table = Table(title="HTTP Security Headers", show_header=True)
    table.add_column("Header", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    # Present headers
    for h in headers.present_headers[:10]:
        table.add_row(
            h.header_name,
            "[green]✓ Present[/green]",
            (h.value[:50] + "...") if h.value and len(h.value) > 50 else (h.value or ""),
        )

    # Missing headers
    for h in headers.missing_headers[:5]:
        severity_color = {"high": "red", "medium": "yellow", "low": "green"}.get(h.severity, "white")
        table.add_row(
            h.header_name,
            f"[{severity_color}]✗ Missing[/{severity_color}]",
            h.description or "",
        )

    console.print(table)

    # Score
    grade = headers.grade or "N/A"
    grade_color = {"A+": "green", "A": "green", "B": "blue", "C": "yellow", "D": "orange1", "F": "red"}.get(grade, "white")
    console.print(f"\nSecurity Headers Score: [{grade_color}]{headers.score}/100 (Grade: {grade})[/{grade_color}]")

    # CSP analysis
    if headers.csp and headers.csp.present:
        status = "[yellow]Report-Only[/yellow]" if headers.csp.report_only else "[green]Enforcing[/green]"
        console.print(f"\n[blue]CSP:[/blue] {status}")
        if headers.csp.issues:
            console.print(f"  [yellow]Issues: {len(headers.csp.issues)}[/yellow]")

    # HSTS analysis
    if headers.hsts and headers.hsts.present:
        max_age = headers.hsts.max_age or 0
        console.print(
            f"\n[blue]HSTS:[/blue] max-age={max_age}, "
            f"includeSubDomains={'✓' if headers.hsts.include_subdomains else '✗'}, "
            f"preload={'✓' if headers.hsts.preload else '✗'}"
        )


def _format_discovery_results(console: Console, discovery) -> None:
    """Format discovery scan results."""
    table = Table(title="Discovery Files", show_header=True)
    table.add_column("File", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    # robots.txt
    if discovery.robots:
        status = "[green]✓ Found[/green]" if discovery.robots.found else "[yellow]Not found[/yellow]"
        details = ""
        if discovery.robots.found:
            details = f"{len(discovery.robots.disallowed_paths)} disallows"
            if discovery.robots.interesting_disallows:
                details += f" ({len(discovery.robots.interesting_disallows)} interesting)"
        table.add_row("robots.txt", status, details)

    # sitemap.xml
    if discovery.sitemap:
        status = "[green]✓ Found[/green]" if discovery.sitemap.found else "[yellow]Not found[/yellow]"
        details = f"{discovery.sitemap.total_urls} URLs" if discovery.sitemap.found else ""
        table.add_row("sitemap.xml", status, details)

    # security.txt
    if discovery.security_txt:
        status = "[green]✓ Found[/green]" if discovery.security_txt.found else "[yellow]Not found[/yellow]"
        details = ""
        if discovery.security_txt.found and discovery.security_txt.contacts:
            details = f"{len(discovery.security_txt.contacts)} contacts"
        table.add_row("security.txt", status, details)

    console.print(table)

    # Interesting paths
    if discovery.interesting_paths:
        console.print(f"\n[yellow]Interesting Paths ({len(discovery.interesting_paths)}):[/yellow]")
        for path in discovery.interesting_paths[:5]:
            console.print(f"  - {path}")
        if len(discovery.interesting_paths) > 5:
            console.print(f"  ... and {len(discovery.interesting_paths) - 5} more")


def _format_favicon_results(console: Console, favicon) -> None:
    """Format favicon fingerprinting results."""
    if not favicon.found:
        console.print("[yellow]Favicon: Not found or not accessible[/yellow]")
        return

    console.print(f"\n[bold]Favicon Fingerprint[/bold]")
    console.print(f"  URL: {favicon.url}")
    console.print(f"  MurmurHash3: {favicon.mmh3_hash}")
    if favicon.shodan_query:
        console.print(f"  Shodan Query: {favicon.shodan_query}")

    if favicon.matches:
        console.print(f"\n[green]Technology Matches ({len(favicon.matches)}):[/green]")
        for match in favicon.matches:
            console.print(f"  - {match.technology} ({match.category}) - {match.description}")


def _format_asn_results(console: Console, asn) -> None:
    """Format ASN/IP range results."""
    table = Table(title="ASN Information", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("IP Address", asn.ip_address or "N/A")

    if asn.asn:
        table.add_row("ASN", f"AS{asn.asn.asn}")
        table.add_row("Organization", asn.asn.name or "N/A")
        if asn.asn.country:
            table.add_row("Country", asn.asn.country)

    if asn.geolocation:
        geo = asn.geolocation
        location = ", ".join(filter(None, [geo.city, geo.region, geo.country]))
        if location:
            table.add_row("Location", location)

    table.add_row("IP Ranges", str(len(asn.ip_ranges)))
    table.add_row("BGP Peers", str(len(asn.bgp_peers)))

    if asn.rir:
        table.add_row("RIR", asn.rir)

    console.print(table)


def _format_graphql_results(console: Console, graphql) -> None:
    """Format GraphQL introspection results."""
    if not graphql.endpoints:
        console.print("[yellow]GraphQL: No endpoints found[/yellow]")
        return

    table = Table(title="GraphQL Endpoints", show_header=True)
    table.add_column("URL", style="cyan")
    table.add_column("Method")
    table.add_column("Introspection")

    for endpoint in graphql.endpoints:
        if endpoint.exists:
            intro = "[red]✓ Enabled[/red]" if endpoint.introspection_enabled else "[green]Disabled[/green]"
            table.add_row(endpoint.url, endpoint.method or "N/A", intro)

    console.print(table)

    if graphql.has_introspection:
        console.print(f"\n[blue]Schema Analysis:[/blue]")
        console.print(f"  Types: {graphql.total_types}")
        console.print(f"  Queries: {graphql.total_queries}")
        console.print(f"  Mutations: {graphql.total_mutations}")

        if graphql.sensitive_fields:
            console.print(f"\n[yellow]Sensitive Fields ({len(graphql.sensitive_fields)}):[/yellow]")
            for field in graphql.sensitive_fields[:5]:
                console.print(f"  - {field}")

        if graphql.dangerous_mutations:
            console.print(f"\n[red]Dangerous Mutations ({len(graphql.dangerous_mutations)}):[/red]")
            for mutation in graphql.dangerous_mutations[:5]:
                console.print(f"  - {mutation}")


def _format_wayback_results(console: Console, wayback) -> None:
    """Format Wayback Machine results."""
    console.print(f"\n[bold]Wayback Machine URLs[/bold]")
    console.print(f"  Total URLs: {wayback.total_urls}")
    console.print(f"  Interesting URLs: {len(wayback.interesting_urls)}")
    console.print(f"  Unique Paths: {wayback.unique_paths}")

    if wayback.sensitive_files:
        console.print(f"\n[red]Sensitive Files Found ({len(wayback.sensitive_files)}):[/red]")
        for f in wayback.sensitive_files[:5]:
            console.print(f"  - {f}")

    if wayback.api_endpoints:
        console.print(f"\n[blue]API Endpoints ({len(wayback.api_endpoints)}):[/blue]")
        for api in wayback.api_endpoints[:5]:
            console.print(f"  - {api}")

    if wayback.sensitive_params:
        console.print(f"\n[yellow]Sensitive Parameters ({len(wayback.sensitive_params)}):[/yellow]")
        for param in wayback.sensitive_params[:5]:
            console.print(f"  - {param.name} (found {param.count} times)")


def _format_summary(console: Console, result: ScanSession) -> None:
    """Format summary section."""
    console.print()

    summary_parts = []
    if result.dns_result:
        summary_parts.append(f"DNS Records: {result.dns_result.total_records}")
        summary_parts.append(f"DNS Subdomains: {result.dns_result.total_subdomains}")
    if result.crtsh_result:
        summary_parts.append(f"CT Log Subdomains: {len(result.crtsh_result.unique_subdomains)}")
        summary_parts.append(f"Certificates: {result.crtsh_result.total_certificates}")
    if result.port_result:
        summary_parts.append(f"Open Ports: {result.port_result.total_open}")
        high_risk = len(result.port_result.high_risk_ports)
        if high_risk > 0:
            summary_parts.append(f"[red]High Risk Ports: {high_risk}[/red]")
    if result.webtech_result:
        summary_parts.append(f"Technologies: {len(result.webtech_result.technologies)}")
    if result.vuln_result and result.vuln_result.total_vulnerabilities > 0:
        vuln_str = f"Vulnerabilities: {result.vuln_result.total_vulnerabilities}"
        if result.vuln_result.critical_count > 0:
            vuln_str = f"[red]{vuln_str} ({result.vuln_result.critical_count} critical)[/red]"
        elif result.vuln_result.high_count > 0:
            vuln_str = f"[orange1]{vuln_str} ({result.vuln_result.high_count} high)[/orange1]"
        summary_parts.append(vuln_str)
    if result.ssl_result and result.ssl_result.ssl_enabled:
        grade = result.ssl_result.grade or "N/A"
        grade_color = {"A+": "green", "A": "green", "B": "blue", "C": "yellow", "D": "orange1", "F": "red", "T": "red"}.get(grade, "white")
        summary_parts.append(f"SSL Grade: [{grade_color}]{grade}[/{grade_color}]")
    if result.email_result:
        grade = result.email_result.security_grade or "N/A"
        summary_parts.append(f"Email Security: {result.email_result.security_score}/100 ({grade})")
    if result.security_result and result.security_result.total_findings > 0:
        sec_str = f"Security Findings: {result.security_result.total_findings}"
        if result.security_result.critical_count > 0:
            sec_str = f"[red]{sec_str} ({result.security_result.critical_count} critical)[/red]"
        elif result.security_result.high_count > 0:
            sec_str = f"[orange1]{sec_str} ({result.security_result.high_count} high)[/orange1]"
        summary_parts.append(sec_str)
    if result.headers_result:
        grade = result.headers_result.grade or "N/A"
        summary_parts.append(f"Headers: {result.headers_result.score}/100 ({grade})")
    if result.asn_result and result.asn_result.asn:
        summary_parts.append(f"ASN: AS{result.asn_result.asn.asn}")
    if result.graphql_result and result.graphql_result.endpoints:
        found = len([e for e in result.graphql_result.endpoints if e.exists])
        if found > 0:
            summary_parts.append(f"GraphQL Endpoints: {found}")
    if result.wayback_result and result.wayback_result.total_urls > 0:
        summary_parts.append(f"Wayback URLs: {result.wayback_result.total_urls}")

    if summary_parts:
        console.print(
            Panel(
                "\n".join(summary_parts),
                title="Summary",
                border_style="blue",
            )
        )

    if result.duration_seconds:
        console.print(f"\n[dim]Scan completed in {result.duration_seconds:.2f}s[/dim]")
