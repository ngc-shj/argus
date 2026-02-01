"""HTML report generator for scan results."""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from argus.models import ScanSession


class HTMLReportGenerator:
    """Generate professional HTML reports from scan results."""

    def __init__(self) -> None:
        pass

    def generate(
        self,
        session: ScanSession,
        output_path: Path | str,
        title: str | None = None,
    ) -> Path:
        """Generate HTML report and save to file."""
        output_path = Path(output_path)

        title = title or f"Security Scan Report - {session.target.identifier}"
        html_content = self._build_html(session, title)

        output_path.write_text(html_content, encoding="utf-8")
        return output_path

    def generate_string(
        self,
        session: ScanSession,
        title: str | None = None,
    ) -> str:
        """Generate HTML report as string."""
        title = title or f"Security Scan Report - {session.target.identifier}"
        return self._build_html(session, title)

    def _build_html(self, session: ScanSession, title: str) -> str:
        """Build complete HTML document."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    {self._get_styles()}
</head>
<body>
    <div class="container">
        {self._build_header(session, title)}
        {self._build_summary(session)}
        {self._build_sections(session)}
        {self._build_footer(session)}
    </div>
    {self._get_scripts()}
</body>
</html>"""

    def _get_styles(self) -> str:
        """Get embedded CSS styles."""
        return """<style>
:root {
    --primary: #2563eb;
    --primary-dark: #1d4ed8;
    --success: #22c55e;
    --warning: #f59e0b;
    --danger: #ef4444;
    --info: #06b6d4;
    --gray-50: #f9fafb;
    --gray-100: #f3f4f6;
    --gray-200: #e5e7eb;
    --gray-300: #d1d5db;
    --gray-600: #4b5563;
    --gray-700: #374151;
    --gray-800: #1f2937;
    --gray-900: #111827;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    line-height: 1.6;
    color: var(--gray-800);
    background: var(--gray-50);
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

header {
    background: linear-gradient(135deg, var(--gray-900), var(--gray-800));
    color: white;
    padding: 2rem;
    border-radius: 12px;
    margin-bottom: 2rem;
}

header h1 {
    font-size: 1.75rem;
    margin-bottom: 0.5rem;
}

header .meta {
    display: flex;
    gap: 2rem;
    font-size: 0.875rem;
    opacity: 0.9;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.summary-card {
    background: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.summary-card h3 {
    font-size: 0.875rem;
    color: var(--gray-600);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
}

.summary-card .value {
    font-size: 2rem;
    font-weight: 700;
}

.summary-card.critical .value { color: var(--danger); }
.summary-card.warning .value { color: var(--warning); }
.summary-card.success .value { color: var(--success); }
.summary-card.info .value { color: var(--info); }

section {
    background: white;
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin-bottom: 1.5rem;
    overflow: hidden;
}

section h2 {
    background: var(--gray-100);
    padding: 1rem 1.5rem;
    font-size: 1.125rem;
    border-bottom: 1px solid var(--gray-200);
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

section h2:hover {
    background: var(--gray-200);
}

section h2::after {
    content: '▼';
    font-size: 0.75rem;
    transition: transform 0.2s;
}

section.collapsed h2::after {
    transform: rotate(-90deg);
}

section.collapsed .section-content {
    display: none;
}

.section-content {
    padding: 1.5rem;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    text-align: left;
    padding: 0.75rem;
    border-bottom: 1px solid var(--gray-200);
}

th {
    background: var(--gray-50);
    font-weight: 600;
    font-size: 0.875rem;
    color: var(--gray-600);
}

tr:hover {
    background: var(--gray-50);
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-critical { background: #fee2e2; color: #dc2626; }
.badge-high { background: #ffedd5; color: #ea580c; }
.badge-medium { background: #fef3c7; color: #d97706; }
.badge-low { background: #dcfce7; color: #16a34a; }
.badge-info { background: #e0f2fe; color: #0284c7; }

.finding {
    border: 1px solid var(--gray-200);
    border-radius: 8px;
    margin-bottom: 1rem;
    overflow: hidden;
}

.finding-header {
    padding: 1rem;
    background: var(--gray-50);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.finding-body {
    padding: 1rem;
}

.finding-body pre {
    background: var(--gray-100);
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.875rem;
}

.grade {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 3rem;
    height: 3rem;
    border-radius: 50%;
    font-size: 1.5rem;
    font-weight: 700;
}

.grade-a { background: #dcfce7; color: #16a34a; }
.grade-b { background: #e0f2fe; color: #0284c7; }
.grade-c { background: #fef3c7; color: #d97706; }
.grade-d { background: #ffedd5; color: #ea580c; }
.grade-f { background: #fee2e2; color: #dc2626; }

.progress-bar {
    background: var(--gray-200);
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-top: 0.5rem;
}

.progress-bar-fill {
    height: 100%;
    background: var(--primary);
    transition: width 0.3s;
}

footer {
    text-align: center;
    padding: 2rem;
    color: var(--gray-600);
    font-size: 0.875rem;
}

.no-data {
    text-align: center;
    padding: 2rem;
    color: var(--gray-600);
}

@media print {
    body { background: white; }
    .container { max-width: none; padding: 0; }
    section { break-inside: avoid; }
    section h2 { cursor: default; }
    section h2::after { display: none; }
}
</style>"""

    def _get_scripts(self) -> str:
        """Get embedded JavaScript."""
        return """<script>
document.querySelectorAll('section h2').forEach(header => {
    header.addEventListener('click', () => {
        header.parentElement.classList.toggle('collapsed');
    });
});
</script>"""

    def _build_header(self, session: ScanSession, title: str) -> str:
        """Build report header."""
        scan_date = session.started_at.strftime("%Y-%m-%d %H:%M:%S") if session.started_at else "N/A"
        duration = f"{session.duration_seconds:.2f}s" if session.duration_seconds else "N/A"

        return f"""<header>
    <h1>{html.escape(title)}</h1>
    <div class="meta">
        <span>Target: {html.escape(session.target.identifier)}</span>
        <span>Scan Date: {scan_date}</span>
        <span>Duration: {duration}</span>
        <span>Status: {session.status.value}</span>
    </div>
</header>"""

    def _build_summary(self, session: ScanSession) -> str:
        """Build summary cards."""
        cards = []

        # Count findings
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0

        if session.vuln_result:
            total_vulns = session.vuln_result.total_vulnerabilities
            critical_vulns = session.vuln_result.critical_count
            high_vulns = session.vuln_result.high_count

        open_ports = 0
        high_risk_ports = 0
        if session.port_result:
            open_ports = session.port_result.total_open
            high_risk_ports = len(session.port_result.high_risk_ports)

        subdomains = 0
        if session.dns_result:
            subdomains = session.dns_result.total_subdomains
        if session.crtsh_result:
            subdomains += len(session.crtsh_result.unique_subdomains)

        technologies = 0
        if session.webtech_result:
            technologies = len(session.webtech_result.technologies)

        # Build cards
        card_class = "critical" if critical_vulns > 0 else ("warning" if high_vulns > 0 else "success")
        cards.append(f"""<div class="summary-card {card_class}">
    <h3>Vulnerabilities</h3>
    <div class="value">{total_vulns}</div>
    <small>{critical_vulns} critical, {high_vulns} high</small>
</div>""")

        port_class = "warning" if high_risk_ports > 0 else "info"
        cards.append(f"""<div class="summary-card {port_class}">
    <h3>Open Ports</h3>
    <div class="value">{open_ports}</div>
    <small>{high_risk_ports} high risk</small>
</div>""")

        cards.append(f"""<div class="summary-card info">
    <h3>Subdomains</h3>
    <div class="value">{subdomains}</div>
</div>""")

        cards.append(f"""<div class="summary-card info">
    <h3>Technologies</h3>
    <div class="value">{technologies}</div>
</div>""")

        return f"""<div class="summary-grid">
    {''.join(cards)}
</div>"""

    def _build_sections(self, session: ScanSession) -> str:
        """Build all report sections."""
        sections = []

        if session.dns_result:
            sections.append(self._build_dns_section(session.dns_result))

        if session.whois_result:
            sections.append(self._build_whois_section(session.whois_result))

        if session.port_result:
            sections.append(self._build_ports_section(session.port_result))

        if session.webtech_result:
            sections.append(self._build_webtech_section(session.webtech_result))

        if session.crtsh_result:
            sections.append(self._build_crtsh_section(session.crtsh_result))

        if session.vuln_result:
            sections.append(self._build_vuln_section(session.vuln_result))

        return "\n".join(sections)

    def _build_dns_section(self, dns) -> str:
        """Build DNS results section."""
        rows = []
        for _record_type, records in dns.records.items():
            for record in records:
                value = html.escape(record.value)
                if len(value) > 60:
                    value = value[:60] + "..."
                rows.append(f"""<tr>
    <td><span class="badge badge-info">{html.escape(record.record_type)}</span></td>
    <td>{html.escape(record.name)}</td>
    <td>{value}</td>
    <td>{record.ttl}</td>
</tr>""")

        table = f"""<table>
    <thead>
        <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Value</th>
            <th>TTL</th>
        </tr>
    </thead>
    <tbody>
        {''.join(rows) if rows else '<tr><td colspan="4" class="no-data">No DNS records found</td></tr>'}
    </tbody>
</table>"""

        subdomain_list = ""
        if dns.subdomains:
            sub_items = []
            for sub in dns.subdomains[:30]:
                ips = ", ".join(sub.resolved_ips[:3])
                sub_items.append(f"<li><strong>{html.escape(sub.full_domain)}</strong> - {ips}</li>")
            if len(dns.subdomains) > 30:
                sub_items.append(f"<li>... and {len(dns.subdomains) - 30} more</li>")
            subdomain_list = f"""<h3>Discovered Subdomains ({len(dns.subdomains)})</h3>
<ul>{''.join(sub_items)}</ul>"""

        return f"""<section>
    <h2>DNS Records ({dns.total_records} records)</h2>
    <div class="section-content">
        {table}
        {subdomain_list}
    </div>
</section>"""

    def _build_whois_section(self, whois) -> str:
        """Build WHOIS results section."""
        rows = []

        def add_row(label: str, value: Any) -> None:
            if value:
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value[:5])
                rows.append(f"<tr><td><strong>{label}</strong></td><td>{html.escape(str(value))}</td></tr>")

        add_row("Domain", whois.domain_name)
        if whois.registrar:
            add_row("Registrar", whois.registrar.name)
        add_row("Created", str(whois.creation_date.date()) if whois.creation_date else None)
        add_row("Expires", str(whois.expiration_date.date()) if whois.expiration_date else None)
        add_row("Updated", str(whois.updated_date.date()) if whois.updated_date else None)
        add_row("Nameservers", whois.nameservers)
        add_row("Status", whois.status)
        if whois.registrant:
            add_row("Registrant Org", whois.registrant.organization)
            add_row("Registrant Country", whois.registrant.country)

        return f"""<section>
    <h2>WHOIS Information</h2>
    <div class="section-content">
        <table>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="2" class="no-data">No WHOIS information available</td></tr>'}
            </tbody>
        </table>
    </div>
</section>"""

    def _build_ports_section(self, ports) -> str:
        """Build port scan section."""
        rows = []
        for port in ports.open_ports:
            risk_badge = "badge-high" if port.is_high_risk else "badge-low"
            risk_text = "HIGH" if port.is_high_risk else "LOW"
            service_name = port.service.name if port.service else "unknown"
            service_version = port.service.version if port.service else ""

            rows.append(f"""<tr>
    <td><strong>{port.port}</strong></td>
    <td>{port.protocol.upper()}</td>
    <td>{html.escape(service_name)}</td>
    <td>{html.escape(service_version)}</td>
    <td><span class="badge {risk_badge}">{risk_text}</span></td>
</tr>""")

        return f"""<section>
    <h2>Open Ports ({ports.total_open} found)</h2>
    <div class="section-content">
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="5" class="no-data">No open ports found</td></tr>'}
            </tbody>
        </table>
    </div>
</section>"""

    def _build_webtech_section(self, webtech) -> str:
        """Build web technologies section."""
        rows = []
        for tech in webtech.technologies:
            categories = ", ".join(tech.categories[:2])
            rows.append(f"""<tr>
    <td><strong>{html.escape(tech.name)}</strong></td>
    <td>{html.escape(categories)}</td>
    <td>{html.escape(tech.version or '-')}</td>
    <td>{tech.confidence}%</td>
</tr>""")

        missing_headers = ""
        if webtech.missing_security_headers:
            headers_list = ", ".join(webtech.missing_security_headers)
            missing_headers = f"""<div class="finding">
    <div class="finding-header">
        <span><strong>Missing Security Headers</strong></span>
        <span class="badge badge-medium">MEDIUM</span>
    </div>
    <div class="finding-body">
        {html.escape(headers_list)}
    </div>
</div>"""

        return f"""<section>
    <h2>Web Technologies ({len(webtech.technologies)} detected)</h2>
    <div class="section-content">
        <table>
            <thead>
                <tr>
                    <th>Technology</th>
                    <th>Category</th>
                    <th>Version</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="4" class="no-data">No technologies detected</td></tr>'}
            </tbody>
        </table>
        {missing_headers}
    </div>
</section>"""

    def _build_crtsh_section(self, crtsh) -> str:
        """Build Certificate Transparency section."""
        rows = []
        for sub in crtsh.discovered_subdomains[:30]:
            wildcard = "✓" if sub.is_wildcard else ""
            first_seen = sub.first_seen.strftime("%Y-%m-%d") if sub.first_seen else "N/A"
            rows.append(f"""<tr>
    <td>{html.escape(sub.full_domain)}</td>
    <td>{len(sub.certificate_ids)}</td>
    <td>{first_seen}</td>
    <td>{wildcard}</td>
</tr>""")

        return f"""<section>
    <h2>Certificate Transparency ({len(crtsh.unique_subdomains)} subdomains from {crtsh.total_certificates} certs)</h2>
    <div class="section-content">
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Certificates</th>
                    <th>First Seen</th>
                    <th>Wildcard</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="4" class="no-data">No subdomains found</td></tr>'}
            </tbody>
        </table>
    </div>
</section>"""

    def _build_vuln_section(self, vuln) -> str:
        """Build vulnerabilities section."""
        if vuln.total_vulnerabilities == 0:
            return """<section>
    <h2>Vulnerabilities</h2>
    <div class="section-content">
        <p class="no-data" style="color: var(--success);">No known vulnerabilities found for detected technologies.</p>
    </div>
</section>"""

        findings = []
        for tech_vuln in vuln.technology_vulnerabilities:
            if not tech_vuln.vulnerabilities:
                continue

            tech_header = f"{tech_vuln.technology}"
            if tech_vuln.version:
                tech_header += f" {tech_vuln.version}"

            vuln_rows = []
            for v in tech_vuln.vulnerabilities[:10]:
                severity_class = f"badge-{v.severity}"
                desc = html.escape(v.description or "N/A")
                if len(desc) > 80:
                    desc = desc[:80] + "..."
                cvss = f"{v.cvss_score:.1f}" if v.cvss_score else "N/A"

                vuln_rows.append(f"""<tr>
    <td><a href="https://nvd.nist.gov/vuln/detail/{v.cve_id}" target="_blank">{v.cve_id}</a></td>
    <td><span class="badge {severity_class}">{v.severity.upper()}</span></td>
    <td>{cvss}</td>
    <td>{desc}</td>
</tr>""")

            if len(tech_vuln.vulnerabilities) > 10:
                vuln_rows.append(f"""<tr>
    <td colspan="4" class="no-data">... and {len(tech_vuln.vulnerabilities) - 10} more</td>
</tr>""")

            findings.append(f"""<div class="finding">
    <div class="finding-header">
        <span><strong>{html.escape(tech_header)}</strong> ({tech_vuln.total_vulnerabilities} vulnerabilities)</span>
    </div>
    <div class="finding-body">
        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {''.join(vuln_rows)}
            </tbody>
        </table>
    </div>
</div>""")

        summary = f"""<p>
    <strong>Total:</strong> {vuln.total_vulnerabilities} vulnerabilities |
    <span class="badge badge-critical">Critical: {vuln.critical_count}</span>
    <span class="badge badge-high">High: {vuln.high_count}</span>
    <span class="badge badge-medium">Medium: {vuln.medium_count}</span>
    <span class="badge badge-low">Low: {vuln.low_count}</span>
</p>"""

        return f"""<section>
    <h2>Vulnerabilities ({vuln.total_vulnerabilities} found)</h2>
    <div class="section-content">
        {summary}
        {''.join(findings)}
    </div>
</section>"""

    def _build_footer(self, session: ScanSession) -> str:
        """Build report footer."""
        gen_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""<footer>
    <p>Generated by Argus Security Scanner</p>
    <p>Report generated at {gen_time}</p>
</footer>"""
