"""
HTML report generation for truslan.

Generates single-file HTML reports with embedded CSS and minimal JavaScript.
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from ..core.models import ScanResult, FindingSeverity
from ..core.checks import get_top_quick_fixes

logger = logging.getLogger("truslan")


def generate_html_report(result: ScanResult, output_path: Path) -> None:
    """
    Generate single-file HTML report.

    Args:
        result: Scan result with hosts and findings
        output_path: Path to output HTML file
    """
    logger.info(f"Generating HTML report: {output_path}")

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Prepare template data
    context = _prepare_context(result)

    # Render HTML
    html = _render_html(context)

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    logger.info(f"HTML report written: {output_path}")


def _prepare_context(result: ScanResult) -> Dict[str, Any]:
    """Prepare template context data."""

    # Calculate statistics
    hosts_up = sum(1 for h in result.hosts if h.state == "up")
    total_findings = sum(len(h.findings) for h in result.hosts)

    severity_counts = result.summary.get("findings_by_severity", {})

    # Get top quick fixes
    quick_fixes = get_top_quick_fixes(result, limit=5)

    # Duration
    duration = result.summary.get("duration_seconds", 0)
    duration_str = f"{duration:.1f}s" if duration < 60 else f"{duration/60:.1f}m"

    # Separate hosts with no TCP services from interesting hosts
    no_tcp_hosts = [
        h for h in result.hosts
        if len([s for s in h.services if s.state.value == "open" and s.protocol == "tcp"]) == 0
    ]
    interesting_hosts = [h for h in result.hosts if h not in no_tcp_hosts]

    # Check if any no_tcp_hosts have MAC or vendor info
    has_mac = any(h.mac_address for h in no_tcp_hosts)
    has_vendor = any(h.mac_vendor for h in no_tcp_hosts)

    # Get hosts_discovered from summary
    hosts_discovered = result.summary.get("hosts_discovered", len(result.hosts))
    hosts_marked_up = result.summary.get("hosts_marked_up_by_scanner", hosts_up)
    hosts_unresponsive = result.summary.get("hosts_unresponsive_after_discovery", 0)

    # Check if trust_discovery was used
    trust_discovery = False
    if hasattr(result.meta.options, 'trust_discovery'):
        trust_discovery = result.meta.options.trust_discovery

    context = {
        "title": "TrusLAN — LAN Exposure Scan Report",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile": result.meta.profile.value if hasattr(result.meta.profile, 'value') else result.meta.profile,
        "hosts_total": len(result.hosts),
        "hosts_up": hosts_up,
        "hosts_discovered": hosts_discovered,
        "hosts_marked_up_by_scanner": hosts_marked_up,
        "hosts_unresponsive_after_discovery": hosts_unresponsive,
        "trust_discovery": trust_discovery,
        "services_total": result.summary.get("services_total", 0),
        "services_open": result.summary.get("services_open", 0),
        "findings_total": total_findings,
        "severity_counts": severity_counts,
        "duration": duration_str,
        "quick_fixes": quick_fixes,
        "hosts": result.hosts,
        "interesting_hosts": interesting_hosts,
        "no_tcp_hosts": no_tcp_hosts,
        "no_tcp_has_mac": has_mac,
        "no_tcp_has_vendor": has_vendor,
        "nmap_commands": result.meta.nmap_commands,
        "scanner_version": result.meta.scanner_version,
        "nmap_version": result.meta.nmap_version or "unknown",
        "platform": result.meta.platform or "unknown",
        "scan_mode": result.meta.options.mode if hasattr(result.meta.options, 'mode') else "unknown",
        "top_ports": result.meta.options.top_ports if hasattr(result.meta.options, 'top_ports') else None
    }

    return context


def _render_html(context: Dict[str, Any]) -> str:
    """Render HTML report from context."""

    # Build quick fixes HTML
    quick_fixes_html = ""
    for fix in context["quick_fixes"]:
        severity = fix["severity"]
        severity_class = severity.value if hasattr(severity, 'value') else severity
        quick_fixes_html += f"""
        <div class="quick-fix">
            <span class="severity-badge {severity_class}">{severity_class.upper()}</span>
            <strong>{fix['title']}</strong> (affects {fix['count']} host(s))
            <p>{fix['remediation']}</p>
        </div>
        """

    # Build hosts HTML - only for interesting hosts (those with open TCP services or non-info findings)
    hosts_html = ""
    for host in context["interesting_hosts"]:
        # OS info
        os_info = ""
        if host.os_matches:
            top_match = host.os_matches[0]
            os_info = f"{top_match.name} ({top_match.accuracy}% confidence)"

        # Services table
        services_html = ""
        for service in host.services:
            state_class = "open" if service.state.value == "open" else "filtered"
            services_html += f"""
            <tr>
                <td>{service.port}</td>
                <td>{service.protocol}</td>
                <td><span class="state-{state_class}">{service.state.value}</span></td>
                <td>{service.service or "-"}</td>
                <td>{service.product or "-"}</td>
                <td>{service.version or "-"}</td>
            </tr>
            """

        # Findings table
        findings_html = ""
        for finding in host.findings:
            severity_class = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
            findings_html += f"""
            <tr>
                <td><span class="severity-badge {severity_class}">{severity_class.upper()}</span></td>
                <td><strong>{finding.title}</strong></td>
                <td>{finding.port or "-"}</td>
                <td>{finding.description}</td>
                <td>{finding.remediation}</td>
            </tr>
            """

        hosts_html += f"""
        <div class="host-card">
            <h2>{host.ip} {f"({host.hostname})" if host.hostname else ""}</h2>
            <div class="host-info">
                <p><strong>State:</strong> {host.state}</p>
                {f"<p><strong>OS:</strong> {os_info}</p>" if os_info else ""}
                {f"<p><strong>MAC:</strong> {host.mac_address} ({host.mac_vendor})</p>" if host.mac_address else ""}
                <p><strong>Open Ports:</strong> {len([s for s in host.services if s.state.value == "open"])}</p>
                <p><strong>Findings:</strong> {len(host.findings)}</p>
            </div>

            <h3>Services</h3>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {services_html if services_html else "<tr><td colspan='6'>No services detected</td></tr>"}
                </tbody>
            </table>

            {f"<h3>Security Findings</h3>" if findings_html else ""}
            {f"<table><thead><tr><th>Severity</th><th>Finding</th><th>Port</th><th>Description</th><th>Remediation</th></tr></thead><tbody>{findings_html}</tbody></table>" if findings_html else ""}
        </div>
        """

    # Build consolidated table for hosts with no TCP services
    no_tcp_hosts_html = ""
    if context["no_tcp_hosts"]:
        # Use a one-liner note instead of full remediation text (which appears in Top Quick Fixes)
        remediation_note = f"<p><strong>Note:</strong> No TCP ports found under the {context['profile'].upper()} profile; see Top Quick Fixes for next steps.</p>"

        # Build table headers based on available data
        headers = ["IP", "State"]
        if context["no_tcp_has_mac"]:
            headers.append("MAC")
        if context["no_tcp_has_vendor"]:
            headers.append("Vendor")
        headers.append("Open TCP Ports")

        header_html = "".join(f"<th>{h}</th>" for h in headers)

        # Build table rows
        rows_html = ""
        for host in context["no_tcp_hosts"]:
            cells = [host.ip, host.state]
            if context["no_tcp_has_mac"]:
                cells.append(host.mac_address or "-")
            if context["no_tcp_has_vendor"]:
                cells.append(host.mac_vendor or "-")
            cells.append("0")

            row_html = "".join(f"<td>{cell}</td>" for cell in cells)
            rows_html += f"<tr>{row_html}</tr>\n"

        no_tcp_hosts_html = f"""
        <div class="host-card no-tcp-group">
            <h2>Hosts with No TCP Services ({len(context["no_tcp_hosts"])} hosts)</h2>
            <div class="host-info">
                <p>The following hosts are up but have no open TCP ports within the current scan profile ({context["profile"].upper()}).</p>
                {remediation_note}
            </div>
            <table>
                <thead>
                    <tr>{header_html}</tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """

    # Build nmap commands HTML
    commands_html = ""
    for cmd in context["nmap_commands"]:
        commands_html += f"<pre>{cmd}</pre>\n"

    # Complete HTML document
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{context['title']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}

        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 1.8em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}

        h3 {{
            color: #555;
            margin-top: 25px;
            margin-bottom: 10px;
            font-size: 1.3em;
        }}

        .header {{
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        .metadata {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}

        .metadata-item {{
            padding: 10px;
        }}

        .metadata-item strong {{
            display: block;
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}

        .metadata-item span {{
            display: block;
            font-size: 1.2em;
            color: #2c3e50;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .summary-card.findings {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}

        .summary-card.services {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}

        .summary-card.hosts {{
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }}

        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 0.9em;
            opacity: 0.9;
        }}

        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
        }}

        .summary-card .note {{
            margin-top: 10px;
            font-size: 0.75em;
            opacity: 0.85;
            font-style: italic;
            line-height: 1.3;
        }}

        .severity-counts {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 30px;
        }}

        .severity-count {{
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
        }}

        .severity-count.critical {{
            background-color: #c0392b;
            color: white;
        }}

        .severity-count.high {{
            background-color: #e74c3c;
            color: white;
        }}

        .severity-count.medium {{
            background-color: #f39c12;
            color: white;
        }}

        .severity-count.low {{
            background-color: #3498db;
            color: white;
        }}

        .severity-count.info {{
            background-color: #95a5a6;
            color: white;
        }}

        .quick-fix {{
            background-color: #fff9e6;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
        }}

        .quick-fix p {{
            margin-top: 10px;
            color: #555;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{
            background-color: #c0392b;
            color: white;
        }}

        .severity-badge.high {{
            background-color: #e74c3c;
            color: white;
        }}

        .severity-badge.medium {{
            background-color: #f39c12;
            color: white;
        }}

        .severity-badge.low {{
            background-color: #3498db;
            color: white;
        }}

        .severity-badge.info {{
            background-color: #95a5a6;
            color: white;
        }}

        .host-card {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}

        .host-info {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}

        .host-info p {{
            margin: 5px 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}

        th {{
            background-color: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}

        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }}

        tr:hover {{
            background-color: #f8f9fa;
        }}

        .state-open {{
            color: #27ae60;
            font-weight: bold;
        }}

        .state-filtered {{
            color: #f39c12;
            font-weight: bold;
        }}

        pre {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: "Courier New", monospace;
            font-size: 0.9em;
        }}

        .appendix {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
        }}

        @media print {{
            body {{
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{context['title']}</h1>
            <p>Generated: {context['generated_at']}</p>
        </div>

        <div class="metadata">
            <div class="metadata-item">
                <strong>Scan Profile</strong>
                <span>{context['profile'].upper()}</span>
            </div>
            <div class="metadata-item">
                <strong>Duration</strong>
                <span>{context['duration']}</span>
            </div>
            <div class="metadata-item">
                <strong>Scanner Version</strong>
                <span>v{context['scanner_version']}</span>
            </div>
            <div class="metadata-item">
                <strong>Nmap Version</strong>
                <span>{context['nmap_version']}</span>
            </div>
            <div class="metadata-item">
                <strong>Platform</strong>
                <span>{context['platform']}</span>
            </div>
        </div>

        <h2>Summary</h2>
        <div class="summary-cards">
            <div class="summary-card hosts">
                <h3>Hosts Up</h3>
                <div class="value">{context['hosts_up']}/{context['hosts_discovered']}</div>
                <div class="note">
                    {'Phase 2 ran with -Pn (trust discovery). Silent hosts were scanned anyway; counts may be closer.' if context['trust_discovery'] else
                     ('Some devices respond to ARP/ICMP but block TCP probes; they may appear discovered yet not up during scanning.' if context['hosts_unresponsive_after_discovery'] > 0 else '')}
                </div>
            </div>
            <div class="summary-card services">
                <h3>Open Ports</h3>
                <div class="value">{context['services_open']}</div>
            </div>
            <div class="summary-card findings">
                <h3>Security Findings</h3>
                <div class="value">{context['findings_total']}</div>
            </div>
        </div>

        <div class="severity-counts">
            <div class="severity-count critical">CRITICAL: {context['severity_counts'].get('critical', 0)}</div>
            <div class="severity-count high">HIGH: {context['severity_counts'].get('high', 0)}</div>
            <div class="severity-count medium">MEDIUM: {context['severity_counts'].get('medium', 0)}</div>
            <div class="severity-count low">LOW: {context['severity_counts'].get('low', 0)}</div>
            <div class="severity-count info">INFO: {context['severity_counts'].get('info', 0)}</div>
        </div>

        {f"<h2>Top Quick Fixes</h2>{quick_fixes_html}" if context['quick_fixes'] else ""}

        <h2>Detailed Results</h2>
        {hosts_html if hosts_html else ""}
        {no_tcp_hosts_html}
        {f"<p>No hosts found.</p>" if not hosts_html and not no_tcp_hosts_html else ""}

        <div class="appendix">
            <h2>Appendix: Scan Configuration</h2>
            <h3>Nmap Commands Executed</h3>
            {commands_html}
        </div>
    </div>
</body>
</html>
"""

    return html
