"""
CSV report generation for truslan.

Generates findings in CSV format for easy import into spreadsheets.
"""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Any

from ..core.models import ScanResult, Host, Finding

logger = logging.getLogger("truslan")


def generate_csv_report(result: ScanResult, output_path: Path) -> None:
    """
    Generate CSV report of findings.

    Args:
        result: Scan result with hosts and findings
        output_path: Path to output CSV file
    """
    logger.info(f"Generating CSV report: {output_path}")

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    # Header
    headers = [
        "host",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "state",
        "finding_id",
        "severity",
        "title",
        "remediation"
    ]

    # Collect all findings with service info
    for host in result.hosts:
        for finding in host.findings:
            # Find matching service
            service_info = _find_service(host, finding.port)

            row = {
                "host": host.ip,
                "port": finding.port or "",
                "protocol": finding.protocol or "",
                "service": finding.service or "",
                "product": service_info.get("product", "") if service_info else "",
                "version": service_info.get("version", "") if service_info else "",
                "state": service_info.get("state", "") if service_info else "",
                "finding_id": finding.finding_id,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                "title": finding.title,
                "remediation": finding.remediation
            }
            rows.append(row)

    # Write CSV
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"CSV report written: {len(rows)} findings")


def _find_service(host: Host, port: int) -> Dict[str, Any]:
    """Find service info for a given port on host."""
    for service in host.services:
        if service.port == port:
            return {
                "product": service.product or "",
                "version": service.version or "",
                "state": service.state.value if hasattr(service.state, 'value') else service.state
            }
    return {}
