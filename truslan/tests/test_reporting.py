"""
Tests for HTML report generation (v1.2.6).

Tests:
- Quick Fixes text deduplication (appears once in Top Quick Fixes section)
- No TCP services group shows one-liner note instead of full remediation
"""

import pytest
from pathlib import Path
from datetime import datetime
from truslan.core.models import (
    ScanResult, ScanMeta, ScanProfile, ScanOptions, Host, Finding, FindingSeverity
)
from truslan.reports.html import generate_html_report


class TestQuickFixesDedup:
    """Test that Quick Fixes text is not duplicated in HTML report."""

    def test_quick_fixes_dedup_single_occurrence(self, tmp_path):
        """Test that full remediation text appears only once in Top Quick Fixes section."""
        # Create scan result with many hosts with no TCP services
        hosts = []
        for i in range(1, 21):  # 20 hosts
            host = Host(
                ip=f"192.168.1.{i}",
                state="up",
                services=[]
            )
            # Add NO_TCP_OPEN_IN_PROFILE finding
            host.findings = [
                Finding(
                    finding_id="NO_TCP_OPEN_IN_PROFILE",
                    severity=FindingSeverity.INFO,
                    title="No TCP services found in selected profile",
                    description=f"Host is up but has no TCP ports open.",
                    remediation="No TCP ports found even in aggressive profile scan. Recommendations: (1) Switch to explicit ports mode targeting your environment's business services: --mode ports -p <custom-port-list>",
                    host=host.ip
                )
            ]
            hosts.append(host)

        meta = ScanMeta(
            profile=ScanProfile.AGGRESSIVE,
            options=ScanOptions(
                profile=ScanProfile.AGGRESSIVE,
                cidr_list=['192.168.1.0/24'],
                mode='top',
                top_ports=1000
            ),
            started_at=datetime.now(),
            finished_at=datetime.now(),
            nmap_commands=['nmap -sn 192.168.1.0/24'],
            nmap_version='7.80'
        )

        result = ScanResult(
            meta=meta,
            hosts=hosts,
            summary={
                'hosts_total': 20,
                'hosts_up': 20,
                'hosts_discovered': 20,
                'hosts_marked_up_by_scanner': 20,
                'services_total': 0,
                'services_open': 0,
                'findings_total': 20,
                'findings_by_severity': {'info': 20},
                'duration_seconds': 60.0
            }
        )

        # Generate HTML report
        output_path = tmp_path / "report.html"
        generate_html_report(result, output_path)

        # Read the HTML
        html_content = output_path.read_text()

        # Count occurrences of the long remediation text
        # The full remediation should appear ONLY in the Top Quick Fixes section
        remediation_snippet = "No TCP ports found even in aggressive profile"
        occurrences = html_content.count(remediation_snippet)

        # Should appear exactly once (in Top Quick Fixes)
        assert occurrences == 1, f"Remediation text appears {occurrences} times, expected 1"

    def test_no_tcp_group_has_oneliner(self, tmp_path):
        """Test that No TCP services group shows one-liner note."""
        # Create scan result with hosts with no TCP services
        hosts = []
        for i in range(1, 6):  # 5 hosts
            host = Host(
                ip=f"192.168.1.{i}",
                state="up",
                services=[]
            )
            host.findings = [
                Finding(
                    finding_id="NO_TCP_OPEN_IN_PROFILE",
                    severity=FindingSeverity.INFO,
                    title="No TCP services found in selected profile",
                    description=f"Host is up but has no TCP ports open.",
                    remediation="No action needed; this host exposes no TCP ports within the safe profile.",
                    host=host.ip
                )
            ]
            hosts.append(host)

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=ScanOptions(
                profile=ScanProfile.SAFE,
                cidr_list=['192.168.1.0/24'],
                mode='top',
                top_ports=100
            ),
            started_at=datetime.now(),
            finished_at=datetime.now(),
            nmap_commands=['nmap -sn 192.168.1.0/24'],
            nmap_version='7.80'
        )

        result = ScanResult(
            meta=meta,
            hosts=hosts,
            summary={
                'hosts_total': 5,
                'hosts_up': 5,
                'hosts_discovered': 5,
                'hosts_marked_up_by_scanner': 5,
                'services_total': 0,
                'services_open': 0,
                'findings_total': 5,
                'findings_by_severity': {'info': 5},
                'duration_seconds': 30.0
            }
        )

        # Generate HTML report
        output_path = tmp_path / "report.html"
        generate_html_report(result, output_path)

        # Read the HTML
        html_content = output_path.read_text()

        # Check for the one-liner in the No TCP services group
        assert "No TCP ports found under the SAFE profile; see Top Quick Fixes for next steps" in html_content

        # Check that "Hosts with No TCP Services" section exists
        assert "Hosts with No TCP Services" in html_content
        assert "(5 hosts)" in html_content

    def test_mixed_hosts_report_structure(self, tmp_path):
        """Test report with both interesting hosts and no-TCP hosts."""
        from truslan.core.models import Service, PortState

        hosts = []

        # Add 2 hosts with services
        for i in range(1, 3):
            host = Host(
                ip=f"192.168.1.{i}",
                state="up",
                services=[
                    Service(port=22, protocol="tcp", state=PortState.OPEN, service="ssh"),
                    Service(port=80, protocol="tcp", state=PortState.OPEN, service="http")
                ]
            )
            host.findings = [
                Finding(
                    finding_id="SSH_VERSION_EXPOSED",
                    severity=FindingSeverity.LOW,
                    title="SSH version exposed",
                    description="SSH version is exposed",
                    remediation="Configure SSH to not expose version",
                    host=host.ip
                )
            ]
            hosts.append(host)

        # Add 3 hosts without TCP services
        for i in range(10, 13):
            host = Host(
                ip=f"192.168.1.{i}",
                state="up",
                services=[]
            )
            host.findings = [
                Finding(
                    finding_id="NO_TCP_OPEN_IN_PROFILE",
                    severity=FindingSeverity.INFO,
                    title="No TCP services found",
                    description="No TCP ports open",
                    remediation="No action needed; this host exposes no TCP ports within the safe profile.",
                    host=host.ip
                )
            ]
            hosts.append(host)

        meta = ScanMeta(
            profile=ScanProfile.STANDARD,
            options=ScanOptions(
                profile=ScanProfile.STANDARD,
                cidr_list=['192.168.1.0/24'],
                mode='top',
                top_ports=100
            ),
            started_at=datetime.now(),
            finished_at=datetime.now(),
            nmap_commands=['nmap -sn 192.168.1.0/24'],
            nmap_version='7.80'
        )

        result = ScanResult(
            meta=meta,
            hosts=hosts,
            summary={
                'hosts_total': 5,
                'hosts_up': 5,
                'hosts_discovered': 5,
                'hosts_marked_up_by_scanner': 5,
                'services_total': 4,
                'services_open': 4,
                'findings_total': 5,
                'findings_by_severity': {'info': 3, 'low': 2},
                'duration_seconds': 45.0
            }
        )

        # Generate HTML report
        output_path = tmp_path / "report.html"
        generate_html_report(result, output_path)

        # Read the HTML
        html_content = output_path.read_text()

        # Should have both sections
        assert "Hosts with No TCP Services (3 hosts)" in html_content

        # Check for interesting hosts (should show individual host cards)
        assert "192.168.1.1" in html_content
        assert "192.168.1.2" in html_content

        # Check that no-TCP hosts are in consolidated table
        assert "192.168.1.10" in html_content
        assert "192.168.1.11" in html_content
        assert "192.168.1.12" in html_content


class TestHTMLReportStructure:
    """Test overall HTML report structure."""

    def test_report_has_all_sections(self, tmp_path):
        """Test that report includes all expected sections."""
        from truslan.core.models import Service, PortState

        host = Host(
            ip="192.168.1.100",
            state="up",
            services=[
                Service(port=445, protocol="tcp", state=PortState.OPEN, service="microsoft-ds")
            ]
        )
        host.findings = [
            Finding(
                finding_id="SMB_EXPOSED",
                severity=FindingSeverity.MEDIUM,
                title="SMB exposed",
                description="SMB port is exposed",
                remediation="Restrict SMB access",
                host=host.ip
            )
        ]

        meta = ScanMeta(
            profile=ScanProfile.STANDARD,
            options=ScanOptions(
                profile=ScanProfile.STANDARD,
                cidr_list=['192.168.1.0/24'],
                mode='top'
            ),
            started_at=datetime.now(),
            finished_at=datetime.now(),
            nmap_commands=['nmap -Pn -sT 192.168.1.100'],
            nmap_version='7.80'
        )

        result = ScanResult(
            meta=meta,
            hosts=[host],
            summary={
                'hosts_total': 1,
                'hosts_up': 1,
                'hosts_discovered': 1,
                'hosts_marked_up_by_scanner': 1,
                'services_total': 1,
                'services_open': 1,
                'findings_total': 1,
                'findings_by_severity': {'medium': 1},
                'duration_seconds': 10.0
            }
        )

        # Generate HTML report
        output_path = tmp_path / "report.html"
        generate_html_report(result, output_path)

        # Read the HTML
        html_content = output_path.read_text()

        # Check for major sections
        assert "TrusLAN — LAN Exposure Scan Report" in html_content
        assert "Summary" in html_content
        assert "Top Quick Fixes" in html_content
        assert "192.168.1.100" in html_content
        assert "SMB exposed" in html_content

    def test_empty_report(self, tmp_path):
        """Test report generation with no hosts."""
        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=ScanOptions(
                profile=ScanProfile.SAFE,
                cidr_list=['192.168.1.0/24'],
                mode='top'
            ),
            started_at=datetime.now(),
            finished_at=datetime.now(),
            nmap_commands=['nmap -sn 192.168.1.0/24'],
            nmap_version='7.80'
        )

        result = ScanResult(
            meta=meta,
            hosts=[],
            summary={
                'hosts_total': 0,
                'hosts_up': 0,
                'hosts_discovered': 0,
                'hosts_marked_up_by_scanner': 0,
                'services_total': 0,
                'services_open': 0,
                'findings_total': 0,
                'findings_by_severity': {},
                'duration_seconds': 5.0
            }
        )

        # Generate HTML report
        output_path = tmp_path / "report.html"
        generate_html_report(result, output_path)

        # Should generate without error
        assert output_path.exists()

        html_content = output_path.read_text()
        assert "TrusLAN — LAN Exposure Scan Report" in html_content
