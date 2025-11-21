"""
Basic tests for truslan.

Tests core functionality including discovery, profile planning, and findings engine.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from truslan.core.models import (
    ScanProfile, ScanOptions, Host, Service, Finding, FindingSeverity,
    PortState, ScanResult, ScanMeta, OSMatch
)
from truslan.core.scanners import build_scan_plan
from truslan.core.checks import analyze_scan_results, get_top_quick_fixes
from truslan.core.discovery import _calculate_network_cidr, _netmask_to_prefix, _discover_windows_fallback
from datetime import datetime


class TestDiscovery:
    """Test network discovery functions."""

    def test_calculate_network_cidr_ipv4(self):
        """Test CIDR calculation for IPv4."""
        cidr = _calculate_network_cidr("192.168.1.10", 24)
        assert cidr == "192.168.1.0/24"

        cidr = _calculate_network_cidr("10.0.5.100", 16)
        assert cidr == "10.0.0.0/16"

    def test_calculate_network_cidr_invalid(self):
        """Test CIDR calculation with invalid input."""
        cidr = _calculate_network_cidr("invalid", 24)
        assert cidr is None

    def test_netmask_to_prefix(self):
        """Test netmask to prefix conversion."""
        assert _netmask_to_prefix("255.255.255.0") == 24
        assert _netmask_to_prefix("255.255.0.0") == 16
        assert _netmask_to_prefix("255.0.0.0") == 8

    @patch("truslan.core.discovery.subprocess.run")
    def test_windows_fallback_parses_spanish_ipconfig(self, mock_run):
        """Ensure Windows fallback handles localized ipconfig output."""
        ipconfig_output = """
Adaptador de Ethernet Ethernet 3:

   Vínculo: dirección IPv6 local. . . : fe80::6dc8:c826:2b6c:75d1%13
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.56.1
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0

Adaptador de LAN inalámbrica WiFi 2:

   Vínculo: dirección IPv6 local. . . : fe80::d46e:9689:3cec:45d3%15
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.50.46
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
"""

        mock_run.return_value = Mock(returncode=0, stdout=ipconfig_output, stderr="")

        cidrs = _discover_windows_fallback()

        assert sorted(cidrs) == ["192.168.50.0/24", "192.168.56.0/24"]


class TestScanPlanning:
    """Test scan plan generation."""

    def test_safe_profile_planning(self):
        """Test safe profile generates correct nmap options."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=["192.168.1.0/24"],
            mode="top",
            top_ports=200,
            port_list=None,
            udp=False
        )

        invocations = build_scan_plan(options)

        # Two-phase scanning: discovery invocation only
        assert len(invocations) >= 1
        discovery_inv = invocations[0]

        # Discovery scan should use -sn (ping scan)
        args = discovery_inv.arguments
        assert "-sn" in args
        assert "-n" in args

    def test_standard_profile_planning(self):
        """Test standard profile generates correct options."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=["192.168.1.0/24"],
            mode="top",
            top_ports=1000,
            port_list=None,
            udp=False
        )

        invocations = build_scan_plan(options)

        # Two-phase scanning: discovery invocation
        assert len(invocations) >= 1
        discovery_inv = invocations[0]

        # Discovery scan
        assert "-sn" in discovery_inv.arguments

    def test_aggressive_profile_planning(self):
        """Test aggressive profile planning."""
        options = ScanOptions(
            profile=ScanProfile.AGGRESSIVE,
            cidr_list=["192.168.1.0/24"],
            mode="top",
            top_ports=2000,
            port_list=None,
            udp=False,
            authorized=True
        )

        invocations = build_scan_plan(options)

        # Two-phase scanning: discovery invocation
        assert len(invocations) >= 1
        discovery_inv = invocations[0]

        # Discovery scan
        assert "-sn" in discovery_inv.arguments

    def test_mode_top_validation(self):
        """Test top-ports mode."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=["192.168.1.0/24"],
            mode="top",
            top_ports=500,
            port_list=None,
            udp=False
        )

        invocations = build_scan_plan(options)

        # Two-phase scanning returns discovery invocation
        assert len(invocations) >= 1

    def test_mode_ports_validation(self):
        """Test specific ports mode."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=["192.168.1.0/24"],
            mode="ports",
            top_ports=None,
            port_list="22,80,443",
            udp=False
        )

        invocations = build_scan_plan(options)

        # Two-phase scanning returns discovery invocation
        assert len(invocations) >= 1

    def test_udp_scan_planning(self):
        """Test UDP scan is added when requested (if privileged)."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=["192.168.1.0/24"],
            mode="top",
            top_ports=1000,
            port_list=None,
            udp=True
        )

        # Two-phase scanning: UDP scans are built dynamically after discovery
        invocations = build_scan_plan(options)

        # Should have at least discovery invocation
        assert len(invocations) >= 1
        assert "-sn" in invocations[0].arguments


class TestSecurityChecks:
    """Test security checks and findings engine."""

    def test_check_rdp_exposed(self):
        """Test RDP exposure detection."""
        host = Host(
            ip="192.168.1.10",
            state="up",
            services=[
                Service(
                    port=3389,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service="rdp"
                )
            ]
        )

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=Mock(),
            started_at=datetime.now()
        )

        result = ScanResult(
            meta=meta,
            hosts=[host],
            summary={}
        )

        analyzed = analyze_scan_results(result)

        # Should have RDP finding
        findings = analyzed.hosts[0].findings
        assert any(f.finding_id == "RDP-EXPOSED" for f in findings)

        rdp_finding = next(f for f in findings if f.finding_id == "RDP-EXPOSED")
        assert rdp_finding.severity == FindingSeverity.HIGH
        assert "RDP" in rdp_finding.title

    def test_check_smb_exposed(self):
        """Test SMB exposure detection."""
        host = Host(
            ip="192.168.1.10",
            state="up",
            services=[
                Service(
                    port=445,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service="smb"
                )
            ]
        )

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=Mock(),
            started_at=datetime.now()
        )

        result = ScanResult(
            meta=meta,
            hosts=[host],
            summary={}
        )

        analyzed = analyze_scan_results(result)

        findings = analyzed.hosts[0].findings
        assert any(f.finding_id == "SMB-EXPOSED" for f in findings)

    def test_check_telnet_exposed(self):
        """Test Telnet exposure detection (high severity)."""
        host = Host(
            ip="192.168.1.10",
            state="up",
            services=[
                Service(
                    port=23,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service="telnet"
                )
            ]
        )

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=Mock(),
            started_at=datetime.now()
        )

        result = ScanResult(
            meta=meta,
            hosts=[host],
            summary={}
        )

        analyzed = analyze_scan_results(result)

        findings = analyzed.hosts[0].findings
        telnet_findings = [f for f in findings if f.finding_id == "TELNET-EXPOSED"]
        assert len(telnet_findings) > 0
        assert telnet_findings[0].severity == FindingSeverity.HIGH

    def test_http_https_redirect_check(self):
        """Test HTTP/HTTPS redirect recommendation."""
        host = Host(
            ip="192.168.1.10",
            state="up",
            services=[
                Service(port=80, protocol="tcp", state=PortState.OPEN, service="http"),
                Service(port=443, protocol="tcp", state=PortState.OPEN, service="https")
            ]
        )

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=Mock(),
            started_at=datetime.now()
        )

        result = ScanResult(
            meta=meta,
            hosts=[host],
            summary={}
        )

        analyzed = analyze_scan_results(result)

        findings = analyzed.hosts[0].findings
        assert any("HTTP" in f.finding_id for f in findings)

    def test_get_top_quick_fixes(self):
        """Test top quick fixes extraction."""
        host1 = Host(
            ip="192.168.1.10",
            state="up",
            services=[
                Service(port=3389, protocol="tcp", state=PortState.OPEN, service="rdp")
            ],
            findings=[
                Finding(
                    finding_id="RDP-EXPOSED",
                    severity=FindingSeverity.HIGH,
                    title="RDP Exposed",
                    description="Test",
                    remediation="Fix it",
                    host="192.168.1.10",
                    port=3389
                )
            ]
        )

        host2 = Host(
            ip="192.168.1.11",
            state="up",
            services=[
                Service(port=3389, protocol="tcp", state=PortState.OPEN, service="rdp")
            ],
            findings=[
                Finding(
                    finding_id="RDP-EXPOSED",
                    severity=FindingSeverity.HIGH,
                    title="RDP Exposed",
                    description="Test",
                    remediation="Fix it",
                    host="192.168.1.11",
                    port=3389
                )
            ]
        )

        meta = ScanMeta(
            profile=ScanProfile.SAFE,
            options=Mock(),
            started_at=datetime.now()
        )

        result = ScanResult(
            meta=meta,
            hosts=[host1, host2],
            summary={}
        )

        quick_fixes = get_top_quick_fixes(result, limit=5)

        assert len(quick_fixes) > 0
        assert quick_fixes[0]["id"] == "RDP-EXPOSED"
        assert quick_fixes[0]["count"] == 2


class TestModels:
    """Test data models."""

    def test_scan_profile_enum(self):
        """Test ScanProfile enum."""
        assert ScanProfile.SAFE.value == "safe"
        assert ScanProfile.STANDARD.value == "standard"
        assert ScanProfile.AGGRESSIVE.value == "aggressive"

    def test_finding_severity_enum(self):
        """Test FindingSeverity enum."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"

    def test_service_to_dict(self):
        """Test Service to_dict method."""
        service = Service(
            port=80,
            protocol="tcp",
            state=PortState.OPEN,
            service="http",
            product="nginx",
            version="1.18.0"
        )

        d = service.to_dict()
        assert d["port"] == 80
        assert d["protocol"] == "tcp"
        assert d["state"] == "open"
        assert d["service"] == "http"
        assert d["product"] == "nginx"

    def test_host_to_dict(self):
        """Test Host to_dict method."""
        host = Host(
            ip="192.168.1.10",
            hostname="server.local",
            state="up",
            services=[
                Service(port=22, protocol="tcp", state=PortState.OPEN, service="ssh")
            ]
        )

        d = host.to_dict()
        assert d["ip"] == "192.168.1.10"
        assert d["hostname"] == "server.local"
        assert d["state"] == "up"
        assert len(d["services"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
