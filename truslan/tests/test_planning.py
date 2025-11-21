"""
Scan planning and invocation building tests for truslan v1.3.0.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from truslan.core.models import (
    ScanProfile, ScanOptions, NmapInvocation
)
from truslan.core.scanners import (
    build_scan_plan, _build_tcp_scan, _build_udp_scan, _build_discovery_scan
)


class TestDiscoveryScanBuilding:
    """Test discovery scan invocation building."""

    def test_discovery_scan_basic(self):
        """Test basic discovery scan building."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top'
        )

        inv = _build_discovery_scan(options)

        assert inv.targets == ['192.168.1.0/24']
        assert '-sn' in inv.arguments  # Ping scan
        assert '-n' in inv.arguments   # No DNS

    def test_discovery_scan_multiple_networks(self):
        """Test discovery scan with multiple networks."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24', '10.0.0.0/24'],
            mode='top'
        )

        inv = _build_discovery_scan(options)

        assert len(inv.targets) == 2
        assert '192.168.1.0/24' in inv.targets
        assert '10.0.0.0/24' in inv.targets


class TestTCPScanBuilding:
    """Test TCP scan invocation building."""

    def test_tcp_scan_without_trust_discovery(self):
        """Test TCP scan without trust-discovery flag."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            trust_discovery=False
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10', '192.168.1.11'],
            nse_script_set=None
        )

        # Should NOT have -Pn
        assert '-Pn' not in inv.arguments
        assert '-sV' in inv.arguments  # Service version detection

    def test_tcp_scan_with_trust_discovery(self):
        """Test TCP scan with trust-discovery flag applies -Pn."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            trust_discovery=True
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10', '192.168.1.11'],
            nse_script_set=None
        )

        # Should have -Pn at the beginning
        assert '-Pn' in inv.arguments
        assert inv.arguments.index('-Pn') == 0  # First argument
        assert '-sV' in inv.arguments

    def test_tcp_scan_trust_discovery_in_description(self):
        """Test that trust-discovery is noted in scan description."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            trust_discovery=True
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Description should mention trust-discovery
        assert 'trust-discovery' in inv.description.lower() or '-Pn' in inv.description

    @patch('truslan.core.scanners.is_root', return_value=True)
    def test_tcp_scan_syn_scan_as_root(self, mock_is_root):
        """Test TCP scan uses SYN scan when running as root."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should use SYN scan
        assert '-sS' in inv.arguments
        assert '-sT' not in inv.arguments

    @patch('truslan.core.scanners.is_root', return_value=False)
    def test_tcp_scan_connect_scan_without_root(self, mock_is_root):
        """Test TCP scan uses Connect scan when not root."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should use Connect scan
        assert '-sT' in inv.arguments
        assert '-sS' not in inv.arguments


class TestUDPScanBuilding:
    """Test UDP scan invocation building."""

    @patch('truslan.core.scanners.is_root', return_value=True)
    def test_udp_scan_without_trust_discovery(self, mock_is_root):
        """Test UDP scan without trust-discovery flag."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            udp=True,
            trust_discovery=False
        )

        inv = _build_udp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should NOT have -Pn
        assert '-Pn' not in inv.arguments
        assert '-sU' in inv.arguments

    @patch('truslan.core.scanners.is_root', return_value=True)
    def test_udp_scan_with_trust_discovery(self, mock_is_root):
        """Test UDP scan with trust-discovery flag applies -Pn."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            udp=True,
            trust_discovery=True
        )

        inv = _build_udp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should have -Pn at the beginning
        assert '-Pn' in inv.arguments
        assert inv.arguments.index('-Pn') == 0
        assert '-sU' in inv.arguments


class TestProfileMapping:
    """Test profile to nmap options mapping."""

    def test_safe_profile_mapping(self):
        """Test SAFE profile generates appropriate options."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=200
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Safe profile should have version-light
        assert '--version-light' in inv.arguments
        # Should not have OS detection options
        assert '-O' not in inv.arguments

    def test_standard_profile_mapping(self):
        """Test STANDARD profile generates appropriate options."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Standard profile should have version-light
        assert '--version-light' in inv.arguments

    @patch('truslan.core.scanners.is_root', return_value=True)
    def test_aggressive_profile_mapping(self, mock_is_root):
        """Test AGGRESSIVE profile generates appropriate options."""
        options = ScanOptions(
            profile=ScanProfile.AGGRESSIVE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=2000,
            authorized=True
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Aggressive profile should have version-all
        assert '--version-all' in inv.arguments
        # Should have OS detection
        assert '-O' in inv.arguments


class TestPortModes:
    """Test port selection modes."""

    def test_top_ports_mode(self):
        """Test top ports mode."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=500
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should have top-ports argument
        assert '--top-ports' in inv.arguments
        args_str = ' '.join(inv.arguments)
        assert '500' in args_str

    def test_specific_ports_mode(self):
        """Test specific ports mode."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='ports',
            port_list='22,80,443,3389'
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Should have -p argument
        assert '-p' in inv.arguments
        args_str = ' '.join(inv.arguments)
        assert '22,80,443,3389' in args_str


class TestTimingOptions:
    """Test timing template options."""

    def test_default_timing(self):
        """Test default timing is T3."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            timing='T3'
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        assert '-T3' in inv.arguments

    def test_fast_timing(self):
        """Test fast timing T4."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            timing='T4'
        )

        inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        assert '-T4' in inv.arguments


class TestTrustDiscoveryIntegration:
    """Test trust-discovery flag integration throughout scan building."""

    def test_trust_discovery_false_by_default(self):
        """Test that trust_discovery defaults to False."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top'
        )

        assert options.trust_discovery is False

    def test_trust_discovery_can_be_enabled(self):
        """Test that trust_discovery can be explicitly enabled."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            trust_discovery=True
        )

        assert options.trust_discovery is True

    @patch('truslan.core.scanners.is_root', return_value=True)
    def test_trust_discovery_applies_to_tcp_and_udp(self, mock_is_root):
        """Test that trust-discovery applies to both TCP and UDP scans."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            udp=True,
            trust_discovery=True
        )

        tcp_inv = _build_tcp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        udp_inv = _build_udp_scan(
            options=options,
            targets=['192.168.1.10'],
            nse_script_set=None
        )

        # Both should have -Pn
        assert '-Pn' in tcp_inv.arguments
        assert '-Pn' in udp_inv.arguments


class TestNmapInvocation:
    """Test NmapInvocation model."""

    def test_invocation_to_command(self):
        """Test converting invocation to command list."""
        inv = NmapInvocation(
            targets=['192.168.1.10'],
            arguments=['-sn', '-n'],
            description='Test scan'
        )

        cmd = inv.to_command()

        assert cmd[0] == 'nmap'
        assert '-sn' in cmd
        assert '-n' in cmd
        assert '192.168.1.10' in cmd

    def test_invocation_to_string(self):
        """Test converting invocation to string."""
        inv = NmapInvocation(
            targets=['192.168.1.10', '192.168.1.11'],
            arguments=['-sT', '-p', '22,80,443'],
            description='Port scan'
        )

        cmd_str = inv.to_string()

        assert 'nmap' in cmd_str
        assert '-sT' in cmd_str
        assert '192.168.1.10' in cmd_str
        assert '192.168.1.11' in cmd_str

    def test_invocation_with_pn_flag(self):
        """Test invocation with -Pn flag."""
        inv = NmapInvocation(
            targets=['192.168.1.10'],
            arguments=['-Pn', '-sS', '-p', '1-1000'],
            description='Trust discovery scan'
        )

        cmd = inv.to_command()

        # -Pn should be in the command
        assert '-Pn' in cmd
        # Should appear early in arguments
        pn_index = cmd.index('-Pn')
        nmap_index = cmd.index('nmap')
        assert pn_index > nmap_index
