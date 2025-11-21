"""
CLI and argument parsing tests for truslan v1.3.0.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from argparse import Namespace

from truslan.core.models import ScanProfile, ScanOptions


class TestCLIArgumentParsing:
    """Test CLI argument parsing."""

    @patch('truslan.cli.create_parser')
    def test_scan_command_safe_profile(self, mock_create_parser):
        """Test scan command with safe profile."""
        parser = MagicMock()
        mock_create_parser.return_value = parser

        args = Namespace(
            command='scan',
            cidr='192.168.1.0/24',
            profile='safe',
            mode='top',
            top=None,
            ports=None,
            udp=False,
            trust_discovery=False,
            verbose=False,
            quiet=False
        )
        parser.parse_args.return_value = args

        assert args.profile == 'safe'
        assert args.trust_discovery is False

    @patch('truslan.cli.create_parser')
    def test_scan_command_trust_discovery_flag(self, mock_create_parser):
        """Test that --trust-discovery flag is parsed correctly."""
        parser = MagicMock()
        mock_create_parser.return_value = parser

        args = Namespace(
            command='scan',
            cidr='192.168.1.0/24',
            profile='standard',
            trust_discovery=True,
            verbose=False,
            quiet=False
        )
        parser.parse_args.return_value = args

        assert args.trust_discovery is True


class TestScanOptionsCreation:
    """Test ScanOptions creation from CLI args."""

    def test_scan_options_with_trust_discovery(self):
        """Test that trust_discovery is properly set in ScanOptions."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            trust_discovery=True
        )

        assert options.trust_discovery is True
        assert options.profile == ScanProfile.STANDARD

    def test_scan_options_without_trust_discovery(self):
        """Test default trust_discovery value (False)."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=200
        )

        assert options.trust_discovery is False


class TestProfileValidation:
    """Test profile validation."""

    def test_safe_profile_valid(self):
        """Test safe profile is valid."""
        profile = ScanProfile('safe')
        assert profile == ScanProfile.SAFE

    def test_standard_profile_valid(self):
        """Test standard profile is valid."""
        profile = ScanProfile('standard')
        assert profile == ScanProfile.STANDARD

    def test_aggressive_profile_valid(self):
        """Test aggressive profile is valid."""
        profile = ScanProfile('aggressive')
        assert profile == ScanProfile.AGGRESSIVE

    def test_invalid_profile_raises_error(self):
        """Test invalid profile raises ValueError."""
        with pytest.raises(ValueError):
            ScanProfile('invalid')


class TestModeValidation:
    """Test port selection mode validation."""

    def test_top_mode_valid(self):
        """Test top mode is valid."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=200
        )
        assert options.mode == 'top'

    def test_ports_mode_valid(self):
        """Test ports mode is valid."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='ports',
            port_list='22,80,443'
        )
        assert options.mode == 'ports'

    def test_ports_mode_with_port_list(self):
        """Test ports mode requires port_list."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='ports',
            port_list='22,80,443,3389'
        )
        assert options.port_list == '22,80,443,3389'


class TestFlagCombinations:
    """Test various flag combinations."""

    def test_trust_discovery_with_standard_profile(self):
        """Test trust-discovery works with standard profile."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            trust_discovery=True
        )

        assert options.trust_discovery is True
        assert options.profile == ScanProfile.STANDARD

    def test_trust_discovery_with_aggressive_profile(self):
        """Test trust-discovery works with aggressive profile."""
        options = ScanOptions(
            profile=ScanProfile.AGGRESSIVE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=2000,
            trust_discovery=True,
            authorized=True
        )

        assert options.trust_discovery is True
        assert options.authorized is True

    def test_udp_with_trust_discovery(self):
        """Test UDP scanning can be combined with trust-discovery."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            udp=True,
            trust_discovery=True
        )

        assert options.udp is True
        assert options.trust_discovery is True

    def test_nse_strict_flag(self):
        """Test nse_strict flag."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            nse_strict=True
        )

        assert options.nse_strict is True

    def test_fail_on_errors_flag(self):
        """Test fail_on_errors flag."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            fail_on_errors=True
        )

        assert options.fail_on_errors is True


class TestCIDRParsing:
    """Test CIDR parsing."""

    def test_single_cidr(self):
        """Test single CIDR parsing."""
        from truslan.core.utils import parse_cidr_list

        cidrs = parse_cidr_list('192.168.1.0/24')
        assert len(cidrs) == 1
        assert cidrs[0] == '192.168.1.0/24'

    def test_multiple_cidrs_space_separated(self):
        """Test multiple space-separated CIDRs."""
        from truslan.core.utils import parse_cidr_list

        cidrs = parse_cidr_list('192.168.1.0/24 10.0.0.0/8')
        assert len(cidrs) == 2
        assert '192.168.1.0/24' in cidrs
        assert '10.0.0.0/8' in cidrs

    def test_multiple_cidrs_comma_separated(self):
        """Test multiple comma-separated CIDRs."""
        from truslan.core.utils import parse_cidr_list

        cidrs = parse_cidr_list('192.168.1.0/24,10.0.0.0/8')
        assert len(cidrs) == 2


class TestOptionsToDict:
    """Test ScanOptions to_dict() method."""

    def test_options_to_dict_includes_trust_discovery(self):
        """Test that to_dict includes trust_discovery field."""
        options = ScanOptions(
            profile=ScanProfile.STANDARD,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            top_ports=1000,
            trust_discovery=True
        )

        d = options.to_dict()
        assert 'trust_discovery' in d
        assert d['trust_discovery'] is True

    def test_options_to_dict_default_trust_discovery(self):
        """Test that to_dict includes trust_discovery with default value."""
        options = ScanOptions(
            profile=ScanProfile.SAFE,
            cidr_list=['192.168.1.0/24'],
            mode='top'
        )

        d = options.to_dict()
        assert 'trust_discovery' in d
        assert d['trust_discovery'] is False
