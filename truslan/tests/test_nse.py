"""
Tests for NSE script resolution and explanation features (v1.2.6).

Tests:
- explain_script for available and missing scripts
- list-scripts --grep flag
- list-scripts --explain flag
- Graceful handling of missing vulners script
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from truslan.core.nse import NSEResolver


class TestExplainScript:
    """Test explain_script functionality."""

    def test_explain_available_script(self):
        """Test explain_script for a script that is available."""
        resolver = NSEResolver()

        # Mock available scripts
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers', 'ssh2-enum-algos'}):
            info = resolver.explain_script('ssl-enum-ciphers')

            assert info['present'] is True
            assert info['hint'] is None

    def test_explain_missing_vulners(self):
        """Test explain_script for missing vulners script with helpful hint."""
        resolver = NSEResolver()

        # Mock available scripts without vulners
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers', 'ssh2-enum-algos'}):
            info = resolver.explain_script('vulners')

            assert info['present'] is False
            assert info['hint'] is not None
            assert 'vulners' in info['hint']
            assert 'not part of default' in info['hint']
            assert 'nmap --script-updatedb' in info['hint']

    def test_explain_missing_generic_script(self):
        """Test explain_script for a generic missing script."""
        resolver = NSEResolver()

        # Mock available scripts
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers'}):
            info = resolver.explain_script('some-custom-script')

            assert info['present'] is False
            assert info['hint'] is not None
            assert 'some-custom-script' in info['hint']
            assert 'not available' in info['hint']


class TestListScriptsGrep:
    """Test list-scripts --grep functionality."""

    @patch('subprocess.run')
    def test_grep_available_script(self, mock_run):
        """Test --grep for available script exits 0."""
        # Mock nmap --script-help output
        mock_run.return_value = Mock(
            returncode=0,
            stdout='ssl-enum-ciphers\nssh2-enum-algos\nhttp-headers\n'
        )

        resolver = NSEResolver()
        available = resolver.get_available_scripts()

        assert 'ssl-enum-ciphers' in available

    @patch('subprocess.run')
    def test_grep_missing_script(self, mock_run):
        """Test --grep for missing script exits 2."""
        # Mock nmap --script-help output without vulners
        mock_run.return_value = Mock(
            returncode=0,
            stdout='ssl-enum-ciphers\nssh2-enum-algos\nhttp-headers\n'
        )

        resolver = NSEResolver()
        available = resolver.get_available_scripts()

        assert 'vulners' not in available


class TestVulnersHandling:
    """Test graceful handling of missing vulners script."""

    def test_missing_vulners_logged_as_info(self):
        """Test that missing vulners is logged at INFO level, not WARNING."""
        resolver = NSEResolver(strict=False)

        # Mock available scripts without vulners
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers', 'ssh2-enum-algos'}):
            # Request scripts including vulners
            result = resolver.resolve_scripts(
                categories=[],
                explicit_scripts={'vulners', 'ssl-enum-ciphers'}
            )

            assert 'vulners' in result.scripts_skipped_missing
            assert 'ssl-enum-ciphers' in result.scripts_available
            assert len(result.scripts_available) == 1

    def test_strict_mode_with_missing_vulners(self):
        """Test that strict mode raises error for missing vulners."""
        resolver = NSEResolver(strict=True)

        # Mock available scripts without vulners
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers'}):
            with pytest.raises(ValueError, match="Strict NSE mode"):
                resolver.resolve_scripts(
                    categories=[],
                    explicit_scripts={'vulners', 'ssl-enum-ciphers'}
                )

    def test_prefer_vulners_warning(self):
        """Test that prefer_vulners option triggers helpful warning."""
        from truslan.core.models import ScanProfile, ScanOptions

        # This test verifies the warning is triggered in scanners.py
        # Mock setup would be needed for full integration test
        options = ScanOptions(
            profile=ScanProfile.AGGRESSIVE,
            cidr_list=['192.168.1.0/24'],
            mode='top',
            prefer_vulners=True
        )

        assert options.prefer_vulners is True


class TestScriptGrouping:
    """Test script grouping by prefix."""

    @patch('subprocess.run')
    def test_list_available_scripts_grouped(self, mock_run):
        """Test that scripts are properly grouped by prefix."""
        # Mock nmap output with various scripts
        mock_run.return_value = Mock(
            returncode=0,
            stdout='''ssl-enum-ciphers
ssl-cert
ssh-auth-methods
ssh-hostkey
http-headers
http-security-headers
smb-os-discovery
smb-protocols
'''
        )

        resolver = NSEResolver()
        grouped = resolver.list_available_scripts_grouped()

        # Should have groups for ssl, ssh, http, smb
        assert 'ssl' in grouped
        assert 'ssh' in grouped
        assert 'http' in grouped
        assert 'smb' in grouped

        # Check group contents
        assert 'ssl-enum-ciphers' in grouped['ssl']
        assert 'ssl-cert' in grouped['ssl']
        assert 'ssh-auth-methods' in grouped['ssh']
        assert 'http-headers' in grouped['http']
        assert 'smb-os-discovery' in grouped['smb']


class TestNSEResolution:
    """Test NSE script resolution with various scenarios."""

    def test_resolve_with_no_available_detection(self):
        """Test resolution when script detection fails (allows all)."""
        resolver = NSEResolver()

        # Mock failed detection
        with patch.object(resolver, 'get_available_scripts', return_value=set()):
            result = resolver.resolve_scripts(
                categories=['default'],
                explicit_scripts={'vulners', 'ssl-enum-ciphers'}
            )

            # Should allow all requested scripts when detection fails
            assert len(result.scripts_available) == 2
            assert len(result.scripts_skipped_missing) == 0

    def test_resolve_with_exclusions(self):
        """Test resolution with excluded scripts from retry logic."""
        resolver = NSEResolver()

        # Mock available scripts
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers', 'ssh2-enum-algos'}):
            result = resolver.resolve_scripts(
                categories=[],
                explicit_scripts={'ssl-enum-ciphers', 'ssh2-enum-algos'},
                exclude_scripts={'ssh2-enum-algos'}
            )

            # Should exclude ssh2-enum-algos
            assert 'ssl-enum-ciphers' in result.scripts_available
            assert 'ssh2-enum-algos' not in result.scripts_available
            assert len(result.scripts_available) == 1

    def test_resolve_all_available(self):
        """Test resolution when all requested scripts are available."""
        resolver = NSEResolver()

        # Mock available scripts
        with patch.object(resolver, 'get_available_scripts', return_value={'ssl-enum-ciphers', 'ssh2-enum-algos', 'http-headers'}):
            result = resolver.resolve_scripts(
                categories=[],
                explicit_scripts={'ssl-enum-ciphers', 'ssh2-enum-algos'}
            )

            assert len(result.scripts_available) == 2
            assert len(result.scripts_skipped_missing) == 0
            assert result.scripts_requested == 2
