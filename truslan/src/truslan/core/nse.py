"""
NSE script resolution and validation for truslan.

Provides auto-detection of available NSE scripts, filtering, and safe composition
of --script arguments with clear separation of categories vs explicit scripts.
"""

import subprocess
import logging
import re
from typing import Set, List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger("truslan")


# Canonical NSE script allowlists (corrected names)
SAFE_SCRIPTS_EXPLICIT = {
    "ssl-enum-ciphers"
}

STANDARD_SCRIPTS_EXPLICIT = {
    "ssl-enum-ciphers",
    "ssh2-enum-algos",
    "http-security-headers",
    "http-server-header",
    "vulners"
}

AGGRESSIVE_SCRIPTS_EXPLICIT = {
    "ssl-enum-ciphers",
    "ssh2-enum-algos",
    "http-security-headers",
    "http-server-header",
    "vulners",
    "smb2-security-mode",
    "smb-os-discovery",
    "smb-protocols",
    "smb-security-mode",
    "http-headers",
    "tls-alpn",
    "tls-nextprotoneg",
    "sslv2-drown"
}


@dataclass
class NSEScriptSet:
    """Resolved NSE script set with categories and explicit scripts."""
    categories: List[str]
    explicit_scripts: List[str]
    scripts_requested: int
    scripts_skipped_missing: List[str]
    scripts_available: List[str]

    def to_nmap_arg(self) -> str:
        """Build --script argument value."""
        all_items = self.categories + self.explicit_scripts
        return ",".join(all_items)

    def is_empty(self) -> bool:
        """Check if no scripts are available."""
        return len(self.categories) == 0 and len(self.explicit_scripts) == 0


class NSEResolver:
    """
    NSE script resolver with caching and auto-detection.

    Queries nmap for available scripts once per instance, then filters
    requested scripts against available scripts.
    """

    def __init__(self, nmap_path: str = "nmap", strict: bool = False):
        """
        Initialize resolver.

        Args:
            nmap_path: Path to nmap binary
            strict: If True, abort if any requested script is unavailable
        """
        self.nmap_path = nmap_path
        self.strict = strict
        self._available_scripts: Optional[Set[str]] = None
        self._detection_attempted = False

    def get_available_scripts(self) -> Set[str]:
        """
        Get set of available NSE script names.

        Queries nmap --script-help once and caches result.

        Returns:
            Set of script names (e.g., {"ssl-enum-ciphers", "ssh2-enum-algos"})
        """
        if self._available_scripts is not None:
            return self._available_scripts

        if self._detection_attempted:
            return set()

        self._detection_attempted = True

        try:
            logger.debug("Querying available NSE scripts with nmap --script-help")

            # Run nmap --script-help '*' to get all scripts
            # Output format: script names appear as "scriptname" or in various formats
            cmd = [self.nmap_path, "--script-help", "*"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            if result.returncode != 0:
                logger.warning(f"Failed to query NSE scripts: nmap returned {result.returncode}")
                self._available_scripts = set()
                return self._available_scripts

            # Parse script names from output
            # NSE scripts appear as standalone lines at the beginning, like:
            # "acarsd-info"
            # "address-info"
            # Followed by "Categories: ..." and description text
            scripts = set()

            # Pattern to match script names - must start with letter, contain hyphens/underscores
            # Script names are typically: word-word-word format
            # Must be on a line by itself (no spaces after stripping)
            script_pattern = re.compile(r'^([a-z][a-z0-9_-]+)$', re.IGNORECASE)

            for line in result.stdout.split('\n'):
                stripped = line.strip()

                # Skip empty lines and lines starting with common non-script markers
                if not stripped or stripped.startswith(('Categories:', 'http:', 'https:', '*', '-', 'Starting Nmap')):
                    continue

                # Match script names - they appear alone on a line
                match = script_pattern.match(stripped)
                if match:
                    script_name = match.group(1)
                    # Additional filtering for quality
                    # - Must contain at least one hyphen (script naming convention)
                    # - Length >= 3 characters
                    if '-' in script_name and len(script_name) >= 3:
                        scripts.add(script_name)

            logger.debug(f"Detected {len(scripts)} NSE scripts")
            self._available_scripts = scripts
            return scripts

        except subprocess.TimeoutExpired:
            logger.warning("Timeout querying NSE scripts")
            self._available_scripts = set()
            return self._available_scripts
        except Exception as e:
            logger.warning(f"Failed to query NSE scripts: {e}")
            self._available_scripts = set()
            return self._available_scripts

    def resolve_scripts(
        self,
        categories: List[str],
        explicit_scripts: Set[str],
        exclude_scripts: Optional[Set[str]] = None
    ) -> NSEScriptSet:
        """
        Resolve NSE scripts by filtering explicit scripts against available.

        Args:
            categories: List of NSE categories (e.g., ["default", "safe"])
            explicit_scripts: Set of explicit script names to include
            exclude_scripts: Set of script names to exclude (from retry logic)

        Returns:
            NSEScriptSet with filtered scripts

        Raises:
            ValueError: If strict mode and any requested script is unavailable
        """
        available = self.get_available_scripts()

        # Apply exclusions
        if exclude_scripts:
            explicit_scripts = explicit_scripts - exclude_scripts

        # Filter explicit scripts against available
        scripts_requested = len(explicit_scripts)

        if available:
            scripts_available_filtered = [
                script for script in explicit_scripts
                if script in available
            ]
            scripts_missing = [
                script for script in explicit_scripts
                if script not in available
            ]
        else:
            # If we couldn't detect available scripts, allow all requested
            logger.warning("Could not detect available NSE scripts, allowing all requested scripts")
            scripts_available_filtered = list(explicit_scripts)
            scripts_missing = []

        # Log missing scripts with appropriate severity
        if scripts_missing:
            logger.info(f"Skipping unavailable NSE scripts: {', '.join(sorted(scripts_missing))}")

            if self.strict:
                raise ValueError(
                    f"Strict NSE mode: requested scripts not available: {', '.join(sorted(scripts_missing))}"
                )

        return NSEScriptSet(
            categories=categories.copy(),
            explicit_scripts=scripts_available_filtered,
            scripts_requested=scripts_requested,
            scripts_skipped_missing=scripts_missing,
            scripts_available=scripts_available_filtered
        )

    def explain_script(self, name: str) -> dict:
        """
        Explain whether a script is available and how to install it if missing.

        Args:
            name: Script name to explain (e.g., "vulners")

        Returns:
            Dict with keys:
                - present (bool): Whether script is available
                - location (Optional[str]): Path if available
                - hint (Optional[str]): Installation hint if missing
        """
        available = self.get_available_scripts()

        if name in available:
            return {
                "present": True,
                "location": None,  # Could be enhanced to show actual path
                "hint": None
            }
        else:
            # Provide helpful hints for known optional scripts
            hint = None
            if name == "vulners":
                hint = (
                    "The 'vulners' NSE script is not part of default Nmap installs. "
                    "To use it, download the script from https://github.com/vulnersCom/nmap-vulners "
                    "and place it (along with any required data files) into your Nmap scripts directory "
                    "(typically /usr/share/nmap/scripts/ on Linux or similar on other platforms). "
                    "After copying, run 'nmap --script-updatedb' to register it."
                )
            else:
                hint = (
                    f"The '{name}' NSE script is not available in your Nmap installation. "
                    "Check if it's part of the default Nmap distribution or needs to be installed separately. "
                    "After adding any new scripts, run 'nmap --script-updatedb'."
                )

            return {
                "present": False,
                "location": None,
                "hint": hint
            }

    def list_available_scripts_grouped(self) -> dict:
        """
        Get available scripts grouped by prefix before first hyphen.

        Returns:
            Dict mapping prefix to list of script names, sorted and grouped
        """
        available = self.get_available_scripts()

        if not available:
            return {}

        # Group by prefix (before first hyphen)
        groups = {}

        # Define well-known prefixes for better grouping
        known_prefixes = ["smb", "http", "https", "ssl", "tls", "ssh", "dns", "rdp",
                         "ftp", "vnc", "mysql", "oracle", "ms-sql", "postgresql",
                         "telnet", "snmp", "ldap", "pop3", "imap", "smtp"]

        for script in sorted(available):
            # Extract prefix before first hyphen
            if '-' in script:
                prefix = script.split('-')[0]
            else:
                prefix = script

            # Normalize to lowercase
            prefix = prefix.lower()

            # Use 'misc' for uncommon prefixes
            if prefix not in known_prefixes and len(prefix) <= 2:
                prefix = "misc"

            if prefix not in groups:
                groups[prefix] = []

            groups[prefix].append(script)

        # Sort groups by name and sort scripts within each group
        sorted_groups = {}
        for prefix in sorted(groups.keys()):
            sorted_groups[prefix] = sorted(groups[prefix])

        return sorted_groups


def parse_nse_init_error(stderr: str) -> List[str]:
    """
    Parse NSE initialization error from nmap stderr.

    Looks for patterns like:
    "'script-name' did not match a category, filename, or directory"

    Args:
        stderr: Standard error output from nmap

    Returns:
        List of offending script names
    """
    offending_scripts = []

    # Pattern: 'script-name' did not match...
    pattern = r"'([^']+)'\s+did not match a category"
    matches = re.findall(pattern, stderr)
    offending_scripts.extend(matches)

    # Also check for other common error patterns
    # Pattern: NSE: failed to initialize the script engine: ... script-name
    pattern2 = r"failed to initialize.*?([a-z0-9_-]+)"
    matches2 = re.findall(pattern2, stderr, re.IGNORECASE)
    offending_scripts.extend(matches2)

    # Deduplicate
    return list(set(offending_scripts))


def is_nse_init_error(returncode: int, stderr: str) -> bool:
    """
    Check if nmap failure is due to NSE initialization error.

    Args:
        returncode: Process return code
        stderr: Standard error output

    Returns:
        True if NSE init error detected
    """
    if returncode == 0:
        return False

    # Check for NSE-related error messages
    nse_error_patterns = [
        "did not match a category",
        "failed to initialize the script engine",
        "NSE: failed to",
        "script scan failed"
    ]

    stderr_lower = stderr.lower()
    return any(pattern.lower() in stderr_lower for pattern in nse_error_patterns)
