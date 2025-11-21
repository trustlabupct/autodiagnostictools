"""
Utility functions for truslan.

Provides cross-platform helpers for privilege detection, command execution,
logging, and configuration management.
"""

import os
import sys
import platform
import subprocess
import logging
import re
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any
import json
from datetime import datetime


# Configure structured logging
def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Setup structured logging to stderr."""
    logger = logging.getLogger("truslan")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()


def is_root() -> bool:
    """Check if running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def get_platform_info() -> Dict[str, str]:
    """Get platform information."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version()
    }


def run_command(
    cmd: List[str],
    timeout: int = 300,
    capture_output: bool = True,
    check: bool = True
) -> Tuple[int, str, str]:
    """
    Run a command and return exit code, stdout, stderr.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        check: Whether to raise on non-zero exit

    Returns:
        Tuple of (returncode, stdout, stderr)

    Raises:
        subprocess.TimeoutExpired: If command times out
        subprocess.CalledProcessError: If check=True and command fails
    """
    logger.debug(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {' '.join(cmd)}")
        if not check:
            return e.returncode, e.stdout or "", e.stderr or ""
        raise


def check_nmap_installed() -> Tuple[bool, Optional[str]]:
    """
    Check if nmap is installed and return version.

    Returns:
        Tuple of (installed: bool, version: Optional[str])
    """
    try:
        returncode, stdout, stderr = run_command(
            ["nmap", "--version"],
            timeout=5,
            check=False
        )
        if returncode == 0:
            # Parse version from first line using regex
            # Format: "Nmap version 7.95 ( https://nmap.org )"
            first_line = stdout.split('\n')[0]
            match = re.search(r'Nmap version ([0-9][\w.+-]*)', first_line)
            if match:
                version = match.group(1)
            else:
                version = "unknown"
            return True, version
        return False, None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # On Windows, try common installation paths if nmap not in PATH
        if platform.system() == "Windows":
            nmap_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]
            for nmap_path in nmap_paths:
                if os.path.exists(nmap_path):
                    try:
                        returncode, stdout, stderr = run_command(
                            [nmap_path, "--version"],
                            timeout=5,
                            check=False
                        )
                        if returncode == 0:
                            first_line = stdout.split('\n')[0]
                            match = re.search(r'Nmap version ([0-9][\w.+-]*)', first_line)
                            if match:
                                version = match.group(1)
                            else:
                                version = "unknown"
                            # Add to PATH for future calls
                            nmap_dir = os.path.dirname(nmap_path)
                            if nmap_dir not in os.environ.get('PATH', ''):
                                os.environ['PATH'] = f"{nmap_dir};{os.environ.get('PATH', '')}"
                            return True, version
                    except Exception:
                        continue
        return False, None


def ensure_directory(path: Path) -> None:
    """Ensure directory exists, create if needed."""
    path.mkdir(parents=True, exist_ok=True)


def load_json_file(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(data: Dict[str, Any], path: Path) -> None:
    """Save data to JSON file with pretty formatting."""
    ensure_directory(path.parent)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"Saved JSON to {path}")


def get_config_dir() -> Path:
    """Get user config directory for truslan."""
    if platform.system() == "Windows":
        config_dir = Path(os.environ.get("APPDATA", Path.home())) / "truslan"
    else:
        config_dir = Path.home() / ".config" / "truslan"

    ensure_directory(config_dir)
    return config_dir


def get_effective_user_config_dir() -> Path:
    """
    Get config directory for the effective user.

    When running with sudo, this returns the config directory for the
    invoking user (SUDO_USER), not root. This ensures consent state
    is tied to the actual user, not the elevated privilege context.
    """
    if platform.system() == "Windows":
        # Windows doesn't use sudo
        return get_config_dir()

    # Check if running under sudo
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        # Running as root via sudo, get the original user's home
        import pwd
        try:
            pw_record = pwd.getpwnam(sudo_user)
            user_home = Path(pw_record.pw_dir)
            config_dir = user_home / ".config" / "truslan"
            ensure_directory(config_dir)
            return config_dir
        except KeyError:
            # Fallback to current user if lookup fails
            pass

    # Default behavior
    return get_config_dir()


def check_consent_shown() -> bool:
    """Check if safety banner has been shown before."""
    consent_file = get_effective_user_config_dir() / "consent.json"
    if consent_file.exists():
        try:
            data = load_json_file(consent_file)
            return data.get("consent_shown", False)
        except Exception:
            return False
    return False


def mark_consent_shown() -> None:
    """Mark that safety banner has been shown."""
    consent_file = get_effective_user_config_dir() / "consent.json"
    data = {
        "consent_shown": True,
        "timestamp": datetime.now().isoformat()
    }
    save_json_file(data, consent_file)


def show_safety_banner() -> None:
    """Show one-time safety banner."""
    if not check_consent_shown():
        banner = """
================================================================================
                            IMPORTANT LEGAL NOTICE
================================================================================

Scan only networks you own or have written permission to test.

Unauthorized network scanning may violate computer crime laws in your
jurisdiction, including the U.S. Computer Fraud and Abuse Act (CFAA)
and similar laws in other countries.

By using this tool, you acknowledge that:
- You are authorized to scan the target networks
- You understand the legal implications
- You accept full responsibility for your actions

This message will only be shown once.
================================================================================
"""
        print(banner, file=sys.stderr)
        mark_consent_shown()


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation."""
    import ipaddress
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def parse_cidr_list(cidr_string: str) -> List[str]:
    """Parse space or comma-separated CIDR list."""
    # Replace commas with spaces and split
    cidrs = cidr_string.replace(',', ' ').split()

    # Validate each CIDR
    valid_cidrs = []
    for cidr in cidrs:
        cidr = cidr.strip()
        if cidr and validate_cidr(cidr):
            valid_cidrs.append(cidr)
        elif cidr:
            logger.warning(f"Invalid CIDR notation: {cidr}")

    return valid_cidrs


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def sanitize_filename(name: str) -> str:
    """Sanitize filename by removing dangerous characters."""
    import re
    # Remove or replace dangerous characters
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Remove control characters
    name = re.sub(r'[\x00-\x1f\x7f]', '', name)
    return name.strip()


def get_nmap_privileges_warning() -> Optional[str]:
    """Get warning message if nmap requires elevated privileges."""
    if is_root():
        return None

    system = platform.system()
    if system == "Windows":
        return "Running without administrator privileges. Some scan types may be unavailable. Consider running as Administrator."
    else:
        return "Running without root privileges. SYN scan (-sS) unavailable, falling back to TCP Connect scan (-sT)."


def parse_port_list(port_string: str) -> str:
    """
    Parse and validate port list string.

    Accepts formats like: "22,80,443" or "22-80,443,3389-3390"
    Returns validated string suitable for nmap -p flag.
    """
    import re

    # Remove whitespace
    port_string = port_string.replace(' ', '')

    # Validate format
    if not re.match(r'^[\d,\-]+$', port_string):
        raise ValueError(f"Invalid port format: {port_string}")

    # Validate individual ports and ranges
    parts = port_string.split(',')
    for part in parts:
        if '-' in part:
            # Range
            start, end = part.split('-', 1)
            if not start.isdigit() or not end.isdigit():
                raise ValueError(f"Invalid port range: {part}")
            start_port, end_port = int(start), int(end)
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError(f"Port out of range (1-65535): {part}")
            if start_port > end_port:
                raise ValueError(f"Invalid range (start > end): {part}")
        else:
            # Single port
            if not part.isdigit():
                raise ValueError(f"Invalid port: {part}")
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range (1-65535): {port}")

    return port_string


def load_config_from_files() -> Dict[str, Any]:
    """
    Load configuration from config files.

    Precedence: CLI flags > env vars > pyproject.toml > truslan.json
    This function only handles file-based config.
    """
    config = {}

    # Try truslan.json in current directory
    truslan_json = Path.cwd() / "truslan.json"
    if truslan_json.exists():
        try:
            with open(truslan_json, 'r') as f:
                json_data = json.load(f)
                config.update(json_data)
        except Exception as e:
            logger.warning(f"Error reading truslan.json: {e}")

    # Try pyproject.toml in current directory
    pyproject_toml = Path.cwd() / "pyproject.toml"
    if pyproject_toml.exists():
        try:
            import tomli
            with open(pyproject_toml, 'rb') as f:
                toml_data = tomli.load(f)
                config.update(toml_data.get('tool', {}).get('truslan', {}))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Error reading pyproject.toml: {e}")

    return config


def get_env_config() -> Dict[str, Any]:
    """Get configuration from environment variables."""
    config = {}

    # TRUSLAN_PROFILE
    if 'TRUSLAN_PROFILE' in os.environ:
        config['profile'] = os.environ['TRUSLAN_PROFILE']

    # TRUSLAN_TIMING
    if 'TRUSLAN_TIMING' in os.environ:
        config['timing'] = os.environ['TRUSLAN_TIMING']

    # TRUSLAN_HOST_TIMEOUT
    if 'TRUSLAN_HOST_TIMEOUT' in os.environ:
        config['host_timeout'] = os.environ['TRUSLAN_HOST_TIMEOUT']

    return config


class ProgressTracker:
    """Simple progress tracker using tqdm."""

    def __init__(self, total: int, desc: str = "Processing", disable: bool = False):
        """Initialize progress tracker."""
        self.total = total
        self.desc = desc
        self.disable = disable
        self.pbar = None

        if not disable:
            try:
                from tqdm import tqdm
                self.pbar = tqdm(total=total, desc=desc, unit="host", ascii=True)
            except ImportError:
                logger.warning("tqdm not installed, progress bar disabled")

    def update(self, n: int = 1) -> None:
        """Update progress."""
        if self.pbar:
            self.pbar.update(n)

    def close(self) -> None:
        """Close progress bar."""
        if self.pbar:
            self.pbar.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
