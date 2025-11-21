"""
Core functionality for truslan.

This package contains the core scanning, discovery, and analysis logic.
"""

from .models import (
    ScanProfile,
    FindingSeverity,
    PortState,
    Service,
    OSMatch,
    Finding,
    Host,
    ScanOptions,
    ScanMeta,
    ScanResult,
    NmapInvocation
)

from .discovery import discover_local_networks
from .scanners import build_scan_plan, execute_scan
from .checks import analyze_scan_results, get_top_quick_fixes
from .utils import (
    logger,
    setup_logging,
    show_safety_banner,
    check_nmap_installed,
    parse_cidr_list,
    parse_port_list,
    save_json_file,
    load_json_file,
    get_nmap_privileges_warning,
    format_duration,
    load_config_from_files,
    get_env_config
)

__all__ = [
    # Enums
    "ScanProfile",
    "FindingSeverity",
    "PortState",

    # Models
    "Service",
    "OSMatch",
    "Finding",
    "Host",
    "ScanOptions",
    "ScanMeta",
    "ScanResult",
    "NmapInvocation",

    # Discovery
    "discover_local_networks",

    # Scanning
    "build_scan_plan",
    "execute_scan",

    # Analysis
    "analyze_scan_results",
    "get_top_quick_fixes",

    # Utilities
    "logger",
    "setup_logging",
    "show_safety_banner",
    "check_nmap_installed",
    "parse_cidr_list",
    "parse_port_list",
    "save_json_file",
    "load_json_file",
    "get_nmap_privileges_warning",
    "format_duration",
    "load_config_from_files",
    "get_env_config",
]
