"""
truslan - TrusLAN — LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)

A comprehensive network security scanner for LANs and small businesses.
Originally focused on SMB/Windows file sharing exposure (ports 445/139) and RDP,
now expanded to include HTTP/TLS/SSH/UDP scanning with aggressive modes and reporting.
Provides safe, standard, and aggressive scan profiles with actionable findings.

Version: 1.3.0
Author: Volodymyr Dubetskyy
Organization: TRUST Lab UPCT
© 2025 TRUST Lab UPCT
"""

__app_name__ = "truslan"
__version__ = "1.3.0"
__author__ = "Volodymyr Dubetskyy"
__organization__ = "TRUST Lab UPCT"
__description__ = "TrusLAN — LAN Exposure Scanner (SMB/RDP/HTTP/TLS/SSH/UDP)"
__copyright__ = "© 2025 TRUST Lab UPCT"

from .core.models import (
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

from .core.discovery import discover_local_networks
from .core.scanners import build_scan_plan, execute_scan
from .core.checks import analyze_scan_results, get_top_quick_fixes
from .reports.html import generate_html_report
from .reports.csv import generate_csv_report

__all__ = [
    # Version and metadata
    "__app_name__",
    "__version__",
    "__author__",
    "__organization__",
    "__description__",
    "__copyright__",

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

    # Core functions
    "discover_local_networks",
    "build_scan_plan",
    "execute_scan",
    "analyze_scan_results",
    "get_top_quick_fixes",

    # Reporting
    "generate_html_report",
    "generate_csv_report",
]
