"""trusClamAV - cross-platform helper utilities for ClamAV."""

__version__ = "2.1.0"
__author__ = "Volodymyr Dubetskyy"
__email__ = "volodymyr.dubetskyy@upct.es"

from .clamav_backend import (
    ClamAVDiscovery,
    ClamAVError,
    ClamAVInstallError,
    ClamAVNotFoundError,
    ClamAVScanError,
    ClamAVUpdateError,
    check_admin,
    cleanup_artifacts,
    discover,
    get_database_info,
    get_default_paths,
    get_remediation_hints,
    install_linux,
    install_windows,
    run_scan,
    update_db,
    write_reports,
)
from .config_schema import ClamAVConfig, load_config, save_config

__all__ = [
    "ClamAVDiscovery",
    "ClamAVError",
    "ClamAVInstallError",
    "ClamAVNotFoundError",
    "ClamAVScanError",
    "ClamAVUpdateError",
    "ClamAVConfig",
    "check_admin",
    "cleanup_artifacts",
    "discover",
    "get_database_info",
    "get_default_paths",
    "get_remediation_hints",
    "install_linux",
    "install_windows",
    "load_config",
    "run_scan",
    "save_config",
    "update_db",
    "write_reports",
]
