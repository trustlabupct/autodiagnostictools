"""Version helpers for trustMITRE."""

from __future__ import annotations

from importlib import metadata

PACKAGE_NAME = "trustmitre"


def get_version() -> str:
    """Return the installed package version, defaulting to development value."""
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"


__version__ = get_version()

__all__ = ["get_version", "__version__", "PACKAGE_NAME"]
