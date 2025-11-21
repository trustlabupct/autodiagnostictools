"""Filesystem helpers for trustMITRE."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Iterable

_HOME = Path.home()
_POSIX_CONFIG = _HOME / ".config" / "trustmitre" / "config.json"
_WINDOWS_CONFIG = (
    Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "trustmitre" / "config.json"
)


def default_config_path() -> Path:
    """Return the platform-specific default configuration file path."""
    if platform.system().lower() == "windows":
        return _WINDOWS_CONFIG
    return _POSIX_CONFIG


def runtime_base() -> Path:
    """
    Return the directory where bundled resources live.

    When frozen by PyInstaller, ``__file__`` points inside the temporary
    extraction directory (sys._MEIPASS). During development this resolves to
    the project source tree under trusMITRE/src/trustmitre.
    """
    return Path(__file__).resolve().parent


def resolve_path(path: str | Path, base: Path | None = None) -> Path:
    """Resolve *path* relative to *base* (if provided) and expand user markers."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() and base is not None:
        candidate = (base / candidate).expanduser()
    return candidate.resolve()


def ensure_directory(path: str | Path) -> Path:
    """Create *path* as a directory if it does not already exist."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def ensure_directories(paths: Iterable[str | Path]) -> list[Path]:
    """Ensure each directory in *paths* exists and return the resolved list."""
    return [ensure_directory(Path(p)) for p in paths]
