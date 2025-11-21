"""
Cross-platform ClamAV backend utilities for trusClamAV.

Author: Volodymyr Dubetskyy
Last updated: October 14, 2025
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

SIGNATURE_SUFFIXES = {".cvd", ".cld", ".cud", ".cdb", ".ndb", ".hdb"}
DEFAULT_CLAMD_TCP_ADDR = "127.0.0.1"
DEFAULT_CLAMD_TCP_PORT = 3310
_SIZE_SUFFIXES = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gib": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
    "tib": 1024**4,
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ClamAVError(Exception):
    """Base error for backend failures."""


class ClamAVNotFoundError(ClamAVError):
    """Raised when ClamAV binaries are missing."""


class ClamAVInstallError(ClamAVError):
    """Raised when automatic installation fails."""


class ClamAVUpdateError(ClamAVError):
    """Raised when signature update fails."""


class ClamAVScanError(ClamAVError):
    """Raised when scanning fails."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ClamAVDiscovery:
    """Introspected state of the local ClamAV installation."""

    found: bool
    discovery_method: str
    clamscan_path: Optional[str] = None
    clamdscan_path: Optional[str] = None
    freshclam_path: Optional[str] = None
    clamd_path: Optional[str] = None
    database_dir: Optional[str] = None
    config_dir: Optional[str] = None
    logs_dir: Optional[str] = None
    reports_dir: Optional[str] = None
    clamav_version: Optional[str] = None
    engine_version: Optional[str] = None
    database_exists: bool = False
    database_writable: bool = False
    details: Dict[str, List[str]] = field(default_factory=dict)

    def pick_scanner(self, prefer_clamd: bool = False) -> Optional[str]:
        """Return the preferred scanner path."""
        if prefer_clamd and self.clamdscan_path:
            return self.clamdscan_path
        return self.clamscan_path or self.clamdscan_path


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def check_admin() -> bool:
    """Return True when running with administrative privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - defensive
            return False
    return os.geteuid() == 0


def _windows_paths() -> Dict[str, Path]:
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    local_appdata = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))

    base = program_data / "trusClamAV"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        base = local_appdata / "trusClamAV"
        base.mkdir(parents=True, exist_ok=True)

    return {
        "base": base,
        "config": base / "config",
        "logs": base / "logs",
        "reports": base / "reports",
        "tmp": base / "tmp",
        "database": base / "clamav" / "db",
        "clamav": base / "clamav",
    }


def _windows_database_from_executables(executables: Sequence[Optional[str]]) -> Optional[Path]:
    """Attempt to locate a ClamAV database directory adjacent to known executables."""
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    fallbacks: List[Path] = []

    for exe in executables:
        if not exe:
            continue
        exe_path = Path(exe)

        # Look for a sibling "database" directory near the executable
        direct_candidates = [exe_path.parent / "database"]
        parent = exe_path.parent
        if parent.parent != parent:
            direct_candidates.append(parent.parent / "database")

        for candidate in direct_candidates:
            if candidate.exists():
                candidate.mkdir(parents=True, exist_ok=True)
                if _database_has_signatures(candidate):
                    return candidate
                fallbacks.append(candidate)

        # Chocolatey shim detection
        try:
            choco_root = exe_path.parent.parent
        except IndexError:
            choco_root = None

        if choco_root and choco_root.name.lower() == "chocolatey":
            tools_dir = choco_root / "lib" / "clamav" / "tools"
            if tools_dir.exists():
                version_dirs = sorted((p for p in tools_dir.iterdir() if p.is_dir()), reverse=True)
                for version_dir in version_dirs:
                    db_dir = version_dir / "database"
                    if db_dir.exists():
                        db_dir.mkdir(parents=True, exist_ok=True)
                        if _database_has_signatures(db_dir):
                            return db_dir
                        fallbacks.append(db_dir)
                if version_dirs:
                    fallbacks.append(version_dirs[0] / "database")

    default_dir = program_data / "ClamAV" / "db"
    if default_dir.exists():
        default_dir.mkdir(parents=True, exist_ok=True)
        if _database_has_signatures(default_dir):
            return default_dir
        fallbacks.append(default_dir)

    return fallbacks[0] if fallbacks else None


def _linux_paths() -> Dict[str, Path]:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))

    base = data_home / "trusClamAV"
    return {
        "base": base,
        "config": config_home / "trusClamAV",
        "logs": state_home / "trusClamAV" / "logs",
        "reports": state_home / "trusClamAV" / "reports",
        "tmp": state_home / "trusClamAV" / "tmp",
        "database": data_home / "trusClamAV" / "database",
        "clamav": base / "clamav",
    }


def get_default_paths() -> Dict[str, Path]:
    """Return lazily-created default directories."""
    system = platform.system()
    paths = _windows_paths() if system == "Windows" else _linux_paths()
    try:
        for key, value in paths.items():
            if key in {"config", "logs", "reports", "tmp", "database", "clamav"}:
                value.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        tmp_base = Path(tempfile.gettempdir()) / "trusClamAV"
        fallback_paths = {
            "base": tmp_base,
            "config": tmp_base / "config",
            "logs": tmp_base / "logs",
            "reports": tmp_base / "reports",
            "tmp": tmp_base / "tmp",
            "database": tmp_base / "database",
            "clamav": tmp_base / "clamav",
        }
        for value in fallback_paths.values():
            value.mkdir(parents=True, exist_ok=True)
        return fallback_paths
    return paths


def _database_has_signatures(path: Path) -> bool:
    """Return True if the directory contains any ClamAV signature files."""
    if not path.exists():
        return False
    try:
        return any(child.suffix.lower() in SIGNATURE_SUFFIXES for child in path.iterdir())
    except OSError:
        return False


def _normalise_size_arg(value: Optional[object]) -> Optional[str]:
    """Convert user-provided size thresholds into byte strings understood by ClamAV."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        number = int(value)
        if number <= 0:
            raise ValueError("Size must be greater than zero.")
        return str(number)
    raw = str(value).strip()
    if not raw:
        return None
    match = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*", raw)
    if not match:
        raise ValueError(f"Unable to parse size value: {value}")
    magnitude = float(match.group(1))
    suffix = (match.group(2) or "").lower()
    multiplier = _SIZE_SUFFIXES.get(suffix)
    if multiplier is None:
        raise ValueError(f"Unsupported size suffix in value: {value}")
    bytes_value = int(magnitude * multiplier)
    if bytes_value <= 0:
        raise ValueError("Size must be greater than zero.")
    return str(bytes_value)


def _extensions_to_pattern(extensions: Optional[Sequence[str]]) -> Optional[str]:
    """Return a case-insensitive regex that matches the provided extensions."""
    if not extensions:
        return None
    cleaned: List[str] = []
    for ext in extensions:
        token = (ext or "").strip()
        if not token:
            continue
        if token.startswith("."):
            token = token[1:]
        token = token.strip()
        if not token:
            continue
        cleaned.append(re.escape(token))
    if not cleaned:
        return None
    unique = list(dict.fromkeys(cleaned))
    joined = "|".join(unique)
    return rf"(?i)\.({joined})$"


def _candidate_directories(explicit: Optional[str]) -> Tuple[List[Path], List[str]]:
    ordered = []
    reasons = []

    if explicit:
        ordered.append(Path(explicit))
        reasons.append("cli")

    env_dir = os.environ.get("TRUSCLAMAV_CLAMAV_DIR") or os.environ.get("CLAMAV_DIR")
    if env_dir:
        ordered.append(Path(env_dir))
        reasons.append("env")

    path_dirs = [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    ordered.extend(path_dirs)
    reasons.extend(["PATH"] * len(path_dirs))

    system = platform.system()
    if system == "Windows":
        common = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV" / "bin",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "trusClamAV" / "clamav",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ClamAV",
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "trusClamAV" / "clamav",
            Path(r"C:\Program Files\ClamAV"),
            Path(r"C:\Program Files\ClamAV\bin"),
            Path(r"C:\ProgramData\ClamAV"),
        ]
    else:
        common = [
            Path("/usr/bin"),
            Path("/usr/local/bin"),
            Path("/opt/homebrew/bin"),
            Path("/opt/local/bin"),
            Path("/snap/bin"),
            Path("/opt/clamav/bin"),
            Path("/opt/clamav"),
        ]
    ordered.extend(common)
    reasons.extend(["known"] * len(common))

    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    unique_reasons = []
    for candidate, reason in zip(ordered, reasons):
        key = str(candidate).lower()
        if key not in seen:
            unique_paths.append(candidate)
            unique_reasons.append(reason)
            seen.add(key)

    return unique_paths, unique_reasons


def _resolve_binary(name: str, search_dirs: Sequence[Path], system: str) -> Tuple[Optional[str], Optional[str]]:
    names = [name]
    if system == "Windows" and not name.lower().endswith(".exe"):
        names.insert(0, f"{name}.exe")

    for variant in names:
        resolved = shutil.which(variant)
        if resolved:
            return resolved, "PATH"

    for directory in search_dirs:
        for variant in names:
            candidate = directory / variant
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate), str(directory)

    return None, None


def _default_database_dir(system: str, preferred: Optional[str]) -> Tuple[str, bool, bool]:
    """Return database path, whether it exists, and whether it is writable."""
    if preferred:
        path = Path(preferred)
        exists = _database_has_signatures(path)
        return str(path), exists, os.access(path, os.W_OK)

    if system == "Windows":
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        base = program_data / "ClamAV" / "db"
        if base.exists():
            exists = _database_has_signatures(base)
            return str(base), exists, os.access(base, os.W_OK)
        fallback = get_default_paths()["database"]
        fallback.mkdir(parents=True, exist_ok=True)
        exists = _database_has_signatures(fallback)
        return str(fallback), exists, os.access(fallback, os.W_OK)

    system_db = Path("/var/lib/clamav")
    if system_db.exists():
        exists = _database_has_signatures(system_db)
        return str(system_db), exists, os.access(system_db, os.W_OK)

    fallback = get_default_paths()["database"]
    fallback.mkdir(parents=True, exist_ok=True)
    exists = _database_has_signatures(fallback)
    return str(fallback), exists, os.access(fallback, os.W_OK)


def _extract_versions(clamscan_path: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not clamscan_path:
        return None, None
    try:
        result = run_command([clamscan_path, "--version"], timeout=15)
    except subprocess.SubprocessError:
        return None, None

    line = (result.stdout or "").strip()
    if not line:
        return None, None

    parts = line.split()
    clamav_version = parts[1] if len(parts) > 1 else line
    engine_version = None
    for token in parts:
        if token.startswith("Engine/"):
            engine_version = token.split("/", 1)[-1]
            break
    return clamav_version, engine_version


def discover(clamav_dir: Optional[str] = None, database_dir: Optional[str] = None) -> ClamAVDiscovery:
    """Discover installed ClamAV binaries and metadata."""
    system = platform.system()
    search_dirs, reasons = _candidate_directories(clamav_dir)

    clamscan, clamscan_source = _resolve_binary("clamscan", search_dirs, system)
    clamdscan, clamdscan_source = _resolve_binary("clamdscan", search_dirs, system)
    freshclam, freshclam_source = _resolve_binary("freshclam", search_dirs, system)
    clamd, clamd_source = _resolve_binary("clamd", search_dirs, system)

    db_dir, db_exists, db_writable = _default_database_dir(system, database_dir)
    if system == "Windows":
        chocolatey_db = _windows_database_from_executables([clamscan, freshclam])
        if chocolatey_db:
            db_dir = str(chocolatey_db)
            db_exists = _database_has_signatures(chocolatey_db)
            db_writable = os.access(chocolatey_db, os.W_OK)
    paths = get_default_paths()
    config_dir = str(paths["config"])

    clamav_version, engine_version = _extract_versions(clamscan or clamdscan)

    found = any([clamscan, clamdscan])
    method_parts = []
    for exe, source in [
        ("clamscan", clamscan_source),
        ("clamdscan", clamdscan_source),
        ("freshclam", freshclam_source),
    ]:
        if source:
            method_parts.append(f"{exe}:{source}")
    method = " > ".join(method_parts) if method_parts else "unresolved"

    discovery = ClamAVDiscovery(
        found=found,
        discovery_method=method,
        clamscan_path=clamscan,
        clamdscan_path=clamdscan,
        freshclam_path=freshclam,
        clamd_path=clamd,
        database_dir=db_dir,
        config_dir=config_dir,
        logs_dir=str(paths["logs"]),
        reports_dir=str(paths["reports"]),
        clamav_version=clamav_version,
        engine_version=engine_version,
        database_exists=db_exists,
        database_writable=db_writable,
        details={"search_dirs": [str(p) for p in search_dirs], "reasons": reasons},
    )

    return discovery


# ---------------------------------------------------------------------------
# Installation helpers
# ---------------------------------------------------------------------------


def _linux_package_manager() -> Optional[str]:
    checks = ["apt-get", "dnf", "yum", "pacman", "zypper"]
    for manager in checks:
        if shutil.which(manager):
            return manager
    return None


def _is_admin() -> bool:
    """Check if the process has administrative privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def _run_commands(commands: List[List[str]], check: bool = True) -> None:
    for command in commands:
        logger.info("Running: %s", " ".join(command))
        result = run_command(list(command), timeout=timeout)
        if result.returncode != 0:
            raise ClamAVInstallError(
                f"Command {' '.join(command)} failed with exit code {result.returncode}:\n{result.stderr}"
            )


def install_linux(dry_run: bool = False) -> List[str]:
    """Install ClamAV using the system package manager. Returns executed commands."""
    manager = _linux_package_manager()
    if not manager:
        raise ClamAVInstallError("Unsupported Linux distribution: no known package manager found.")

    commands: Dict[str, List[List[str]]] = {
        "apt-get": [
            ["apt-get", "update"],
            ["apt-get", "install", "-y", "clamav", "clamav-daemon"],
        ],
        "dnf": [["dnf", "install", "-y", "clamav", "clamav-update"]],
        "yum": [["yum", "install", "-y", "clamav", "clamav-update"]],
        "pacman": [["pacman", "-Sy", "--noconfirm", "clamav"]],
        "zypper": [["zypper", "install", "-y", "clamav"]],
    }

    executed: List[str] = []
    for cmd in commands.get(manager, []):
        executed.append(" ".join(cmd))
        if not dry_run:
            _run_commands([cmd])
    return executed


def _download_zip(url: str, destination: Path) -> Path:
    logger.info("Downloading %s", url)
    destination.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, str(destination))  # noqa: S310 - trusted URL provided by operator
    return destination


def _verify_sha256(file_path: Path, expected: Optional[str]) -> None:
    if not expected:
        return
    sha = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            sha.update(chunk)
    digest = sha.hexdigest()
    if digest.lower() != expected.lower():
        raise ClamAVInstallError(f"SHA256 mismatch for {file_path}: expected {expected}, got {digest}")


def _extract_zip(zip_path: Path, destination: Path) -> None:
    logger.info("Extracting %s to %s", zip_path, destination)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(destination)


def install_windows(zip_url: Optional[str] = None, sha256: Optional[str] = None, dry_run: bool = False) -> List[str]:
    """
    Install ClamAV on Windows.

    Uses Chocolatey when available, otherwise downloads a ZIP release.
    Returns the list of commands executed (or planned in dry-run mode).
    """
    actions: List[str] = []
    if not shutil.which("choco"):
        if _is_admin():
            logger.info("Chocolatey not found. Attempting to install via PowerShell...")
            install_cmd = (
                "Set-ExecutionPolicy Bypass -Scope Process -Force; "
                "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
                "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
            )
            try:
                subprocess.run(["powershell", "-Command", install_cmd], check=True, capture_output=False)
                logger.info("Chocolatey installed successfully. Please restart the application to update environment variables.")
                # Refresh environment variables for the current process is tricky without restart, 
                # but we can try to find choco again or just ask user to restart.
                # For now, we'll proceed to try using it if it's in path, or fail gracefully.
                if shutil.which("choco"):
                     pass # Proceed to install clamav
                else:
                     # It might be installed but not in PATH yet for this process
                     # Try to find it in default location
                     choco_path = os.environ.get("ChocolateyInstall", "C:\\ProgramData\\chocolatey")
                     choco_bin = Path(choco_path) / "bin" / "choco.exe"
                     if choco_bin.exists():
                         os.environ["PATH"] += os.pathsep + str(choco_bin.parent)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install Chocolatey: {e}")
                # Fallthrough to error message below

    if shutil.which("choco"):
        command = ["choco", "install", "clamav", "-y", "--no-progress"]
        actions.append(" ".join(command))
        if not dry_run:
            _run_commands([command])
        return actions

    if not zip_url:
        raise ClamAVInstallError(
            "Chocolatey not found and no ZIP URL provided.\n"
            "To install ClamAV on Windows, either:\n"
            "  1. Run this tool as Administrator to automatically install Chocolatey.\n"
            "  2. Install Chocolatey manually (https://chocolatey.org/install) and restart.\n"
            "  3. Provide a direct download URL to a ClamAV ZIP archive using --zip-url"
        )

    temp_dir = Path(tempfile.mkdtemp(prefix="trusclamav_zip_"))
    zip_path = temp_dir / "clamav.zip"
    actions.append(f"download {zip_url}")
    if dry_run:
        return actions

    _download_zip(zip_url, zip_path)
    _verify_sha256(zip_path, sha256)

    base_paths = _windows_paths()
    target = base_paths["clamav"]
    _extract_zip(zip_path, target)
    return actions


def _prepare_freshclam_config(discovery: ClamAVDiscovery) -> Optional[Path]:
    """Ensure a usable freshclam configuration exists on Windows and return its path."""
    if platform.system() != "Windows":
        return None

    config_root = Path(discovery.config_dir or get_default_paths()["config"])
    database_dir = Path(discovery.database_dir or get_default_paths()["database"])
    logs_root = Path(discovery.logs_dir or get_default_paths()["logs"])

    for directory in (config_root, database_dir, logs_root):
        directory.mkdir(parents=True, exist_ok=True)

    config_path = config_root / "freshclam.conf"
    log_path = logs_root / "freshclam.log"

    content = (
        "# Auto-generated by trusClamAV\n"
        f'DatabaseDirectory "{database_dir}"\n'
        f'UpdateLogFile "{log_path}"\n'
        "LogTime yes\n"
        "Foreground yes\n"
        "DNSDatabaseInfo current.cvd.clamav.net\n"
        "DatabaseMirror database.clamav.net\n"
    )

    try:
        if not config_path.exists() or config_path.read_text(encoding="utf-8") != content:
            config_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        logger.warning("Unable to prepare freshclam config at %s: %s", config_path, exc)
        return None

    return config_path


def _prepare_clamd_config(
    discovery: ClamAVDiscovery,
    max_filesize: Optional[str],
    max_scansize: Optional[str],
) -> Optional[Path]:
    """Create a minimal clamd configuration tailored for the current discovery."""
    if platform.system() != "Windows":
        return None

    if not discovery.database_dir:
        logger.warning("clamdscan requested but no database directory available.")
        return None

    defaults = get_default_paths()
    config_root = Path(discovery.config_dir or defaults["config"])
    logs_root = Path(discovery.logs_dir or defaults["logs"])
    tmp_root = Path(defaults["tmp"])
    database_dir = Path(discovery.database_dir)

    for directory in (config_root, logs_root, tmp_root, database_dir):
        directory.mkdir(parents=True, exist_ok=True)

    config_path = config_root / "clamd.conf"
    log_path = logs_root / "clamd.log"
    pid_path = config_root / "clamd.pid"
    max_threads = max(2, (os.cpu_count() or 2))

    lines = [
        "# Auto-generated by trusClamAV",
        f'DatabaseDirectory "{database_dir}"',
        f'LogFile "{log_path}"',
        "LogFileMaxSize 10M",
        "LogFileUnlock yes",
        "LogTime yes",
        "Foreground yes",
        f'PidFile "{pid_path}"',
        f'TemporaryDirectory "{tmp_root}"',
        f"TCPSocket {DEFAULT_CLAMD_TCP_PORT}",
        f'TCPAddr "{DEFAULT_CLAMD_TCP_ADDR}"',
        f"MaxThreads {max_threads}",
        "ReadTimeout 120",
        "FixStaleSocket yes",
        "ExitOnOOM no",
    ]
    if max_filesize:
        lines.append(f"MaxFileSize {max_filesize}")
    if max_scansize:
        lines.append(f"MaxScanSize {max_scansize}")
        lines.append(f"StreamMaxLength {max_scansize}")
    content = "\n".join(lines) + "\n"

    try:
        if not config_path.exists() or config_path.read_text(encoding="utf-8") != content:
            config_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        logger.warning("Unable to prepare clamd config at %s: %s", config_path, exc)
        return None

    return config_path


def _is_clamd_ready(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True when clamd accepts TCP connections at the given host/port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ensure_clamd_daemon(
    discovery: ClamAVDiscovery,
    config_path: Optional[Path],
    wait_timeout: int = 30,
) -> Optional[subprocess.Popen]:
    """
    Start clamd if it is not already running and return the process handle.

    When an existing daemon is detected the function returns None.
    """
    if platform.system() != "Windows":
        return None

    if not config_path:
        raise ClamAVScanError("Failed to prepare clamd configuration.")

    host = DEFAULT_CLAMD_TCP_ADDR
    port = DEFAULT_CLAMD_TCP_PORT

    if _is_clamd_ready(host, port):
        logger.info("Existing clamd daemon detected at %s:%s", host, port)
        return None

    clamd_exe = discovery.clamd_path
    if not clamd_exe:
        raise ClamAVScanError("clamd executable not found; cannot use clamdscan.")

    command = [clamd_exe, "--config-file", str(config_path)]
    logger.info("Starting clamd daemon: %s", " ".join(command))
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise ClamAVScanError(f"Unable to start clamd daemon: {exc}") from exc

    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise ClamAVScanError("clamd daemon exited prematurely.")
        if _is_clamd_ready(host, port):
            logger.info("clamd daemon is ready.")
            return process
        time.sleep(0.5)

    process.terminate()
    raise ClamAVScanError("Timed out waiting for clamd daemon to become ready.")


def _stop_clamd_daemon(process: subprocess.Popen, wait_timeout: int = 5) -> None:
    """Terminate a clamd process that was started by trusClamAV."""
    if process.poll() is not None:
        return
    logger.info("Stopping clamd daemon (pid %s).", process.pid)
    process.terminate()
    try:
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        logger.warning("clamd daemon did not exit gracefully; forcing termination.")
        process.kill()
# ---------------------------------------------------------------------------
# Update helpers
# ---------------------------------------------------------------------------


def update_db(
    discovery: ClamAVDiscovery,
    timeout: int = 600,
    retries: int = 1,
    allow_failure: bool = False,
) -> bool:
    """Update virus signatures using freshclam."""
    if not discovery.freshclam_path:
        raise ClamAVUpdateError("freshclam executable not found.")

    command = [discovery.freshclam_path]
    config_path = _prepare_freshclam_config(discovery)
    if config_path:
        command.extend(["--config-file", str(config_path)])
    command.extend(["--stdout", "--verbose"])
    if discovery.database_dir:
        command.extend(["--datadir", discovery.database_dir])
    commands = [command]

    if platform.system() == "Linux":
        run_command(["systemctl", "stop", "clamav-freshclam"], timeout=30, check=False)

    last_error = None
    for attempt in range(1, retries + 1):
        logger.info("Running freshclam (attempt %s/%s)", attempt, retries)
        result = run_command(commands[0], timeout=timeout, check=False)
        if result.returncode == 0:
            logger.debug("freshclam stdout: %s", result.stdout)
            if discovery.database_dir:
                db_path = Path(discovery.database_dir)
                discovery.database_exists = _database_has_signatures(db_path)
                discovery.database_writable = os.access(db_path, os.W_OK)
            return True
        last_error = result.stderr or result.stdout or f"freshclam exited {result.returncode}"
        time.sleep(2)

    if allow_failure and discovery.database_exists:
        logger.warning("freshclam failed but database exists: %s", last_error)
        return False

    raise ClamAVUpdateError(last_error or "freshclam failed")


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------


def _parse_scan_output(stdout: str) -> Tuple[int, List[Dict[str, str]], Dict[str, str]]:
    infected: List[Dict[str, str]] = []
    summary: Dict[str, str] = {}
    in_summary = False
    ok_count = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("----------- SCAN SUMMARY -----------"):
            in_summary = True
            continue
        if ":" in stripped:
            path_part, tail = stripped.rsplit(":", 1)
            status = tail.strip()
            if status.endswith("FOUND"):
                infected.append(
                    {
                        "path": path_part.strip(),
                        "signature": status.replace("FOUND", "").strip(),
                    }
                )
                continue
            if status.upper() == "OK":
                ok_count += 1
                continue
        if in_summary and ":" in stripped:
            key, value = stripped.split(":", 1)
            summary[key.strip().lower().replace(" ", "_")] = value.strip()
    infected_count = len(infected)
    if "scanned_files" not in summary and ok_count:
        summary["scanned_files"] = str(ok_count)

    return infected_count, infected, summary


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_json_payload(
    targets: Sequence[str],
    exclusions: Sequence[str],
    includes: Sequence[str],
    discovery: ClamAVDiscovery,
    engine: str,
    infected_count: int,
    infected_files: List[Dict[str, str]],
    files_scanned: int,
    elapsed: float,
    status: str,
    errors: List[str],
) -> Dict[str, object]:
    return {
        "schema_version": "1.0",
        "timestamp": _utc_timestamp(),
        "tool": {
            "name": "trusClamAV",
            "clamav_version": discovery.clamav_version or "unknown",
            "engine": engine,
        },
        "targets": [str(Path(target).resolve()) for target in targets],
        "exclusions": list(exclusions),
        "includes": list(includes),
        "files_scanned": files_scanned,
        "infected_count": infected_count,
        "infected_files": infected_files,
        "elapsed_seconds": round(elapsed, 2),
        "status": status,
        "errors": errors,
    }


def write_reports(
    prefix: Path,
    stdout: str,
    stderr: str,
    json_payload: Dict[str, object],
    formats: Sequence[str],
) -> Dict[str, str]:
    def _write(target: Path) -> Dict[str, str]:
        target.parent.mkdir(parents=True, exist_ok=True)
        written_local: Dict[str, str] = {}
        timestamp = _utc_timestamp()

        if "txt" in formats:
            txt_path = target.with_suffix(".txt")
            with txt_path.open("w", encoding="utf-8", errors="replace") as handle:
                handle.write("trusClamAV scan report\n")
                handle.write(f"generated: {timestamp}\n")
                handle.write(f"command stdout:\n{stdout}\n")
                if stderr:
                    handle.write("\ncommand stderr:\n")
                    handle.write(stderr)
            written_local["txt"] = str(txt_path)

        if "json" in formats:
            json_path = target.with_suffix(".json")
            with json_path.open("w", encoding="utf-8") as handle:
                json.dump(json_payload, handle, indent=2, ensure_ascii=True)
            written_local["json"] = str(json_path)

        return written_local

    try:
        return _write(prefix)
    except PermissionError:
        fallback_dir = get_default_paths()["reports"]
        fallback_prefix = fallback_dir / prefix.name
        logger.warning(
            "Falling back to writable reports directory: %s", fallback_prefix
        )
        return _write(fallback_prefix)


def run_scan(
    discovery: ClamAVDiscovery,
    targets: Sequence[str],
    exclude: Optional[Sequence[str]] = None,
    include: Optional[Sequence[str]] = None,
    include_ext: Optional[Sequence[str]] = None,
    max_filesize: Optional[object] = None,
    max_scansize: Optional[object] = None,
    prefer_clamd: bool = False,
    timeout: int = 900,
    output_prefix: Optional[str] = None,
    formats: Sequence[str] = ("txt", "json"),
    db_override: Optional[str] = None,
    dry_run: bool = False,
) -> Dict[str, object]:
    """Run a ClamAV scan and optionally write reports."""
    if not targets:
        raise ClamAVScanError("No targets provided.")
    scanner = discovery.pick_scanner(prefer_clamd)
    if not scanner:
        raise ClamAVScanError("Neither clamscan nor clamdscan is available.")

    resolved_targets: List[str] = []
    errors: List[str] = []
    for target in targets:
        path = Path(target)
        if path.exists():
            resolved_targets.append(str(path))
        else:
            errors.append(f"Target not found: {target}")

    if not resolved_targets:
        raise ClamAVScanError("None of the specified targets exist.")

    try:
        norm_max_filesize = _normalise_size_arg(max_filesize)
        norm_max_scansize = _normalise_size_arg(max_scansize)
    except ValueError as exc:
        raise ClamAVScanError(str(exc)) from exc

    include_patterns: List[str] = []
    if include:
        include_patterns.extend(str(pattern) for pattern in include if pattern)
    ext_pattern = _extensions_to_pattern(include_ext)
    if ext_pattern:
        include_patterns.append(ext_pattern)
    if include_patterns:
        include_patterns = list(dict.fromkeys(include_patterns))

    use_clamdscan = Path(scanner).name.lower().startswith("clamdscan")
    command = [scanner, "--infected", "--verbose"]
    config_path: Optional[Path] = None
    clamd_process: Optional[subprocess.Popen] = None

    database_dir = db_override or discovery.database_dir
    if use_clamdscan:
        config_path = _prepare_clamd_config(discovery, norm_max_filesize, norm_max_scansize)
        if config_path:
            command.extend(["--config-file", str(config_path)])
    else:
        command.append("--recursive")
        if database_dir:
            command.extend(["--database", database_dir])

    if use_clamdscan and platform.system() == "Windows" and not config_path:
        raise ClamAVScanError(
            "Failed to prepare clamd configuration; check permissions and try again."
        )

    if norm_max_filesize:
        command.extend(["--max-filesize", norm_max_filesize])
    if norm_max_scansize:
        command.extend(["--max-scansize", norm_max_scansize])

    if include_patterns:
        for pattern in include_patterns:
            command.extend(["--include", pattern])

    if exclude:
        for pattern in exclude:
            command.extend(["--exclude", pattern])
    command.extend(resolved_targets)

    if dry_run:
        json_payload = _build_json_payload(
            targets=resolved_targets,
            exclusions=exclude or [],
            includes=include_patterns,
            discovery=discovery,
            engine=Path(scanner).name,
            infected_count=0,
            infected_files=[],
            files_scanned=0,
            elapsed=0.0,
            status="dry-run",
            errors=errors,
        )
        reports = {}
        if output_prefix:
            reports = write_reports(Path(output_prefix), "", "Dry run – no scan executed.", json_payload, formats)
        return {
            "status": "dry-run",
            "exit_code": 0,
            "infected_count": 0,
            "infected_files": [],
            "files_scanned": 0,
            "elapsed_seconds": 0.0,
            "stdout": "",
            "stderr": "",
            "command": command,
            "includes": include_patterns,
            "json": json_payload,
            "reports": reports,
        }

    try:
        if use_clamdscan:
            clamd_process = _ensure_clamd_daemon(discovery, config_path)

        logger.info("Executing scan: %s", " ".join(command))
        started = time.time()
        result = run_command(command, timeout=timeout, check=False)
        elapsed = time.time() - started
    finally:
        if clamd_process:
            _stop_clamd_daemon(clamd_process)

    infected_count, infected_files, summary = _parse_scan_output(result.stdout or "")
    status = "clean"
    if result.returncode == 1:
        status = "infected"
    elif result.returncode not in (0, 1):
        status = "error"

    files_scanned = 0
    if "scanned_files" in summary:
        try:
            files_scanned = int(summary["scanned_files"])
        except ValueError:
            files_scanned = 0

    if status == "error":
        if result.stderr:
            errors.append(result.stderr.strip())
        if not errors:
            errors.append("Scan failed.")

    json_payload = _build_json_payload(
        targets=resolved_targets,
        exclusions=exclude or [],
        includes=include_patterns,
        discovery=discovery,
        engine=Path(scanner).name,
        infected_count=infected_count,
        infected_files=infected_files,
        files_scanned=files_scanned,
        elapsed=elapsed,
        status=status,
        errors=errors,
    )

    reports = {}
    if output_prefix:
        reports = write_reports(Path(output_prefix), result.stdout or "", result.stderr or "", json_payload, formats)

    return {
        "status": status,
        "exit_code": result.returncode,
        "infected_count": infected_count,
        "infected_files": infected_files,
        "files_scanned": files_scanned,
        "elapsed_seconds": round(elapsed, 2),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": command,
        "includes": include_patterns,
        "json": json_payload,
        "reports": reports,
    }


# ---------------------------------------------------------------------------
# Diagnostics and cleanup
# ---------------------------------------------------------------------------


def get_database_info(db_dir: Optional[str]) -> Dict[str, object]:
    """Return metadata about signature database files."""
    if not db_dir:
        return {"exists": False, "age_days": None, "file_count": 0, "total_mb": 0.0}

    path = Path(db_dir)
    if not path.exists():
        return {"exists": False, "age_days": None, "file_count": 0, "total_mb": 0.0}

    newest = None
    total_bytes = 0
    count = 0
    for entry in path.glob("*"):
        if entry.suffix.lower() not in SIGNATURE_SUFFIXES:
            continue
        stat = entry.stat()
        count += 1
        total_bytes += stat.st_size
        age = (time.time() - stat.st_mtime) / 86400
        newest = age if newest is None else min(newest, age)

    return {
        "exists": count > 0,
        "age_days": round(newest, 2) if newest is not None else None,
        "file_count": count,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
    }


def get_remediation_hints(discovery: ClamAVDiscovery) -> List[str]:
    """Return user-facing hints based on discovery results."""
    hints: List[str] = []
    system = platform.system().lower()

    if not discovery.found:
        if system == "windows":
            hints.append("Install ClamAV via Chocolatey: choco install clamav -y --no-progress")
            hints.append("Or provide --zip-url to trusclamav install for manual ZIP deployment.")
        else:
            hints.append("Install ClamAV with: sudo apt-get install -y clamav clamav-daemon")

    if not discovery.database_exists:
        hints.append("Run 'trusclamav update' or 'freshclam' to download the signature database.")

    if not discovery.database_writable:
        hints.append("Signature directory is not writable; run updates with administrative privileges.")

    if not discovery.freshclam_path:
        hints.append("freshclam executable missing; reinstall or repair ClamAV.")

    return hints


def cleanup_artifacts(
    roots: Iterable[Path],
    patterns: Iterable[str],
    dry_run: bool = False,
    purge_db_dir: Optional[Path] = None,
) -> Dict[str, object]:
    removed: List[str] = []
    errors: List[str] = []
    reclaimed = 0

    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            for item in root.rglob(pattern):
                try:
                    if item.is_dir():
                        size = sum(child.stat().st_size for child in item.rglob("*") if child.is_file())
                        if not dry_run:
                            shutil.rmtree(item)
                        reclaimed += size
                    else:
                        size = item.stat().st_size
                        if not dry_run:
                            item.unlink()
                        reclaimed += size
                    removed.append(str(item))
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{item}: {exc}")

    if purge_db_dir and purge_db_dir.exists():
        try:
            size = sum(child.stat().st_size for child in purge_db_dir.rglob("*") if child.is_file())
            if not dry_run:
                shutil.rmtree(purge_db_dir)
            reclaimed += size
            removed.append(str(purge_db_dir))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{purge_db_dir}: {exc}")

    return {
        "removed": removed,
        "errors": errors,
        "bytes_reclaimed": reclaimed,
        "dry_run": dry_run,
    }


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------


def run_command(
    command: Sequence[str],
    timeout: int = 600,
    check: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run with sensible defaults."""
    logger.debug("Executing command: %s", " ".join(command))
    result = subprocess.run(
        list(command),
        timeout=timeout,
        text=True,
        env=env,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            command,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


# Windows admin detection requires ctypes
if os.name == "nt":  # pragma: no cover - platform dependent
    import ctypes  # noqa: E402
