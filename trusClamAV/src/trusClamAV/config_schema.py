"""
Configuration helpers for trusClamAV.

Author: Volodymyr Dubetskyy
Last updated: October 14, 2025
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .clamav_backend import get_default_paths

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path("output") / "trusclamav"
DEFAULT_OUTPUT_PREFIX = "scan"


def resolve_output_prefix(value: str) -> Path:
    """Resolve an output prefix relative to the standard output/trusclamav directory."""
    candidate = Path(value or DEFAULT_OUTPUT_PREFIX)

    if candidate.is_absolute():
        prefix = candidate
    else:
        parts = candidate.parts
        if parts and parts[0].lower() == "out":
            prefix = candidate
        else:
            prefix = DEFAULT_OUTPUT_DIR / candidate

    if prefix.suffix:
        prefix = prefix.with_suffix("")

    try:
        prefix.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        logger.warning("Unable to create output directory %s", prefix.parent)

    return prefix

@dataclass
class ClamAVConfig:
    """Runtime configuration for the CLI."""

    clamav_dir: Optional[str] = None
    db_dir: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    include: List[str] = field(default_factory=list)
    include_ext: List[str] = field(default_factory=list)
    max_filesize: Optional[str] = None
    max_scansize: Optional[str] = None
    out: str = DEFAULT_OUTPUT_PREFIX
    formats: List[str] = field(default_factory=lambda: ["txt", "json"])
    timeout: int = 900
    quiet: bool = False
    dry_run: bool = False
    use_clamd: bool = False
    log_file: Optional[str] = None
    log_level: str = "INFO"


def _default_config_candidates() -> List[Path]:
    paths = get_default_paths()
    config_dir = paths["config"]
    return [
        config_dir / "config.json",
        config_dir / "config.yaml",
        config_dir / "config.yml",
    ]


def _load_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            if path.suffix.lower() in {".yaml", ".yml"}:
                try:
                    import yaml  # type: ignore
                except ImportError:  # pragma: no cover - optional dependency
                    logger.warning("PyYAML not installed; ignoring %s", path)
                    return {}
                return yaml.safe_load(handle) or {}
            return json.load(handle)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load %s: %s", path, exc)
        return {}


def _apply_mapping(config: ClamAVConfig, mapping: Dict[str, Any]) -> None:
    for key, value in mapping.items():
        if hasattr(config, key):
            setattr(config, key, value)
        else:
            logger.debug("Ignoring unknown config key: %s", key)


def _apply_environment(config: ClamAVConfig) -> None:
    env_map = {
        "TRUSCLAMAV_CLAMAV_DIR": ("clamav_dir", str),
        "TRUSCLAMAV_DB_DIR": ("db_dir", str),
        "TRUSCLAMAV_TARGETS": ("targets", lambda v: [p.strip() for p in v.split(os.pathsep) if p.strip()]),
        "TRUSCLAMAV_EXCLUDE": ("exclude", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        "TRUSCLAMAV_INCLUDE": ("include", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        "TRUSCLAMAV_INCLUDE_EXT": ("include_ext", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        "TRUSCLAMAV_MAX_FILESIZE": ("max_filesize", str),
        "TRUSCLAMAV_MAX_SCANSIZE": ("max_scansize", str),
        "TRUSCLAMAV_OUT": ("out", str),
        "TRUSCLAMAV_FORMATS": ("formats", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        "TRUSCLAMAV_TIMEOUT": ("timeout", int),
        "TRUSCLAMAV_LOG_FILE": ("log_file", str),
        "TRUSCLAMAV_LOG_LEVEL": ("log_level", str),
        "TRUSCLAMAV_QUIET": ("quiet", lambda v: v.lower() in {"1", "true", "yes"}),
        "TRUSCLAMAV_DRY_RUN": ("dry_run", lambda v: v.lower() in {"1", "true", "yes"}),
        "TRUSCLAMAV_USE_CLAMD": ("use_clamd", lambda v: v.lower() in {"1", "true", "yes"}),
    }

    for env_key, (attribute, converter) in env_map.items():
        value = os.environ.get(env_key)
        if value is None:
            continue
        try:
            setattr(config, attribute, converter(value))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Invalid value for %s: %s", env_key, exc)


def _apply_cli(config: ClamAVConfig, args: Any) -> None:
    if getattr(args, "clamav_dir", None):
        config.clamav_dir = args.clamav_dir
    if getattr(args, "db_dir", None):
        config.db_dir = args.db_dir
    if getattr(args, "targets", None):
        config.targets = list(args.targets)
    if getattr(args, "exclude", None):
        config.exclude = list(args.exclude)
    if getattr(args, "include", None):
        config.include = list(args.include)
    if getattr(args, "include_ext", None):
        config.include_ext = list(args.include_ext)
    if getattr(args, "max_filesize", None):
        config.max_filesize = args.max_filesize
    if getattr(args, "max_scansize", None):
        config.max_scansize = args.max_scansize
    if getattr(args, "out", None):
        config.out = args.out
    if getattr(args, "format", None):
        config.formats = list(args.format)
    if getattr(args, "timeout", None):
        config.timeout = args.timeout
    if getattr(args, "quiet", False):
        config.quiet = True
    if getattr(args, "dry_run", False):
        config.dry_run = True
    if getattr(args, "use_clamd", False):
        config.use_clamd = True
    if getattr(args, "log_file", None):
        config.log_file = args.log_file
    if getattr(args, "log_level", None):
        config.log_level = args.log_level


def load_config(config_file: Optional[str] = None, cli_args: Any = None) -> ClamAVConfig:
    """Load configuration with precedence: CLI > environment > config file > defaults."""
    config = ClamAVConfig()

    candidates: List[Path] = []
    if config_file:
        candidates.append(Path(config_file))
    candidates.extend(_default_config_candidates())

    for candidate in candidates:
        mapping = _load_file(candidate)
        if mapping:
            _apply_mapping(config, mapping)
            break

    _apply_environment(config)

    if cli_args is not None:
        _apply_cli(config, cli_args)

    if not config.log_file:
        config.log_file = str(get_default_paths()["logs"] / "app.log")

    return config


def save_config(config: ClamAVConfig, path: Optional[Path] = None) -> Path:
    """Persist configuration as JSON."""
    if path is None:
        path = get_default_paths()["config"] / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(asdict(config), handle, indent=2, ensure_ascii=True)
    return path
