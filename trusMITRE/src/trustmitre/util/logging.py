"""Logging helpers for trustMITRE."""

from __future__ import annotations

import logging
from logging import Logger
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

from .paths import ensure_directory


def setup_logging(level: int | str = "INFO", log_file: Optional[Path] = None) -> Logger:
    """Setup application logging with optional file sink."""
    logging.captureWarnings(True)

    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, markup=False, show_path=False)
    ]

    if log_file is not None:
        ensure_directory(log_file.parent)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )

    return logging.getLogger("trustmitre")


__all__ = ["setup_logging"]
