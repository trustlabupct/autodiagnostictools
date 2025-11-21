"""
Integration tests for trusClamAV scanning commands.

Author: Volodymyr Dubetskyy
Last updated: October 14, 2025
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from trusClamAV.clamav_backend import discover, run_scan  # noqa: E402


def _require_clamav() -> Path:
    discovery = discover()
    if not discovery.found:
        pytest.skip("ClamAV binaries not available.")
    if not discovery.database_dir or not Path(discovery.database_dir).exists():
        pytest.skip("ClamAV database missing.")
    return Path(discovery.database_dir)


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_clean_scan(tmp_path: Path) -> None:
    _require_clamav()
    clean_dir = tmp_path / "clean"
    _write_file(clean_dir / "hello.txt", "hello\n")

    result = run_scan(
        discover(),
        [str(clean_dir)],
        output_prefix=str(tmp_path / "clean_report"),
        formats=("txt", "json"),
    )

    assert result["status"] == "clean"
    assert result["infected_count"] == 0
    assert Path(result["reports"]["txt"]).exists()
    assert Path(result["reports"]["json"]).exists()


def test_eicar_scan(tmp_path: Path) -> None:
    _require_clamav()
    eicar_dir = tmp_path / "eicar"
    eicar_sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    _write_file(eicar_dir / "eicar.com", eicar_sig)

    result = run_scan(
        discover(),
        [str(eicar_dir)],
        output_prefix=str(tmp_path / "eicar_report"),
        formats=("txt", "json"),
    )

    assert result["status"] == "infected"
    assert result["infected_count"] == 1
    infected_files = result["infected_files"]
    assert any("Eicar" in entry["signature"] or "EICAR" in entry["signature"] for entry in infected_files)
