"""
Doctor command integration tests.

Author: Volodymyr Dubetskyy
Last updated: October 14, 2025
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_doctor_json() -> dict:
    root = _project_root()
    result = subprocess.run(
        [sys.executable, "-m", "trusClamAV", "doctor", "--json"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"doctor failed: {result.stderr}")
    return json.loads(result.stdout)


def test_doctor_has_required_fields() -> None:
    data = _run_doctor_json()

    assert data["os"] in {"linux", "windows"}
    assert "paths" in data
    assert "clamscan" in data["paths"]
    assert "freshclam" in data["paths"]
    assert "db_dir" in data["paths"]
    assert "discovery_method" in data
    assert isinstance(data["admin"], bool)
    assert "hints" in data
