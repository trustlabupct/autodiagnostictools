"""Test configuration for trusClamAV."""

import sys
from pathlib import Path


def pytest_configure():
    """Add src/ to sys.path so tests can import the package without installation."""
    root = Path(__file__).resolve().parents[1]
    src_path = root / "src"
    if src_path.exists():
        sys.path.insert(0, str(src_path))
