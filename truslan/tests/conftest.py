"""Test configuration for truslan."""

import sys
from pathlib import Path


def pytest_configure():
    """Ensure src/ is on sys.path for imports when running tests from the repo."""
    root = Path(__file__).resolve().parents[1]
    src_path = root / "src"
    if src_path.exists():
        sys.path.insert(0, str(src_path))
