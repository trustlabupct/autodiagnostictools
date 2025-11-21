from __future__ import annotations

from pathlib import Path

from trustmitre.analytics.loader import load_analytic

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_load_analytic_parses_operations():
    analytic_path = PROJECT_ROOT / "analytics" / "CAR-2013-05-003.txt"
    analytic = load_analytic(analytic_path)
    assert analytic.analytic_id == "CAR-2013-05-003"
    kinds = [op.kind for op in analytic.operations]
    assert "search" in kinds
    assert "filter" in kinds
    assert kinds[-1] == "output"
