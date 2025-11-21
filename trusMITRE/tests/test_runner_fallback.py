from __future__ import annotations

from datetime import datetime, timezone

import pytest

from trustmitre.engine.runner import Runner, load_compiled
from trustmitre.analytics.compiler import compile_all
from trustmitre.analytics.loader import Analytic, AnalyticOperation
from trustmitre.engine import runner as runner_module


def _simple_analytic() -> Analytic:
    operations = [
        AnalyticOperation("search", "process", "Process:Create", None),
        AnalyticOperation("filter", "cmd", 'exe = "cmd.exe"', "process"),
        AnalyticOperation("output", "output", "cmd", None),
    ]
    return Analytic(
        analytic_id="CAR-TEST-002",
        title="Test fallback analytic",
        description=None,
        raw_text="",
        operations=operations,
    )


class BoomExecutor:
    def __init__(self, *args, **kwargs):
        raise PermissionError("no semaphores available")


def test_runner_falls_back_to_single_worker(monkeypatch, tmp_path):
    analytics = [_simple_analytic()]
    compiled_dir = tmp_path / ".compiled"
    compile_all(analytics, compiled_dir)
    compiled = load_compiled(compiled_dir)

    event = {
        "time_generated": datetime.now(timezone.utc).isoformat(),
        "host": "lab",
        "log_type": "process",
        "event_type": "Process:Create",
        "severity": "medium",
        "attributes": {"exe": "cmd.exe"},
        "raw": {"exe": "cmd.exe"},
    }

    monkeypatch.setattr(runner_module, "ProcessPoolExecutor", BoomExecutor)
    runner = Runner(compiled, workers=2, batch_size=10)
    detections = runner.execute([event])

    assert len(detections) == 1
    assert detections[0].analytic_id == "CAR-TEST-002"
