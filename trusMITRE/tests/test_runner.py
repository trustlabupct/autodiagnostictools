from __future__ import annotations

from collections import Counter
from pathlib import Path

from trustmitre.analytics.loader import load_analytic
from trustmitre.analytics.compiler import compile_all
from trustmitre.engine.runner import Runner, load_compiled
from trustmitre.ingest.reader import stream_logs

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_runner_detects_golden_events(tmp_path):
    target_ids = ["CAR-2013-02-003", "CAR-2013-05-003", "CAR-2013-08-001"]
    analytics_dir = PROJECT_ROOT / "analytics"
    analytics = [load_analytic(analytics_dir / f"{analytic_id}.txt") for analytic_id in target_ids]

    compiled_dir = tmp_path / "compiled"
    compile_all(analytics, compiled_dir)

    events_path = PROJECT_ROOT / "samples" / "golden_events.jsonl"
    events = list(stream_logs([events_path]))

    compiled = load_compiled(compiled_dir)
    runner = Runner(compiled, workers=1, batch_size=5)
    detections = runner.execute(events)

    assert len(detections) == 3
    counts = Counter(record.analytic_id for record in detections)
    for analytic_id in target_ids:
        assert counts[analytic_id] == 1
