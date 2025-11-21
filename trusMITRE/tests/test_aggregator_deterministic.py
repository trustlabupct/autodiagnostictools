from __future__ import annotations

import json
from pathlib import Path

from trustmitre.report.aggregator import write_detection_artifacts
from trustmitre.report.schema import DetectionRecord


def _record(analytic_id: str, time_generated: str) -> DetectionRecord:
    return DetectionRecord(
        analytic_id=analytic_id,
        title=analytic_id,
        log_type="process",
        time_generated=time_generated,
        host="host",
        details={"original_subset": {"time_generated": time_generated}},
        evidence={"fields_used": ["time_generated"]},
        severity="medium",
    )


def test_write_detection_artifacts_deterministic(tmp_path):
    records = [
        _record("CAR-2013-05-003", "2025-10-15T10:01:00+00:00"),
        _record("CAR-2013-02-003", "2025-10-15T10:00:00+00:00"),
        _record("CAR-2013-08-001", "2025-10-15T10:05:00+00:00"),
    ]

    first = _run_and_digest(tmp_path / "first", records)
    second = _run_and_digest(tmp_path / "second", records)

    assert first == second


def _run_and_digest(base: Path, records: list[DetectionRecord]) -> dict:
    base.mkdir()
    jsonl_path, csv_path, summary_path = write_detection_artifacts(base, records)
    return {
        "jsonl": jsonl_path.read_text(encoding="utf-8"),
        "csv": csv_path.read_text(encoding="utf-8"),
        "summary": json.loads(summary_path.read_text(encoding="utf-8")),
    }
