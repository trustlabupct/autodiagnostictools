from __future__ import annotations

import json

from trustmitre.report.aggregator import write_detection_artifacts
from trustmitre.report.schema import DetectionRecord


def test_write_detection_artifacts(tmp_path):
    records = [
        DetectionRecord(
            analytic_id="CAR-2013-02-003",
            title="cmd.exe spawn",
            log_type="process",
            time_generated="2025-10-15T10:00:00Z",
            host="lab-host",
            details={"original_subset": {"foo": "bar"}},
            evidence={"fields_used": ["exe"]},
            severity="medium",
        ),
        DetectionRecord(
            analytic_id="CAR-2013-02-003",
            title="cmd.exe spawn",
            log_type="process",
            time_generated="2025-10-15T10:01:00Z",
            host="lab-host",
            details={"original_subset": {"foo": "baz"}},
            evidence={"fields_used": ["exe"]},
            severity="medium",
        ),
    ]

    jsonl_path, csv_path, summary_path = write_detection_artifacts(tmp_path, records)
    assert jsonl_path.exists()
    assert csv_path.exists()
    assert summary_path.exists()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_detections"] == 2
    assert summary["analytics"]["CAR-2013-02-003"] == 2
