from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

from trustmitre.report.aggregator import write_detection_artifacts
from trustmitre.report.schema import DetectionRecord

SEVERITIES = ["info", "low", "medium", "high"]


def _random_detection(idx: int) -> DetectionRecord:
    analytic_id = random.choice(
        ["CAR-2013-02-003", "CAR-2013-05-003", "CAR-2013-08-001", "CAR-2014-04-003"]
    )
    ts = datetime(2025, 10, 15, tzinfo=timezone.utc) + timedelta(seconds=idx)
    return DetectionRecord(
        analytic_id=analytic_id,
        title=f"{analytic_id} detection",
        log_type=random.choice(["process", "network", "file", "system"]),
        time_generated=ts.isoformat(),
        host=f"lab-{random.randint(0, 5)}",
        details={"original_subset": {"index": idx}},
        evidence={"fields_used": ["test_field"]},
        severity=random.choice(SEVERITIES),
    )


def test_aggregator_summary_consistency(tmp_path):
    random.seed(20251015)
    records = [_random_detection(i) for i in range(20)]
    jsonl_path, csv_path, summary_path = write_detection_artifacts(tmp_path, records)

    assert jsonl_path.exists()
    assert csv_path.exists()
    assert summary_path.exists()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_detections"] == len(records)
    assert sum(summary["analytics"].values()) == len(records)
    assert sum(summary["severity_breakdown"].values()) == len(records)
