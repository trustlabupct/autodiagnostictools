"""Aggregate detection outputs for trustMITRE."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .schema import DetectionRecord
from ..util.io import write_csv, write_json, write_json_lines


def sort_detections(records: Iterable[DetectionRecord]) -> List[DetectionRecord]:
    return sorted(records, key=lambda rec: (rec.time_generated, rec.analytic_id))


def write_detection_artifacts(
    output_dir: Path, detections: Iterable[DetectionRecord]
) -> Tuple[Path, Path, Path]:
    detections = list(detections)
    sorted_records = sort_detections(detections)

    jsonl_path = output_dir / "detections.jsonl"
    write_json_lines(jsonl_path, (record.to_dict() for record in sorted_records))

    csv_rows = [
        {
            "analytic_id": record.analytic_id,
            "title": record.title,
            "host": record.host,
            "log_type": record.log_type,
            "time_generated": record.time_generated,
            "severity": record.severity,
        }
        for record in sorted_records
    ]
    csv_path = output_dir / "report.csv"
    write_csv(csv_path, csv_rows)

    summary = _build_summary(sorted_records)
    summary_path = output_dir / "summary.json"
    write_json(summary_path, summary)

    return jsonl_path, csv_path, summary_path


def _build_summary(records: Iterable[DetectionRecord]) -> Dict[str, Any]:
    counts: Counter[str] = Counter(record.analytic_id for record in records)
    by_severity: Counter[str] = Counter(record.severity for record in records)
    return {
        "total_detections": int(sum(counts.values())),
        "analytics": dict(counts),
        "severity_breakdown": dict(by_severity),
    }


__all__ = ["write_detection_artifacts", "sort_detections"]
