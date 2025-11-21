"""Generic log readers and normalizers."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping

from ..util.paths import resolve_path

Event = Dict[str, Any]

SUPPORTED_EXTENSIONS = {".json", ".jsonl", ".ndjson", ".csv"}

logger = logging.getLogger(__name__)


def stream_logs(inputs: Iterable[str | Path]) -> Iterator[Event]:
    for item in inputs:
        path = resolve_path(item)
        if not path.exists():
            continue
        suffix = path.suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            continue
        if suffix in {".jsonl", ".ndjson"}:
            yield from _read_json_lines(path)
        elif suffix == ".csv":
            yield from _read_csv(path)
        else:
            yield from _read_json(path)


def _read_json_lines(path: Path) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line in %s", path)
                continue
            yield normalize_event(record)


def _read_json(path: Path) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        for key in ("events", "Records", "records", "data"):
            if key in payload and isinstance(payload[key], list):
                records = payload[key]
                break
        else:
            records = [payload]
    else:
        records = [payload]
    for record in records:
        if isinstance(record, Mapping):
            yield normalize_event(record)


def _read_csv(path: Path) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield normalize_event(row)


def normalize_event(record: Mapping[str, Any]) -> Event:
    timestamp = _extract_timestamp(record)
    host = _extract_host(record)
    log_type = _extract_log_type(record)
    event_type = record.get("event_type") or record.get("EventID") or record.get("EventName")
    severity = record.get("severity") or record.get("level") or "medium"
    attributes = _flatten(record)
    expanded = dict(attributes)
    for key, value in list(attributes.items()):
        if key.startswith("attributes.") and len(key) > len("attributes."):
            plain = key[len("attributes.") :]
            expanded.setdefault(plain, value)
        if key.startswith("raw.") and len(key) > len("raw."):
            plain_raw = key[len("raw.") :]
            expanded.setdefault(f"raw.{plain_raw}", value)
    return {
        "time_generated": timestamp,
        "host": host,
        "log_type": log_type,
        "event_type": str(event_type or "unknown"),
        "severity": str(severity),
        "attributes": expanded,
        "raw": dict(record),
    }


def _extract_timestamp(record: Mapping[str, Any]) -> str:
    candidates = [
        record.get("time_generated"),
        record.get("@timestamp"),
        record.get("timestamp"),
        record.get("UtcTime"),
        record.get("EventTime"),
        record.get("date"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        ts = _to_iso(candidate)
        if ts:
            return ts
    return datetime.now(timezone.utc).isoformat()


def _extract_host(record: Mapping[str, Any]) -> str:
    for key in ("host", "hostname", "Computer", "computer_name", "SourceComputerId"):
        value = record.get(key)
        if value:
            return str(value)
    return "unknown"


def _extract_log_type(record: Mapping[str, Any]) -> str:
    for key in ("log_type", "LogChannel", "channel", "EventType", "type"):
        value = record.get(key)
        if value:
            return str(value).lower()
    event_id = str(record.get("EventID") or "").lower()
    if event_id in {"1", "process create", "processcreate"}:
        return "process"
    if event_id in {"3", "networkconnect"}:
        return "network"
    return "system"


def _to_iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        dt_value = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt_value.isoformat()
    text = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return None


def _flatten(record: Mapping[str, Any], prefix: str = "") -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}
    for key, value in record.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            flattened.update(_flatten(value, path))
        else:
            flattened[path] = value
    return flattened


__all__ = ["stream_logs", "normalize_event", "SUPPORTED_EXTENSIONS"]
