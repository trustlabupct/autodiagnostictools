"""Sysmon specific ingestion helpers."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any, Dict, Iterator

import xmltodict

from ..util.io import write_json_lines

try:  # pragma: no cover - optional import
    import win32evtlog
except Exception:  # pragma: no cover
    win32evtlog = None

try:  # pragma: no cover
    from Evtx.Evtx import Evtx
except Exception:  # pragma: no cover
    Evtx = None


SYS_MON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def export_live_sysmon(
    output_path: Path, channel: str = SYS_MON_CHANNEL, *, limit: int | None = None
) -> Path:
    if not is_windows():
        raise RuntimeError("Live Sysmon export is only available on Windows.")
    if win32evtlog is None:
        raise RuntimeError(
            "pywin32 is required for live Sysmon export. Install the optional 'windows' extra."
        )

    handle = win32evtlog.OpenEventLog(None, channel)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events: list[Dict[str, Any]] = []
    total = 0
    while True:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break
        for event in batch:
            record = {
                "EventID": event.EventID & 0xFFFF,
                "EventCategory": event.EventCategory,
                "TimeGenerated": event.TimeGenerated.isoformat(),
                "SourceName": event.SourceName,
                "ComputerName": event.ComputerName,
                "StringInserts": list(event.StringInserts or []),
            }
            events.append(record)
            total += 1
            if limit is not None and total >= limit:
                break
        if limit is not None and total >= limit:
            break
    win32evtlog.CloseEventLog(handle)
    return write_json_lines(output_path, events)


def convert_evtx(evtx_path: Path, output_path: Path) -> Path:
    if Evtx is None:
        raise RuntimeError(
            "python-evtx is required to convert EVTX files. Install the optional 'offline_evtx' extra."
        )
    with Evtx(str(evtx_path)) as log:
        records: list[Dict[str, Any]] = []
        for record in log.records():
            parsed = xmltodict.parse(record.xml())
            records.append(parsed)
    return write_json_lines(output_path, records)


def read_evtx_events(evtx_path: Path) -> Iterator[Dict[str, Any]]:  # pragma: no cover - helper
    if Evtx is None:
        raise RuntimeError("python-evtx is required to parse EVTX files")
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            yield xmltodict.parse(record.xml())


__all__ = ["export_live_sysmon", "convert_evtx", "read_evtx_events", "is_windows"]
