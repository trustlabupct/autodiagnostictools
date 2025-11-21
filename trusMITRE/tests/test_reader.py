from __future__ import annotations

from trustmitre.ingest.reader import normalize_event


def test_normalize_event_handles_sysmon_like_payload():
    record = {
        "timestamp": "2025-10-15T10:00:00Z",
        "Computer": "lab-host",
        "EventID": "1",
        "Image": "C:/Windows/System32/cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    }
    event = normalize_event(record)
    assert event["log_type"] == "process"
    assert event["host"] == "lab-host"
    assert event["event_type"] == "1"
    assert "Image" in event["attributes"]
