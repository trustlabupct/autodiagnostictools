from __future__ import annotations

from trustmitre.ingest.reader import normalize_event


def test_normalize_event_merges_nested_attributes():
    record = {
        "time_generated": "2025-10-15T10:00:00Z",
        "attributes": {
            "exe": "cmd.exe",
            "dest_port": "445",
        },
    }
    event = normalize_event(record)
    attrs = event["attributes"]
    assert attrs["exe"] == "cmd.exe"
    assert attrs["dest_port"] == "445"
