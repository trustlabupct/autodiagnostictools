from __future__ import annotations

import random
from datetime import datetime, timezone

from trustmitre.engine.dsl import AnalyticInterpreter, CompiledAnalytic


SPEC = {
    "analytic_id": "CAR-TEST-001",
    "title": "Test Analytic",
    "description": None,
    "raw_text": "",
    "operations": [
        {"kind": "search", "target": "events", "expression": "Process:Create", "source": None},
        {
            "kind": "filter",
            "target": "matches",
            "expression": 'exe = "cmd.exe"',
            "source": "events",
        },
        {"kind": "output", "target": "matches", "expression": "matches", "source": None},
    ],
}


def _event(exe: str, host: str) -> dict:
    return {
        "time_generated": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "log_type": "process",
        "event_type": "Process:Create",
        "severity": "medium",
        "attributes": {"exe": exe},
        "raw": {"exe": exe},
    }


def test_analytic_interpreter_matches_expected_events():
    random.seed(8642)
    analytic = CompiledAnalytic.from_spec(SPEC)
    interpreter = AnalyticInterpreter(analytic)

    events = [_event(random.choice(["cmd.exe", "notepad.exe"]), f"host-{i}") for i in range(50)]
    expected = [event for event in events if event["attributes"]["exe"] == "cmd.exe"]

    detections = list(interpreter.execute(events))
    assert len(detections) == len(expected)
    for detection in detections:
        assert detection.analytic_id == "CAR-TEST-001"
        assert "exe" in detection.evidence["fields_used"]
