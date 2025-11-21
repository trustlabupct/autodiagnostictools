from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from trustmitre.ingest.reader import normalize_event


def _random_timestamp() -> str:
    base = datetime.now(timezone.utc)
    delta = timedelta(seconds=random.randint(-100000, 100000))
    ts = base + delta
    # Alternate between explicit Z suffix and ISO format
    if random.choice([True, False]):
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return ts.isoformat()


def test_normalize_event_randomized_timestamp_roundtrip():
    random.seed(1337)
    for _ in range(200):
        ts = _random_timestamp()
        record = {
            random.choice(["timestamp", "@timestamp", "UtcTime"]): ts,
            "Computer": f"host-{random.randint(0, 99)}",
            "EventID": random.choice(["1", "3", "7"]),
        }
        event = normalize_event(record)
        parsed = datetime.fromisoformat(
            event["time_generated"].replace("Z", "+00:00")
        )
        assert parsed.tzinfo is not None
        assert event["host"].startswith("host-")
        assert event["log_type"] in {"process", "network", "system"}
