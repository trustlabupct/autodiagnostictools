"""Detection schema definitions for trustMITRE."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Mapping

SCHEMA_VERSION = "1.0"


@dataclass(slots=True)
class DetectionRecord:
    analytic_id: str
    title: str
    log_type: str
    time_generated: str
    host: str
    details: Dict[str, Any]
    evidence: Dict[str, Any]
    severity: str
    version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["details"] = dict(self.details)
        payload["evidence"] = dict(self.evidence)
        payload["version"] = self.version
        return payload

    @classmethod
    def from_event(
        cls, analytic_id: str, title: str, event: Mapping[str, Any]
    ) -> "DetectionRecord":
        log_type = str(event.get("log_type") or "unknown")
        time_generated = _coerce_time(event.get("time_generated"))
        host = str(event.get("host") or "unknown")
        severity = str(event.get("severity") or "medium")
        attributes = event.get("attributes") or {}
        evidence = {
            "fields_used": sorted(attributes.keys()),
        }
        details = {
            "original_subset": {
                key: value for key, value in event.items() if key not in {"attributes"}
            }
        }
        return cls(
            analytic_id=analytic_id,
            title=title,
            log_type=log_type,
            time_generated=time_generated,
            host=host,
            details=details,
            evidence=evidence,
            severity=severity,
        )


def _coerce_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return datetime.utcnow().isoformat()


__all__ = ["DetectionRecord", "SCHEMA_VERSION"]
