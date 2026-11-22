"""Normalized event model shared by collectors and the detection engine."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import json

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _first(data: dict, *names: str, default: Any = None) -> Any:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return value
    return default

@dataclass
class SecurityEvent:
    timestamp: str
    host: str
    source: str
    product: str
    category: str
    action: str
    outcome: str
    severity: str
    message: str
    source_ip: str = ""
    user: str = ""
    process: str = ""
    event_id: str = ""
    raw: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_mapping(cls, item: dict, source: str = "json") -> "SecurityEvent":
        if not isinstance(item, dict):
            raise ValueError("event must be a JSON object")
        known = {
            "timestamp": _first(item, "timestamp", "@timestamp", "timeCreated", "TimeCreated", default=utc_now()),
            "host": _first(item, "host", "hostname", "Computer", "computer", default="unknown-host"),
            "source": _first(item, "source", "channel", "log_name", default=source),
            "product": _first(item, "product", "os", default="unknown"),
            "category": _first(item, "category", "event.category", default="generic"),
            "action": _first(item, "action", "event.action", default="event"),
            "outcome": _first(item, "outcome", "event.outcome", default="unknown"),
            "severity": _first(item, "severity", "level", default="low"),
            "message": _first(item, "message", "Message", "description", default=""),
            "source_ip": _first(item, "source_ip", "src_ip", "IpAddress", "SourceIp", default=""),
            "user": _first(item, "user", "username", "TargetUserName", "SubjectUserName", default=""),
            "process": _first(item, "process", "process_name", "NewProcessName", default=""),
            "event_id": str(_first(item, "event_id", "EventID", "event.code", default="")),
        }
        known["timestamp"] = str(known["timestamp"])
        for key in ("host", "source", "product", "category", "action", "outcome", "severity", "message", "source_ip", "user", "process"):
            known[key] = str(known[key] or "")
        return cls(**known, raw=item)

def normalize_windows_event(item: dict) -> SecurityEvent:
    """Normalize a Windows Event Log JSON export produced by the bundled script."""
    event_id = str(_first(item, "EventID", "event_id", default=""))
    event_data = item.get("EventData") or item.get("event_data") or {}
    if not isinstance(event_data, dict):
        event_data = {}
    message = str(_first(item, "Message", "message", default=""))
    host = str(_first(item, "Computer", "computer", default="windows-host"))
    timestamp = str(_first(item, "TimeCreated", "timestamp", default=utc_now()))
    user = str(_first(event_data, "TargetUserName", "SubjectUserName", "AccountName", default=""))
    source_ip = str(_first(event_data, "IpAddress", "SourceAddress", "ClientAddress", default=""))
    process = str(_first(event_data, "NewProcessName", "ProcessName", "ServiceName", default=""))
    mapping = {
        "4624": ("authentication", "login_success", "success", "low"),
        "4625": ("authentication", "login_failed", "failure", "medium"),
        "4720": ("identity", "account_created", "success", "medium"),
        "4728": ("identity", "group_member_added", "success", "high"),
        "4732": ("identity", "group_member_added", "success", "high"),
        "4756": ("identity", "group_member_added", "success", "high"),
        "1102": ("audit", "audit_log_cleared", "success", "critical"),
        "7045": ("service", "service_installed", "success", "high"),
        "4697": ("service", "service_installed", "success", "high"),
        "4688": ("process", "process_created", "success", "low"),
    }
    category, action, outcome, severity = mapping.get(event_id, ("windows", "event", "unknown", "low"))
    if not message:
        message = f"Windows event {event_id}"
    return SecurityEvent(
        timestamp=timestamp, host=host, source="Windows Security/System",
        product="windows", category=category, action=action, outcome=outcome,
        severity=severity, message=message, source_ip=source_ip,
        user=user, process=process, event_id=event_id, raw=item
    )
