"""Parsers for common endpoint log formats."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import re
from .models import SecurityEvent, utc_now, normalize_windows_event

SSH_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s*(?P<body>.*)$"
)
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.I)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.I)
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)", re.I)

def _syslog_timestamp(month: str, day: str, clock: str) -> str:
    now = datetime.now()
    try:
        parsed = datetime.strptime(f"{now.year} {month} {int(day)} {clock}", "%Y %b %d %H:%M:%S")
        return parsed.astimezone().isoformat()
    except ValueError:
        return utc_now()

def parse_ssh_line(line: str) -> SecurityEvent | None:
    match = SSH_RE.match(line.strip())
    if not match:
        return None
    body = match.group("body")
    fields = {
        "timestamp": _syslog_timestamp(match.group("month"), match.group("day"), match.group("clock")),
        "host": match.group("host"),
        "source": "sshd",
        "product": "linux",
        "category": "authentication",
        "action": "event",
        "outcome": "unknown",
        "severity": "low",
        "message": body,
        "raw": {"line": line.rstrip("\n")},
    }
    failed = FAILED_RE.search(body) or INVALID_RE.search(body)
    accepted = ACCEPTED_RE.search(body)
    if failed:
        fields.update(action="login_failed", outcome="failure", severity="medium",
                      user=failed.group("user"), source_ip=failed.group("ip"))
    elif accepted:
        fields.update(action="login_success", outcome="success", severity="low",
                      user=accepted.group("user"), source_ip=accepted.group("ip"))
    else:
        return None
    return SecurityEvent(**fields)

def parse_json_line(line: str, source: str = "json") -> SecurityEvent | None:
    if not line.strip():
        return None
    item = json.loads(line)
    if not isinstance(item, dict):
        raise ValueError("each JSONL record must be an object")
    if source == "windows":
        return normalize_windows_event(item)
    return SecurityEvent.from_mapping(item, source=source)

def normalize_line(line: str, source: str = "auto") -> SecurityEvent | None:
    mode = source.lower()
    if mode in ("json", "windows"):
        return parse_json_line(line, mode)
    if mode == "ssh":
        return parse_ssh_line(line)
    if mode == "auto":
        if line.lstrip().startswith("{"):
            try:
                item = json.loads(line)
                if isinstance(item, dict) and any(k in item for k in ("EventID", "event_id")):
                    return normalize_windows_event(item)
                return SecurityEvent.from_mapping(item, source="json")
            except json.JSONDecodeError:
                return None
        return parse_ssh_line(line)
    raise ValueError(f"unsupported source type: {source}")
