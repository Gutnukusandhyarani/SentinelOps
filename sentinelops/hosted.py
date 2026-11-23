"""Serverless persistence and ingestion adapter for Supabase PostgREST.

The local application continues to use SQLite. Hosted Vercel functions use this
adapter so no data is written to Vercel's ephemeral filesystem.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

from .models import SecurityEvent
from .normalize import normalize_line
from .detector import detect_builtin


class HostedConfigError(RuntimeError):
    pass


class SupabaseREST:
    def __init__(self):
        self.base_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        self.key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
        if not self.base_url or not self.key:
            raise HostedConfigError("Hosted database environment is not configured.")
        if not self.base_url.startswith("https://"):
            raise HostedConfigError("SUPABASE_URL must use HTTPS.")

    def request(self, table: str, method: str = "GET", params: dict | None = None,
                payload=None, prefer: str | None = None, headers: dict | None = None):
        query = "?" + urlencode(params or {}) if params else ""
        url = f"{self.base_url}/rest/v1/{table}{query}"
        request_headers = {
            "apikey": self.key,
            "Accept": "application/json",
        }
        # Supabase's new sb_secret_ keys are not JWTs. They must be sent
        # only as apikey; putting one in Authorization: Bearer makes the
        # API gateway reject it as an invalid JWT. Legacy service_role keys
        # are JWTs and still need the Authorization header.
        if not self.key.startswith("sb_secret_"):
            request_headers["Authorization"] = f"Bearer {self.key}"
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        if prefer:
            request_headers["Prefer"] = prefer
        if headers:
            request_headers.update(headers)
        body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(url, data=body, method=method, headers=request_headers)
        try:
            with urlopen(req, timeout=9) as response:
                raw = response.read(2_000_000)
                data = json.loads(raw.decode("utf-8")) if raw else None
                return data, dict(response.headers.items())
        except HTTPError as exc:
            # Log the upstream response for server-side diagnosis without exposing
            # it to dashboard visitors or logging any credentials.
            detail = exc.read(2048).decode("utf-8", "replace")
            print(f"Supabase REST error: status={exc.code} detail={detail[:1000]}")
            raise RESTError(exc.code) from None
        except (URLError, TimeoutError, OSError):
            raise RESTError(503) from None


class RESTError(RuntimeError):
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Supabase request failed ({status}).")


class HostedStore:
    """Small Store-compatible interface used by the existing detection engine."""
    def __init__(self):
        self.db = SupabaseREST()

    def add_event(self, event: SecurityEvent) -> int:
        row = {
            "timestamp": event.timestamp, "host": event.host, "source": event.source,
            "product": event.product, "category": event.category, "action": event.action,
            "outcome": event.outcome, "severity": event.severity, "message": event.message,
            "source_ip": event.source_ip, "user": event.user, "process": event.process,
            "event_id": event.event_id, "raw_json": event.raw or {},
        }
        data, _ = self.db.request("events", "POST", payload=row, prefer="return=representation")
        return int(data[0]["id"]) if data else 0

    def count_recent_failed_logins(self, source_ip: str, since: str) -> int:
        rows, _ = self.db.request("events", params={
            "select": "id", "action": "eq.login_failed",
            "source_ip": "eq." + source_ip, "timestamp": "gte." + since,
            "limit": "5",
        })
        return len(rows or [])

    def add_alert(self, alert: dict) -> bool:
        row = {
            "rule_id": alert["rule_id"], "title": alert["title"],
            "severity": alert["severity"], "timestamp": alert["timestamp"],
            "host": alert.get("host", ""), "entity": alert.get("entity", ""),
            "description": alert.get("description", ""),
            "evidence": alert.get("evidence", {}),
            "fingerprint": alert["fingerprint"],
        }
        try:
            self.db.request("alerts", "POST", payload=row, prefer="return=minimal")
            return True
        except RESTError as exc:
            if exc.status == 409:
                return False
            raise

    def count(self, table: str, filters: dict | None = None) -> int:
        params = {"select": "id", **(filters or {})}
        _, headers = self.db.request(table, params=params,
                                     headers={"Prefer": "count=exact", "Range": "0-0"})
        content_range = next((v for k, v in headers.items() if k.lower() == "content-range"), "")
        try:
            return int(content_range.rsplit("/", 1)[1])
        except (IndexError, ValueError):
            return 0

    def public_summary(self) -> dict:
        # SECURITY DEFINER RPC returns aggregates only; raw telemetry tables stay private.
        data, _ = self.db.request("rpc/sentinelops_public_summary", "POST", payload={})
        return data or {}

    def public_activity(self, days: int = 14) -> list[dict]:
        days = max(1, min(int(days), 30))
        data, _ = self.db.request(
            "rpc/sentinelops_public_activity", "POST", payload={"days": days}
        )
        return data or []


def ingest_remote_records(records: list, source_type: str = "json") -> dict:
    """Validate a bounded collector batch, persist events, and run built-in rules."""
    if source_type not in {"ssh", "json", "windows"}:
        raise ValueError("unsupported source_type")
    if not isinstance(records, list) or not 1 <= len(records) <= 50:
        raise ValueError("records must be a list containing 1 to 50 items")

    store = HostedStore()
    counts = {"received": len(records), "ingested": 0, "skipped": 0, "alerts": 0, "errors": 0}
    max_lengths = {
        "timestamp": 64, "host": 128, "source": 64, "product": 32,
        "category": 64, "action": 64, "outcome": 32, "severity": 16,
        "message": 1000, "source_ip": 64, "user": 128, "process": 256, "event_id": 64,
    }
    for record in records:
        try:
            if source_type == "ssh":
                if not isinstance(record, str):
                    raise ValueError("SSH records must be strings")
                line = record
            else:
                if not isinstance(record, dict):
                    raise ValueError("JSON records must be objects")
                line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            if len(line.encode("utf-8")) > 12000:
                raise ValueError("record exceeds 12 KB limit")
            event = normalize_line(line, source_type)
            if event is None:
                counts["skipped"] += 1
                continue
            for field, maximum in max_lengths.items():
                if len(str(getattr(event, field) or "")) > maximum:
                    raise ValueError(f"{field} exceeds allowed length")
            if str(event.severity).lower() not in {"info", "low", "medium", "high", "critical"}:
                event.severity = "low"
            store.add_event(event)
            counts["ingested"] += 1
            alerts = detect_builtin(event, store)
            counts["alerts"] += sum(1 for alert in alerts if store.add_alert(alert))
        except (ValueError, TypeError, json.JSONDecodeError):
            counts["errors"] += 1
    return counts
