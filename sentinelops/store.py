"""SQLite persistence with lightweight schema initialization."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from .models import SecurityEvent, utc_now

DEFAULT_DB = Path("data/sentinelops.db")

class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=20)
        self.conn.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self):
        self.conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, host TEXT,
          source TEXT, product TEXT, category TEXT, action TEXT, outcome TEXT,
          severity TEXT, message TEXT, source_ip TEXT, user TEXT, process TEXT,
          event_id TEXT, raw_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, title TEXT NOT NULL,
          severity TEXT NOT NULL, timestamp TEXT NOT NULL, host TEXT, entity TEXT,
          description TEXT, evidence TEXT, status TEXT NOT NULL DEFAULT 'new',
          notes TEXT NOT NULL DEFAULT '', fingerprint TEXT UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
        CREATE TABLE IF NOT EXISTS fim_baseline (
          path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
          modified_ns INTEGER NOT NULL, captured_at TEXT NOT NULL
        );
        """)
        self.conn.commit()

    def add_event(self, event: SecurityEvent) -> int:
        cur = self.conn.execute("""
        INSERT INTO events(timestamp,host,source,product,category,action,outcome,severity,
          message,source_ip,user,process,event_id,raw_json)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (event.timestamp,event.host,event.source,event.product,event.category,event.action,
              event.outcome,event.severity,event.message,event.source_ip,event.user,event.process,
              event.event_id,json.dumps(event.raw or {}, ensure_ascii=False)))
        self.conn.commit()
        return int(cur.lastrowid)

    def count_recent_failed_logins(self, source_ip: str, since: str) -> int:
        """Count recent failed SSH logins for the built-in burst detector."""
        row = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE action='login_failed' AND source_ip=? "
            "AND julianday(timestamp)>=julianday(?)",
            (source_ip, since)
        ).fetchone()
        return int(row[0])

    def add_alert(self, alert: dict) -> bool:
        try:
            self.conn.execute("""
            INSERT INTO alerts(rule_id,title,severity,timestamp,host,entity,description,evidence,fingerprint)
            VALUES(?,?,?,?,?,?,?,?,?)
            """, (alert["rule_id"],alert["title"],alert["severity"],alert["timestamp"],
                  alert.get("host",""),alert.get("entity",""),alert.get("description",""),
                  json.dumps(alert.get("evidence",{}), ensure_ascii=False),alert["fingerprint"]))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def recent_events(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result=[]
        for r in rows:
            item=dict(r); item["raw"]=json.loads(item.pop("raw_json") or "{}"); result.append(item)
        return result

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        rows=self.conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result=[]
        for r in rows:
            item=dict(r); item["evidence"]=json.loads(item["evidence"] or "{}"); result.append(item)
        return result

    def summary(self) -> dict:
        total=self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts=self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        new_alerts=self.conn.execute("SELECT COUNT(*) FROM alerts WHERE status='new'").fetchone()[0]
        critical=self.conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status='new'").fetchone()[0]
        by_severity={r["severity"]:r["n"] for r in self.conn.execute("SELECT severity,COUNT(*) n FROM alerts GROUP BY severity")}
        return {"events":total,"alerts":alerts,"new_alerts":new_alerts,"critical_open":critical,"alerts_by_severity":by_severity}

    def public_summary(self) -> dict:
        """Return aggregate counts only; never include raw endpoint identifiers or evidence."""
        summary=self.summary()
        last=self.conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        return {
            "events": summary["events"],
            "alerts": summary["alerts"],
            "new_alerts": summary["new_alerts"],
            "critical_open": summary["critical_open"],
            "alerts_by_severity": summary["alerts_by_severity"],
            "last_event_at": last,
        }

    def public_activity(self, days: int=14) -> list[dict]:
        """Return daily totals only; no host, user, IP, process or raw message fields."""
        days=max(1,min(int(days),30))
        event_rows=self.conn.execute(
            "SELECT substr(timestamp,1,10) AS day, COUNT(*) AS total FROM events "
            "WHERE julianday(timestamp) >= julianday('now', ?) GROUP BY day",
            (f"-{days-1} days",)
        ).fetchall()
        alert_rows=self.conn.execute(
            "SELECT substr(timestamp,1,10) AS day, COUNT(*) AS total FROM alerts "
            "WHERE julianday(timestamp) >= julianday('now', ?) GROUP BY day",
            (f"-{days-1} days",)
        ).fetchall()
        events={str(row["day"]):int(row["total"]) for row in event_rows if row["day"]}
        alerts={str(row["day"]):int(row["total"]) for row in alert_rows if row["day"]}
        from datetime import date, timedelta
        today=date.today()
        return [
            {"day":(today-timedelta(days=offset)).isoformat(),
             "events":events.get((today-timedelta(days=offset)).isoformat(),0),
             "alerts":alerts.get((today-timedelta(days=offset)).isoformat(),0)}
            for offset in range(days-1,-1,-1)
        ]

    def update_alert(self, alert_id: int, status: str, notes: str) -> bool:
        if status not in {"new","investigating","resolved","false_positive"}:
            raise ValueError("invalid triage status")
        cur=self.conn.execute("UPDATE alerts SET status=?,notes=? WHERE id=?",
                              (status,notes[:4000],alert_id))
        self.conn.commit()
        return cur.rowcount > 0

    def fim_rows(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM fim_baseline")]

    def upsert_fim(self, path: str, sha256: str, size: int, modified_ns: int):
        self.conn.execute("""INSERT INTO fim_baseline(path,sha256,size,modified_ns,captured_at)
        VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,
        size=excluded.size,modified_ns=excluded.modified_ns,captured_at=excluded.captured_at""",
        (path,sha256,size,modified_ns,utc_now()))
        self.conn.commit()

    def close(self):
        self.conn.close()
