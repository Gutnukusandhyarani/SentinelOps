"""Ingest records and run detectors."""
from pathlib import Path
import json
from .normalize import normalize_line
from .detector import detect_builtin, detect_imported, load_imported_rules
from .store import Store

def ingest_file(file_path: str, source_type: str="auto", db_path: str="data/sentinelops.db",
                rules_path: str | None=None) -> dict:
    path=Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    imported=load_imported_rules(rules_path) if rules_path else []
    store=Store(db_path)
    counts={"read":0,"ingested":0,"skipped":0,"alerts":0,"errors":0}
    try:
        with path.open("r",encoding="utf-8",errors="replace") as handle:
            for line_no,line in enumerate(handle,1):
                if not line.strip():
                    continue
                counts["read"]+=1
                try:
                    event=normalize_line(line,source_type)
                    if event is None:
                        counts["skipped"]+=1
                        continue
                    store.add_event(event)
                    counts["ingested"]+=1
                    alerts=detect_builtin(event,store)+detect_imported(event,imported)
                    counts["alerts"]+=sum(1 for alert in alerts if store.add_alert(alert))
                except (ValueError,TypeError) as exc:
                    counts["errors"]+=1
                    print(f"[line {line_no}] skipped: {exc}")
    finally:
        store.close()
    return counts


def ingest_remote_records(records: list, source_type: str="json", db_path: str="data/sentinelops.db",
                         rules_path: str | None=None) -> dict:
    """Validate and ingest a bounded batch received from an authenticated endpoint agent."""
    if source_type not in {"ssh", "json", "windows"}:
        raise ValueError("unsupported source_type")
    if not isinstance(records, list) or not 1 <= len(records) <= 50:
        raise ValueError("records must be a list containing 1 to 50 items")
    imported=load_imported_rules(rules_path) if rules_path else []
    store=Store(db_path)
    counts={"received":len(records),"ingested":0,"skipped":0,"alerts":0,"errors":0}
    max_field_lengths={"timestamp":64,"host":128,"source":64,"product":32,"category":64,
        "action":64,"outcome":32,"severity":16,"message":1000,"source_ip":64,
        "user":128,"process":256,"event_id":64}
    try:
        for record in records:
            try:
                if source_type == "ssh":
                    if not isinstance(record, str):
                        raise ValueError("SSH records must be strings")
                    line=record
                else:
                    if not isinstance(record, dict):
                        raise ValueError("JSON records must be objects")
                    line=json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                if len(line.encode("utf-8")) > 12000:
                    raise ValueError("record exceeds 12 KB limit")
                event=normalize_line(line,source_type)
                if event is None:
                    counts["skipped"]+=1
                    continue
                for key,maximum in max_field_lengths.items():
                    value=getattr(event,key)
                    if len(str(value or "")) > maximum:
                        raise ValueError(f"{key} exceeds allowed length")
                if str(event.severity).lower() not in {"info","low","medium","high","critical"}:
                    event.severity="low"
                store.add_event(event)
                counts["ingested"]+=1
                alerts=detect_builtin(event,store)+detect_imported(event,imported)
                counts["alerts"]+=sum(1 for alert in alerts if store.add_alert(alert))
            except (ValueError,TypeError,json.JSONDecodeError):
                counts["errors"]+=1
    finally:
        store.close()
    return counts
