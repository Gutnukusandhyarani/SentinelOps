"""Ingest records and run detectors."""
from pathlib import Path
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
