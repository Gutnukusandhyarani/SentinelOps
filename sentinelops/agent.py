"""Simple local file-tail collector for authorized endpoint logs."""
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from .normalize import normalize_line
from .detector import detect_builtin,detect_imported,load_imported_rules
from .store import Store

def follow_file(file_path,source_type="auto",db_path="data/sentinelops.db",
                rules_path=None,from_start=False,poll_interval=1.0):
    path=Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(path)
    imported=load_imported_rules(rules_path) if rules_path else []
    store=Store(db_path)
    counts={"ingested":0,"skipped":0,"alerts":0,"errors":0}
    stream=path.open("r",encoding="utf-8",errors="replace")
    if not from_start:
        stream.seek(0,os.SEEK_END)
    identity=(path.stat().st_dev,path.stat().st_ino)
    try:
        print(f"Watching {path} (Ctrl+C to stop).")
        while True:
            line=stream.readline()
            if line:
                try:
                    event=normalize_line(line,source_type)
                    if event is None:
                        counts["skipped"]+=1
                        continue
                    store.add_event(event); counts["ingested"]+=1
                    for alert in detect_builtin(event,store)+detect_imported(event,imported):
                        if store.add_alert(alert):
                            counts["alerts"]+=1
                            print(f"[ALERT] {alert['severity'].upper()} {alert['rule_id']} — {alert['title']}")
                except (ValueError,TypeError,json.JSONDecodeError) as exc:
                    counts["errors"]+=1
                    print(f"[collector] skipped malformed line: {exc}")
                continue
            try:
                current=path.stat()
                new_identity=(current.st_dev,current.st_ino)
                if new_identity!=identity:
                    stream.close()
                    stream=path.open("r",encoding="utf-8",errors="replace")
                    identity=new_identity
            except FileNotFoundError:
                pass
            time.sleep(max(0.2,float(poll_interval)))
    except KeyboardInterrupt:
        print("\nCollector stopped.")
    finally:
        stream.close()
        store.close()
    return counts
