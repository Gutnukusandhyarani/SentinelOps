"""Read-only SHA-256 file integrity baselining."""
from __future__ import annotations
import hashlib
from pathlib import Path
from .models import SecurityEvent, utc_now
from .store import Store
from .detector import detect_builtin

def _hash_file(path: Path) -> tuple[str,int,int]:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024),b""):
            digest.update(chunk)
    stat=path.stat()
    return digest.hexdigest(),stat.st_size,stat.st_mtime_ns

def _files(root: Path):
    if root.is_file():
        yield root
    else:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                yield path

def baseline(root_path: str, db_path: str="data/sentinelops.db") -> int:
    root=Path(root_path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    store=Store(db_path); count=0
    try:
        for path in _files(root):
            digest,size,mtime=_hash_file(path)
            store.upsert_fim(str(path),digest,size,mtime); count+=1
    finally:
        store.close()
    return count

def check(root_path: str, db_path: str="data/sentinelops.db") -> list[dict]:
    root=Path(root_path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    store=Store(db_path)
    changed=[]
    try:
        known={row["path"]:row for row in store.fim_rows()}
        current=set()
        for path in _files(root):
            key=str(path); current.add(key)
            digest,size,mtime=_hash_file(path)
            prior=known.get(key)
            if prior is None:
                status="added"
            elif prior["sha256"]!=digest:
                status="modified"
            else:
                continue
            changed.append({"path":key,"status":status,"sha256":digest})
        for key in known:
            known_path=Path(key)
            if (known_path==root or root in known_path.parents) and key not in current:
                changed.append({"path":key,"status":"removed","sha256":""})
        for item in changed:
            event=SecurityEvent(timestamp=utc_now(),host="local",source="file-integrity",
                product="filesystem",category="file",action="file_integrity_changed",
                outcome="changed",severity="medium",message=f"File {item['status']}: {item['path']}",
                process="",event_id="",raw=item)
            store.add_event(event)
            for alert in detect_builtin(event,store):
                store.add_alert(alert)
    finally:
        store.close()
    return changed
