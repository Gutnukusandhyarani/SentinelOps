"""SentinelOps dashboard server with an aggregate-only public mode and authenticated ingestion."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import json
import os
import secrets
import threading
import time
from .store import Store
from .ingest import ingest_remote_records

WEB_DIR=Path(__file__).resolve().parent.parent/"web"

class Handler(BaseHTTPRequestHandler):
    db_path="data/sentinelops.db"
    public_mode=False
    ingest_token=""
    rules_path=None
    _rate_lock=threading.Lock()
    _rate_window={}

    def _headers(self, content_type="application/json; charset=utf-8", cache="no-store"):
        self.send_header("Content-Type",content_type)
        self.send_header("Cache-Control",cache)
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")

    def _json(self, payload, status=200):
        body=json.dumps(payload,ensure_ascii=False).encode("utf-8")
        self.send_response(status); self._headers(); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _static(self, filename):
        path=(WEB_DIR/filename).resolve()
        if WEB_DIR.resolve() not in path.parents and path!=WEB_DIR.resolve():
            self.send_error(403); return
        if not path.is_file():
            self.send_error(404); return
        content_type="text/html; charset=utf-8" if path.suffix==".html" else "text/css; charset=utf-8" if path.suffix==".css" else "application/javascript; charset=utf-8"
        body=path.read_bytes()
        self.send_response(200); self._headers(content_type, "no-cache"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _authorized_ingest(self):
        expected=self.ingest_token
        supplied=self.headers.get("Authorization","")
        if not expected or len(expected)<32 or not supplied.startswith("Bearer "):
            return False
        return secrets.compare_digest(supplied[7:].strip(),expected)

    def _within_ingest_rate(self):
        now=time.monotonic(); key=self.client_address[0]
        with self._rate_lock:
            history=[t for t in self._rate_window.get(key,[]) if now-t<60]
            if len(history)>=60:
                self._rate_window[key]=history
                return False
            history.append(now); self._rate_window[key]=history
            if len(self._rate_window)>500:
                self._rate_window={k:v for k,v in self._rate_window.items() if any(now-t<60 for t in v)}
            return True

    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path=="/": return self._static("index.html")
        if parsed.path in ("/app.js","/styles.css"): return self._static(parsed.path.lstrip("/"))
        if parsed.path=="/api/health":
            return self._json({"status":"ok","product":"SentinelOps","public_mode":self.public_mode})
        if parsed.path=="/api/config":
            return self._json({"public_mode":self.public_mode,"refresh_seconds":15})
        if self.public_mode:
            if parsed.path not in {"/api/public/summary","/api/public/activity"}:
                return self._json({"error":"not found"},404)
            store=Store(self.db_path)
            try:
                if parsed.path=="/api/public/summary":
                    return self._json(store.public_summary())
                return self._json(store.public_activity(14))
            finally:
                store.close()
        store=Store(self.db_path)
        try:
            if parsed.path=="/api/summary": return self._json(store.summary())
            if parsed.path=="/api/events":
                limit=min(max(int(parse_qs(parsed.query).get("limit",["100"])[0]),1),500)
                return self._json(store.recent_events(limit))
            if parsed.path=="/api/alerts":
                limit=min(max(int(parse_qs(parsed.query).get("limit",["100"])[0]),1),500)
                return self._json(store.recent_alerts(limit))
            return self._json({"error":"not found"},404)
        except Exception as exc:
            return self._json({"error":str(exc)},500)
        finally:
            store.close()

    def do_POST(self):
        parsed=urlparse(self.path)
        if parsed.path=="/api/ingest":
            if not self._authorized_ingest():
                return self._json({"error":"unauthorized"},401)
            if not self._within_ingest_rate():
                return self._json({"error":"rate limit exceeded"},429)
            if self.headers.get("Content-Type","").split(";",1)[0].strip().lower()!="application/json":
                return self._json({"error":"application/json required"},415)
            try:
                length=int(self.headers.get("Content-Length","0"))
                if length<1 or length>128000:
                    return self._json({"error":"request must be between 1 and 128000 bytes"},413)
                payload=json.loads(self.rfile.read(length))
                if not isinstance(payload,dict):
                    return self._json({"error":"JSON object required"},400)
                source_type=str(payload.get("source_type","json"))
                records=payload.get("records")
                result=ingest_remote_records(records,source_type,self.db_path,self.rules_path)
                return self._json({"accepted":result["ingested"],"skipped":result["skipped"],
                    "alerts_created":result["alerts"],"errors":result["errors"]},202)
            except (ValueError,TypeError,json.JSONDecodeError) as exc:
                return self._json({"error":str(exc)},400)
            except Exception:
                return self._json({"error":"ingestion failed"},500)

        # Detailed read and triage endpoints remain disabled in public mode.
        if self.public_mode:
            return self._json({"error":"not found"},404)
        if not parsed.path.startswith("/api/alerts/") or not parsed.path.endswith("/triage"):
            return self._json({"error":"not found"},404)
        try:
            alert_id=int(parsed.path.split("/")[-2])
            length=int(self.headers.get("Content-Length","0"))
            if length>10000: return self._json({"error":"request too large"},413)
            body=json.loads(self.rfile.read(length) or b"{}")
            status=str(body.get("status","new")); notes=str(body.get("notes",""))
            store=Store(self.db_path)
            try: updated=store.update_alert(alert_id,status,notes)
            finally: store.close()
            return self._json({"updated":updated})
        except (ValueError,json.JSONDecodeError) as exc:
            return self._json({"error":str(exc)},400)

    def log_message(self,fmt,*args):
        # Keep standard host logs; request bodies and event details are never logged.
        super().log_message(fmt,*args)

def serve(host="127.0.0.1",port=8787,db_path="data/sentinelops.db"):
    public_mode=os.environ.get("SENTINELOPS_PUBLIC_MODE", "0").lower() in {"1","true","yes"}
    token=os.environ.get("SENTINELOPS_INGEST_TOKEN", "")
    rules_path=os.environ.get("SENTINELOPS_RULES_PATH") or None
    if public_mode and len(token)<32:
        raise ValueError("SENTINELOPS_INGEST_TOKEN must be at least 32 characters in public mode.")
    if host not in {"127.0.0.1","localhost","::1"} and not public_mode:
        raise ValueError("Non-local binding requires SENTINELOPS_PUBLIC_MODE=1 and a protected ingestion token.")
    Handler.db_path=db_path; Handler.public_mode=public_mode; Handler.ingest_token=token; Handler.rules_path=rules_path
    # Initialize storage before the HTTP server starts, so missing disk mounts fail closed.
    store=Store(db_path); store.close()
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"SentinelOps dashboard: http://{host}:{port} (public aggregate mode: {public_mode})")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping SentinelOps.")
    finally: server.server_close()
