"""Small localhost-only JSON API and static dashboard server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
from urllib.parse import urlparse, parse_qs
from .store import Store

WEB_DIR=Path(__file__).resolve().parent.parent/"web"

class Handler(BaseHTTPRequestHandler):
    db_path="data/sentinelops.db"
    def _json(self, payload, status=200):
        body=json.dumps(payload,ensure_ascii=False).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.end_headers(); self.wfile.write(body)

    def _static(self, filename):
        path=(WEB_DIR/filename).resolve()
        if WEB_DIR.resolve() not in path.parents and path!=WEB_DIR.resolve():
            self.send_error(403); return
        if not path.is_file():
            self.send_error(404); return
        content_type="text/html; charset=utf-8" if path.suffix==".html" else "text/css; charset=utf-8" if path.suffix==".css" else "application/javascript; charset=utf-8"
        body=path.read_bytes()
        self.send_response(200); self.send_header("Content-Type",content_type)
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path=="/":
            return self._static("index.html")
        if parsed.path in ("/app.js","/styles.css"):
            return self._static(parsed.path.lstrip("/"))
        store=Store(self.db_path)
        try:
            if parsed.path=="/api/health":
                return self._json({"status":"ok","product":"SentinelOps"})
            if parsed.path=="/api/summary":
                return self._json(store.summary())
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
        if not parsed.path.startswith("/api/alerts/") or not parsed.path.endswith("/triage"):
            return self._json({"error":"not found"},404)
        try:
            alert_id=int(parsed.path.split("/")[-2])
            length=int(self.headers.get("Content-Length","0"))
            if length>10000:
                return self._json({"error":"request too large"},413)
            body=json.loads(self.rfile.read(length) or b"{}")
            status=str(body.get("status","new"))
            notes=str(body.get("notes",""))
            store=Store(self.db_path)
            try:
                updated=store.update_alert(alert_id,status,notes)
            finally:
                store.close()
            return self._json({"updated":updated})
        except (ValueError,json.JSONDecodeError) as exc:
            return self._json({"error":str(exc)},400)

    def log_message(self, fmt, *args):
        # Keep default request logging but avoid noisy stack traces.
        super().log_message(fmt,*args)

def serve(host="127.0.0.1",port=8787,db_path="data/sentinelops.db"):
    if host not in {"127.0.0.1","localhost","::1"}:
        raise ValueError("For safety, SentinelOps only binds to localhost in this portfolio build.")
    Handler.db_path=db_path
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"SentinelOps dashboard: http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SentinelOps.")
    finally:
        server.server_close()
