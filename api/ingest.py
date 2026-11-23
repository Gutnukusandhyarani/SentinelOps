from http.server import BaseHTTPRequestHandler
from sentinelops.vercel_api import handle_ingest, send_json

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        handle_ingest(self)

    def do_GET(self):
        send_json(self, {"error": "method not allowed"}, 405)
