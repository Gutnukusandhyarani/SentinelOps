from http.server import BaseHTTPRequestHandler
from sentinelops.vercel_api import handle_config

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_config(self)
