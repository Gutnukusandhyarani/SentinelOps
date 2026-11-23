from http.server import BaseHTTPRequestHandler
from sentinelops.vercel_api import handle_public_summary

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_public_summary(self)
