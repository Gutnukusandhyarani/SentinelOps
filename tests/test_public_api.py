import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from datetime import datetime, timezone

from sentinelops.server import Handler


class PublicApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        Handler.db_path = self.temp.name + "/public.db"
        Handler.public_mode = True
        Handler.ingest_token = "test-only-token-that-is-long-enough-123456"
        Handler.rules_path = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def get_json(self, path):
        with urlopen(self.base + path, timeout=3) as response:
            return response.status, json.loads(response.read().decode())

    def test_config_declares_public_mode(self):
        status, body = self.get_json("/api/config")
        self.assertEqual(status, 200)
        self.assertTrue(body["public_mode"])

    def test_unauthenticated_ingestion_is_rejected(self):
        payload = json.dumps({"source_type": "json", "records": [{}]}).encode()
        request = Request(self.base + "/api/ingest", data=payload, method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as ctx:
            urlopen(request, timeout=3)
        self.assertEqual(ctx.exception.code, 401)

    def test_authenticated_ingestion_and_aggregate_public_view(self):
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        event = {"timestamp": now, "host": "private-lab-host", "product": "linux", "source": "sshd",
                 "category": "authentication", "action": "login_failed", "outcome": "failure",
                 "severity": "medium", "message": "test event", "source_ip": "192.0.2.8", "user": "private-user"}
        payload = json.dumps({"source_type": "json", "records": [event]}).encode()
        request = Request(self.base + "/api/ingest", data=payload, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {Handler.ingest_token}"})
        with urlopen(request, timeout=3) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(response.status, 202)
            self.assertEqual(result["accepted"], 1)

        _, summary = self.get_json("/api/public/summary")
        self.assertEqual(summary["events"], 1)
        self.assertNotIn("host", summary)
        self.assertNotIn("source_ip", summary)
        _, activity = self.get_json("/api/public/activity")
        self.assertEqual(len(activity), 14)
        self.assertTrue(all(set(day) == {"day", "events", "alerts"} for day in activity))

    def test_private_event_api_is_hidden_in_public_mode(self):
        with self.assertRaises(HTTPError) as ctx:
            urlopen(self.base + "/api/events", timeout=3)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
