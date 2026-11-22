import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentinelops.ingest import ingest_remote_records
from sentinelops.store import Store


class RemoteIngestionTests(unittest.TestCase):
    def test_ingests_events_and_generates_builtin_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "sentinelops.db")
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            records = [
                {
                    "timestamp": now,
                    "host": "authorized-lab-host",
                    "source": "sshd",
                    "product": "linux",
                    "category": "authentication",
                    "action": "login_failed",
                    "outcome": "failure",
                    "severity": "medium",
                    "message": "Failed password for test-user from 192.0.2.10 port 22 ssh2",
                    "source_ip": "192.0.2.10",
                    "user": "test-user",
                    "event_id": str(i),
                }
                for i in range(5)
            ]
            result = ingest_remote_records(records, "json", db)
            self.assertEqual(result["ingested"], 5)
            self.assertEqual(result["errors"], 0)
            self.assertGreaterEqual(result["alerts"], 1)

            store = Store(db)
            try:
                summary = store.public_summary()
                self.assertEqual(summary["events"], 5)
                self.assertGreaterEqual(summary["alerts"], 1)
                activity = store.public_activity(14)
                self.assertEqual(len(activity), 14)
                self.assertTrue(all(set(item) == {"day", "events", "alerts"} for item in activity))
            finally:
                store.close()

    def test_public_summary_does_not_expose_identifiers_or_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "sentinelops.db")
            store = Store(db)
            try:
                summary = store.public_summary()
                serialized = json.dumps(summary)
                for private_value in ("host", "source_ip", "username", "raw", "evidence", "process"):
                    self.assertNotIn(private_value, serialized)
            finally:
                store.close()

    def test_remote_ingestion_rejects_oversized_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "sentinelops.db")
            with self.assertRaises(ValueError):
                ingest_remote_records([{}] * 51, "json", db)

    def test_remote_ingestion_rejects_unsupported_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "sentinelops.db")
            with self.assertRaises(ValueError):
                ingest_remote_records([{}], "command", db)


if __name__ == "__main__":
    unittest.main()
