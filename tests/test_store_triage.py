import tempfile
import unittest
from pathlib import Path
from sentinelops.store import Store

class StoreTriageTests(unittest.TestCase):
    def test_alert_triage_updates_status_and_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp)/"db.sqlite")
            try:
                store.add_alert({
                    "rule_id":"TEST-001","title":"Test alert","severity":"low",
                    "timestamp":"2026-11-22T10:00:00Z","host":"host","entity":"user",
                    "description":"test","evidence":{},"fingerprint":"unique-test-1"
                })
                alert=store.recent_alerts(1)[0]
                self.assertTrue(store.update_alert(alert["id"],"investigating","Reviewed by analyst"))
                updated=store.recent_alerts(1)[0]
                self.assertEqual(updated["status"],"investigating")
                self.assertEqual(updated["notes"],"Reviewed by analyst")
            finally: store.close()

if __name__=="__main__": unittest.main()
