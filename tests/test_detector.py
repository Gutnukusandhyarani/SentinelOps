import tempfile
import unittest
from pathlib import Path
from sentinelops.models import SecurityEvent
from sentinelops.store import Store
from sentinelops.detector import detect_builtin

class DetectorTests(unittest.TestCase):
    def test_ssh_burst_alerts_at_five(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=Store(Path(tmp)/"test.db")
            try:
                event=None
                for n in range(5):
                    event=SecurityEvent(timestamp=f"2026-11-22T09:0{n}:00+00:00",host="lab",
                        source="sshd",product="linux",category="authentication",action="login_failed",
                        outcome="failure",severity="medium",message="Failed password",
                        source_ip="203.0.113.45",user="user",event_id="sshd",raw={})
                    store.add_event(event)
                alerts=detect_builtin(event,store)
                self.assertTrue(any(a["rule_id"]=="AUTH-001" for a in alerts))
            finally: store.close()

if __name__=="__main__": unittest.main()
