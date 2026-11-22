import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelops.agent import follow_file
from sentinelops.store import Store

class AgentTests(unittest.TestCase):
    def test_follow_collector_reads_existing_lines_and_detects_burst(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            log=root/"auth.log"
            lines=[
                f"Nov 22 10:0{i}:00 host sshd[100]: Failed password for analyst from 203.0.113.70 port 22 ssh2"
                for i in range(5)
            ]
            log.write_text("\n".join(lines)+"\n")
            db=root/"events.sqlite"
            with patch("sentinelops.agent.time.sleep",side_effect=KeyboardInterrupt):
                counts=follow_file(str(log),"ssh",str(db),from_start=True)
            self.assertEqual(counts["ingested"],5)
            self.assertGreaterEqual(counts["alerts"],1)
            store=Store(db)
            try:
                self.assertEqual(store.summary()["events"],5)
            finally:
                store.close()

if __name__=="__main__": unittest.main()
