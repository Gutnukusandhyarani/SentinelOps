import tempfile, unittest
from pathlib import Path
from sentinelops.ingest import ingest_file
from sentinelops.store import Store

class IngestTests(unittest.TestCase):
    def test_ingest_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=str(Path(tmp)/"db.sqlite")
            sample=Path(__file__).parents[1]/"samples"/"sample_events.jsonl"
            result=ingest_file(str(sample),"json",db)
            self.assertEqual(result["ingested"],6)
            store=Store(db)
            try:
                self.assertEqual(store.summary()["events"],6)
                self.assertGreaterEqual(store.summary()["alerts"],1)
            finally: store.close()

if __name__=="__main__": unittest.main()
