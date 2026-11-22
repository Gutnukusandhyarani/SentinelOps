import tempfile
import unittest
from pathlib import Path
from sentinelops.integrity import baseline,check

class IntegrityTests(unittest.TestCase):
    def test_detects_modified_added_and_removed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"watch"; root.mkdir()
            original=root/"original.txt"; original.write_text("one")
            db=str(Path(tmp)/"sentinel.sqlite")
            self.assertEqual(baseline(str(root),db),1)
            original.write_text("two")
            (root/"new.txt").write_text("new")
            changes=check(str(root),db)
            states={Path(item["path"]).name:item["status"] for item in changes}
            self.assertEqual(states["original.txt"],"modified")
            self.assertEqual(states["new.txt"],"added")
            original.unlink()
            second=check(str(root),db)
            self.assertIn("removed",{item["status"] for item in second})

if __name__=="__main__": unittest.main()
