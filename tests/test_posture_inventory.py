import json
import tempfile
import unittest
from pathlib import Path
from sentinelops.inventory import export_python_inventory
from sentinelops.posture import run_posture_audit

class PostureInventoryTests(unittest.TestCase):
    def test_posture_returns_structured_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            ssh=Path(tmp)/"sshd_config"
            ssh.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
            results=run_posture_audit(str(ssh))
            self.assertTrue(results)
            self.assertTrue(all({"id","title","status","finding","recommendation"} <= set(r) for r in results))

    def test_inventory_writes_cyclonedx(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"sbom.json"
            result=export_python_inventory(str(output))
            data=json.loads(output.read_text())
            self.assertEqual(data["bomFormat"],"CycloneDX")
            self.assertGreaterEqual(result["components"],0)

if __name__=="__main__": unittest.main()
