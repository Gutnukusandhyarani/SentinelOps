import json
import tempfile
import unittest
from pathlib import Path
from sentinelops.detector import load_imported_rules,detect_imported
from sentinelops.models import SecurityEvent

class ImportedRuleTests(unittest.TestCase):
    def test_sigmaforge_style_rule_pack_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"pack.json"
            path.write_text(json.dumps([{
                "id":"rule-123","title":"Account created","level":"medium",
                "description":"Test imported rule","tags":["attack.persistence"],
                "conditions":[
                    {"field":"action","operator":"equals","value":"account_created"},
                    {"field":"event_id","operator":"equals","value":"4720"}
                ]
            }]))
            rules=load_imported_rules(path)
            event=SecurityEvent(timestamp="2026-11-22T10:00:00Z",host="host",
                source="Windows Security",product="windows",category="identity",
                action="account_created",outcome="success",severity="medium",
                message="Account created",event_id="4720",raw={})
            self.assertEqual(len(detect_imported(event,rules)),1)

if __name__=="__main__": unittest.main()
