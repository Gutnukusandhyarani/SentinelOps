import unittest
from sentinelops.normalize import parse_ssh_line, normalize_line
from sentinelops.models import normalize_windows_event

class NormalizeTests(unittest.TestCase):
    def test_ssh_failure(self):
        event=parse_ssh_line("Nov 22 10:01:02 labbox sshd[100]: Failed password for testuser from 192.0.2.10 port 22 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.action,"login_failed")
        self.assertEqual(event.user,"testuser")
        self.assertEqual(event.source_ip,"192.0.2.10")

    def test_ssh_success(self):
        event=parse_ssh_line("Nov 22 10:01:02 labbox sshd[100]: Accepted publickey for testuser from 192.0.2.10 port 22 ssh2")
        self.assertEqual(event.action,"login_success")

    def test_windows_4625(self):
        event=normalize_windows_event({"EventID":4625,"Computer":"host","EventData":{"TargetUserName":"demo","IpAddress":"192.0.2.20"}})
        self.assertEqual(event.action,"login_failed")
        self.assertEqual(event.source_ip,"192.0.2.20")

    def test_json_normalization(self):
        event=normalize_line('{"host":"node","action":"login_success","outcome":"success"}',"json")
        self.assertEqual(event.host,"node")
        self.assertEqual(event.action,"login_success")

if __name__=="__main__": unittest.main()
