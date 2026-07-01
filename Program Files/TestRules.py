from __future__ import annotations

import unittest
from datetime import datetime, timezone
import sys
from pathlib import Path

# Add Program Files to import path
PROGRAM_FILES_DIR = Path(__file__).resolve().parent
if str(PROGRAM_FILES_DIR) not in sys.path:
    sys.path.insert(0, str(PROGRAM_FILES_DIR))

from Detection.Rules import (
    detect_brute_force,
    detect_privilege_escalation,
    detect_suspicious_process_chain,
)
from Models import Event

def dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

class TestDetectionRules(unittest.TestCase):
    def test_brute_force_detection(self):
        events = [
            Event(timestamp=dt("2026-05-14T09:18:32Z"), source_file="a.csv", user="jdoe", ip_address="10.10.8.21", host="ws-014", action="failed_login", outcome="failure", message="Failed login"),
            Event(timestamp=dt("2026-05-14T09:19:01Z"), source_file="a.csv", user="jdoe", ip_address="10.10.8.21", host="ws-014", action="failed_login", outcome="failure", message="Failed login"),
            Event(timestamp=dt("2026-05-14T09:19:44Z"), source_file="a.csv", user="jdoe", ip_address="10.10.8.21", host="ws-014", action="successful_login", outcome="success", message="Successful login"),
        ]
        result = detect_brute_force(events)
        self.assertTrue(result.triggered)

    def test_privilege_detection(self):
        events = [
            Event(timestamp=dt("2026-05-14T10:02:11Z"), source_file="b.csv", user="admin01", ip_address="10.0.0.1", host="dc-01", action="group_change", outcome="success", event_category="privilege", message="User added to local administrators group"),
        ]
        result = detect_privilege_escalation(events)
        self.assertTrue(result.triggered)

    def test_process_chain_detection(self):
        events = [
            Event(timestamp=dt("2026-05-14T08:51:12Z"), source_file="c.txt", user="user1", ip_address="10.0.0.1", host="ws-014", process_name="cmd.exe", parent_process_name="winword.exe", action="start", outcome="success", message="Command shell launched from document"),
            Event(timestamp=dt("2026-05-14T08:51:18Z"), source_file="c.txt", user="user1", ip_address="10.0.0.1", host="ws-014", process_name="powershell.exe", parent_process_name="cmd.exe", action="start", outcome="success", message="Script process launched"),
        ]
        result = detect_suspicious_process_chain(events)
        self.assertTrue(result.triggered)

if __name__ == "__main__":
    unittest.main()
