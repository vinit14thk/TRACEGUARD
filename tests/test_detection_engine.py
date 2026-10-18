import unittest
import pandas as pd

from src.detection_engine import detect_suspicious_activity


class TestDetectionEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = pd.read_csv("data/raw/security_events.csv")

    def test_repeated_failed_logins_detected(self):
        alerts = detect_suspicious_activity(self.events)

        matching = [
            alert for alert in alerts
            if alert["alert_type"] == "repeated_failed_logins"
            and alert["user"] == "alice"
        ]

        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["severity"], "high")
        self.assertEqual(
            matching[0]["evidence_ids"],
            ["EVT003", "EVT004", "EVT005"]
        )

    def test_success_after_failures_detected(self):
        alerts = detect_suspicious_activity(self.events)

        matching = [
            alert for alert in alerts
            if alert["alert_type"] == "success_after_repeated_failures"
        ]

        self.assertEqual(len(matching), 1)
        self.assertIn("EVT006", matching[0]["evidence_ids"])
        self.assertIn("EVT003", matching[0]["evidence_ids"])

    def test_suspicious_process_detected(self):
        alerts = detect_suspicious_activity(self.events)

        matching = [
            alert for alert in alerts
            if alert["alert_type"] == "unrecognized_process"
        ]

        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["evidence_ids"], ["EVT007"])

    def test_two_failed_logins_trigger_medium_alert(self):
        bob_events = self.events[
            (self.events["user"] == "bob")
            & (self.events["source_ip"] == "198.51.100.77")
        ]

        alerts = detect_suspicious_activity(bob_events)

        matching = [
            alert for alert in alerts
            if alert["alert_type"] == "repeated_failed_logins"
        ]

        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["severity"], "medium")
        self.assertEqual(
            matching[0]["evidence_ids"],
            ["EVT009", "EVT010"]
        )

    def test_ground_truth_does_not_change_detections(self):
        original_alerts = detect_suspicious_activity(self.events)

        changed_events = self.events.copy()
        changed_events["ground_truth"] = "normal"

        changed_alerts = detect_suspicious_activity(changed_events)

        self.assertEqual(original_alerts, changed_alerts)


if __name__ == "__main__":
    unittest.main(verbosity=2)