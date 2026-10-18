import unittest
import pandas as pd

from src.incident_report import (
    generate_incident_report,
    validate_report_evidence,
)


class TestIncidentReport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = pd.read_csv("data/raw/security_events.csv")
        cls.report = generate_incident_report(cls.events)

    def test_report_contains_all_events(self):
        self.assertEqual(
            self.report["events_reviewed"],
            len(self.events),
        )

    def test_report_generates_alerts(self):
        self.assertGreater(
            self.report["alerts_generated"],
            0,
        )

    def test_all_evidence_references_are_valid(self):
        errors = validate_report_evidence(
            self.report,
            self.events,
        )
        self.assertEqual(errors, [])

    def test_unknown_evidence_id_is_rejected(self):
        invalid_report = {
            "alerts": [
                {
                    "evidence_ids": ["FAKE999"],
                    "evidence": [
                        {"event_id": "FAKE999"}
                    ],
                }
            ]
        }

        errors = validate_report_evidence(
            invalid_report,
            self.events,
        )

        self.assertTrue(errors)

    def test_mismatched_evidence_details_are_rejected(self):
        invalid_report = {
            "alerts": [
                {
                    "evidence_ids": ["EVT001"],
                    "evidence": [
                        {"event_id": "EVT002"}
                    ],
                }
            ]
        }

        errors = validate_report_evidence(
            invalid_report,
            self.events,
        )

        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()