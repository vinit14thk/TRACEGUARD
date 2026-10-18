import unittest
import pandas as pd

from src.investigation_replay import (
    remove_event,
    delay_event,
    compare_alerts,
)


class TestInvestigationReplay(unittest.TestCase):

    def setUp(self):
        self.events = pd.DataFrame({
            "event_id": ["EVT001", "EVT002", "EVT003"],
            "timestamp": [
                "2026-10-16 08:00:00",
                "2026-10-16 08:01:00",
                "2026-10-16 08:02:00",
            ],
        })

    def test_remove_event(self):
        result = remove_event(self.events, "EVT002")

        self.assertEqual(len(result), 2)
        self.assertNotIn("EVT002", result["event_id"].tolist())

    def test_removing_event_preserves_original(self):
        original_count = len(self.events)

        remove_event(self.events, "EVT002")

        self.assertEqual(len(self.events), original_count)

    def test_delay_event(self):
        result = delay_event(self.events, "EVT002", minutes=5)

        delayed_timestamp = pd.to_datetime(
            result.loc[
                result["event_id"] == "EVT002",
                "timestamp",
            ].iloc[0]
        )

        self.assertEqual(
            delayed_timestamp,
            pd.Timestamp("2026-10-16 08:06:00"),
        )

    def test_delay_preserves_original(self):
        original_timestamp = self.events.loc[
            self.events["event_id"] == "EVT002",
            "timestamp",
        ].iloc[0]

        delay_event(self.events, "EVT002", minutes=5)

        self.assertEqual(
            self.events.loc[
                self.events["event_id"] == "EVT002",
                "timestamp",
            ].iloc[0],
            original_timestamp,
        )

    def test_missing_event_raises_error(self):
        with self.assertRaises(ValueError):
            delay_event(self.events, "UNKNOWN", minutes=5)

    def test_negative_delay_raises_error(self):
        with self.assertRaises(ValueError):
            delay_event(self.events, "EVT002", minutes=-1)

    def test_alert_comparison(self):
        original = [
            {
                "alert_type": "failed_login",
                "severity": "high",
                "user": "Alice",
                "evidence_ids": ["EVT001", "EVT002"],
            }
        ]

        replayed = [
            {
                "alert_type": "failed_login",
                "severity": "high",
                "user": "Alice",
                "evidence_ids": ["EVT001"],
            }
        ]

        result = compare_alerts(original, replayed)

        self.assertEqual(result["original_alert_count"], 1)
        self.assertEqual(result["replayed_alert_count"], 1)
        self.assertEqual(len(result["alerts_disappeared"]), 1)
        self.assertEqual(len(result["alerts_appeared"]), 1)


if __name__ == "__main__":
    unittest.main()