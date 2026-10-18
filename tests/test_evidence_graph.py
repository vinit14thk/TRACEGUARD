import unittest
import pandas as pd

from src.evidence_graph import (
    build_evidence_graph,
    find_related_events,
    find_related_events_in_time,
)


class TestEvidenceGraph(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = pd.read_csv("data/raw/security_events.csv")
        cls.graph = build_evidence_graph(cls.events)

    def test_graph_contains_all_events(self):
        event_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get("node_type") == "event"
        ]
        self.assertEqual(len(event_nodes), len(self.events))

    def test_graph_has_expected_entity_types(self):
        node_types = {
            data.get("node_type")
            for _, data in self.graph.nodes(data=True)
        }
        self.assertTrue({"event", "user", "ip", "device"}.issubset(node_types))

    def test_related_events_share_entities(self):
        related = find_related_events(self.graph, "EVT003")
        self.assertIn("EVT004", related)
        self.assertIn("EVT005", related)

    def test_time_filter_returns_nearby_events(self):
        related = find_related_events_in_time(
            self.events, "EVT003", minutes=5
        )
        self.assertIn("EVT004", related)
        self.assertIn("EVT005", related)
        self.assertNotIn("EVT003", related)

    def test_shorter_window_is_not_broader(self):
        within_one = set(
            find_related_events_in_time(self.events, "EVT003", minutes=1)
        )
        within_five = set(
            find_related_events_in_time(self.events, "EVT003", minutes=5)
        )
        self.assertTrue(within_one.issubset(within_five))

    def test_unknown_event_returns_empty_list(self):
        self.assertEqual(
            find_related_events_in_time(
                self.events, "DOES_NOT_EXIST", minutes=5
            ),
            [],
        )

    def test_negative_window_is_rejected(self):
        with self.assertRaises(ValueError):
            find_related_events_in_time(
                self.events, "EVT003", minutes=-1
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)