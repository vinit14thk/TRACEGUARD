import pandas as pd
from detection_engine import detect_suspicious_activity


def evaluate_dataset(file_path):
    events = pd.read_csv(file_path)
    alerts = detect_suspicious_activity(events)

    # Collect event IDs cited by at least one alert.
    cited_event_ids = {
        event_id
        for alert in alerts
        for event_id in alert["evidence_ids"]
    }

    actual = {
        row["event_id"]: row["ground_truth"] == "suspicious"
        for _, row in events.iterrows()
    }

    results = []
    for event_id, actually_suspicious in actual.items():
        predicted = event_id in cited_event_ids
        results.append({
            "event_id": event_id,
            "ground_truth": "suspicious" if actually_suspicious else "normal",
            "predicted_suspicious": predicted,
            "actually_suspicious": actually_suspicious,
        })

    true_positives = sum(
        row["predicted_suspicious"] and row["actually_suspicious"]
        for row in results
    )
    false_positives = sum(
        row["predicted_suspicious"] and not row["actually_suspicious"]
        for row in results
    )
    false_negatives = sum(
        not row["predicted_suspicious"] and row["actually_suspicious"]
        for row in results
    )

    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives else 0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives else 0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    print(f"\nEvaluation: {file_path}")
    print("=" * 45)
    print(f"Events evaluated: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"True positives:   {true_positives}")
    print(f"False positives:  {false_positives}")
    print(f"False negatives:  {false_negatives}")
    print(f"Precision:        {precision:.3f}")
    print(f"Recall:           {recall:.3f}")
    print(f"F1 score:         {f1:.3f}")
    print("\nEvent-level results:")
    print(pd.DataFrame(results).to_string(index=False))


if __name__ == "__main__":
    evaluate_dataset("data/raw/test_security_events.csv")