from pathlib import Path
import json
import pandas as pd

try:
    from .detection_engine import detect_suspicious_activity
except ImportError:
    from detection_engine import detect_suspicious_activity


def remove_event(events: pd.DataFrame, event_id: str) -> pd.DataFrame:
    """Return a copy with one event removed."""
    return events[
        events["event_id"].astype(str) != str(event_id)
    ].copy()


def delay_event(
    events: pd.DataFrame,
    event_id: str,
    minutes: int = 5,
) -> pd.DataFrame:
    """Return a copy with one event delayed."""
    if minutes < 0:
        raise ValueError("Delay must be zero or greater.")

    replayed = events.copy()
    matching = replayed["event_id"].astype(str) == str(event_id)

    if not matching.any():
        raise ValueError(f"Event not found: {event_id}")

    replayed["timestamp"] = pd.to_datetime(replayed["timestamp"])
    replayed.loc[matching, "timestamp"] += pd.Timedelta(minutes=minutes)

    return replayed.sort_values("timestamp").reset_index(drop=True)


def alert_signature(alert: dict) -> tuple:
    """Create a consistent identifier for comparing alerts."""
    evidence_ids = alert.get("evidence_ids", [])

    return (
        alert.get("alert_type", ""),
        alert.get("severity", ""),
        alert.get("user", ""),
        tuple(sorted(str(item) for item in evidence_ids)),
    )


def compare_alerts(original_alerts: list[dict], replayed_alerts: list[dict]) -> dict:
    """Compare alert signatures before and after replay."""
    original = {alert_signature(alert) for alert in original_alerts}
    replayed = {alert_signature(alert) for alert in replayed_alerts}

    return {
        "original_alert_count": len(original_alerts),
        "replayed_alert_count": len(replayed_alerts),
        "alerts_disappeared": [
            list(item) for item in sorted(original - replayed)
        ],
        "alerts_appeared": [
            list(item) for item in sorted(replayed - original)
        ],
    }


def run_replay(events: pd.DataFrame, replayed_events: pd.DataFrame) -> dict:
    """Run detection on original and modified logs."""
    original_alerts = detect_suspicious_activity(events)
    replayed_alerts = detect_suspicious_activity(replayed_events)

    return compare_alerts(original_alerts, replayed_alerts)


def main():
    project_root = Path(__file__).resolve().parent.parent
    data_path = project_root / "data" / "raw" / "security_events.csv"
    report_path = project_root / "reports" / "replay_comparison.json"

    events = pd.read_csv(data_path)

    baseline_alerts = detect_suspicious_activity(events)

    removal_events = remove_event(events, "EVT004")
    removal_result = run_replay(events, removal_events)

    delayed_events = delay_event(events, "EVT006", minutes=5)
    delay_result = run_replay(events, delayed_events)

    report = {
        "report_title": "TRACEGUARD Investigation Replay Comparison",
        "source_dataset": "data/raw/security_events.csv",
        "original_dataset_modified": False,
        "baseline": {
            "events_reviewed": len(events),
            "alerts_generated": len(baseline_alerts),
        },
        "experiments": [
            {
                "name": "Remove EVT004",
                "events_remaining": len(removal_events),
                **removal_result,
            },
            {
                "name": "Delay EVT006 by five minutes",
                "events_remaining": len(delayed_events),
                **delay_result,
            },
        ],
        "limitations": [
            "The dataset contains synthetic events only.",
            "Changed alert signatures do not prove a real security incident.",
            "Results depend on the current detection rules.",
        ],
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("TRACEGUARD INVESTIGATION REPLAY")
    print("=" * 40)
    print(f"Original events: {len(events)}")
    print(f"Original alerts: {len(baseline_alerts)}")

    for experiment in report["experiments"]:
        print(f"\n{experiment['name']}")
        print(f"Alerts before: {experiment['original_alert_count']}")
        print(f"Alerts after: {experiment['replayed_alert_count']}")
        print(f"Disappeared: {len(experiment['alerts_disappeared'])}")
        print(f"Appeared: {len(experiment['alerts_appeared'])}")

    print(f"\nJSON report saved to: {report_path}")
    print("Original CSV was not modified.")


if __name__ == "__main__":
    main()