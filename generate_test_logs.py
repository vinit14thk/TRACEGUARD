import pandas as pd
from pathlib import Path

output_path = Path("data/raw/test_security_events.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

events = [
    # Normal activity
    {
        "event_id": "TST001",
        "timestamp": "2026-10-18 09:00:00",
        "user": "alice",
        "source_ip": "10.0.0.12",
        "device": "LAPTOP-01",
        "event_type": "login",
        "status": "success",
        "process": "",
        "ground_truth": "normal",
    },
    # Only one failed login: should not trigger repeated-failure rule
    {
        "event_id": "TST002",
        "timestamp": "2026-10-18 09:05:00",
        "user": "bob",
        "source_ip": "198.51.100.20",
        "device": "UNKNOWN-03",
        "event_type": "login",
        "status": "failed",
        "process": "",
        "ground_truth": "normal",
    },
    # Two failures more than five minutes apart
    {
        "event_id": "TST003",
        "timestamp": "2026-10-18 09:10:00",
        "user": "carol",
        "source_ip": "198.51.100.30",
        "device": "UNKNOWN-04",
        "event_type": "login",
        "status": "failed",
        "process": "",
        "ground_truth": "normal",
    },
    {
        "event_id": "TST004",
        "timestamp": "2026-10-18 09:16:00",
        "user": "carol",
        "source_ip": "198.51.100.30",
        "device": "UNKNOWN-04",
        "event_type": "login",
        "status": "failed",
        "process": "",
        "ground_truth": "normal",
    },
    # Two failures within five minutes: suspicious
    {
        "event_id": "TST005",
        "timestamp": "2026-10-18 09:20:00",
        "user": "david",
        "source_ip": "198.51.100.40",
        "device": "UNKNOWN-05",
        "event_type": "login",
        "status": "failed",
        "process": "",
        "ground_truth": "suspicious",
    },
    {
        "event_id": "TST006",
        "timestamp": "2026-10-18 09:22:00",
        "user": "david",
        "source_ip": "198.51.100.40",
        "device": "UNKNOWN-05",
        "event_type": "login",
        "status": "failed",
        "process": "",
        "ground_truth": "suspicious",
    },
    # A known suspicious process
    {
        "event_id": "TST007",
        "timestamp": "2026-10-18 09:30:00",
        "user": "erin",
        "source_ip": "203.0.113.70",
        "device": "UNKNOWN-06",
        "event_type": "process",
        "status": "observed",
        "process": "unknown_script",
        "ground_truth": "suspicious",
    },
]

df = pd.DataFrame(events)
df.to_csv(output_path, index=False)

print(f"Created {output_path}")
print(f"Total events: {len(df)}")
print("\nGround-truth distribution:")
print(df["ground_truth"].value_counts().to_string())