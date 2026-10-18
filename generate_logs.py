import csv
from pathlib import Path

OUTPUT_FILE = Path("data/raw/security_events.csv")

FIELDS = [
    "event_id", "timestamp", "event_type", "user",
    "source_ip", "device", "process", "status", "ground_truth"
]

EVENTS = [
    {"event_id": "EVT001", "timestamp": "2026-10-18T08:00:00", "event_type": "login", "user": "alice", "source_ip": "10.0.0.12", "device": "LAPTOP-01", "process": "", "status": "success", "ground_truth": "normal"},
    {"event_id": "EVT002", "timestamp": "2026-10-18T08:03:00", "event_type": "login", "user": "bob", "source_ip": "10.0.0.15", "device": "LAPTOP-02", "process": "", "status": "success", "ground_truth": "normal"},
    {"event_id": "EVT003", "timestamp": "2026-10-18T08:10:00", "event_type": "login", "user": "alice", "source_ip": "203.0.113.50", "device": "UNKNOWN-01", "process": "", "status": "failed", "ground_truth": "suspicious"},
    {"event_id": "EVT004", "timestamp": "2026-10-18T08:10:20", "event_type": "login", "user": "alice", "source_ip": "203.0.113.50", "device": "UNKNOWN-01", "process": "", "status": "failed", "ground_truth": "suspicious"},
    {"event_id": "EVT005", "timestamp": "2026-10-18T08:10:40", "event_type": "login", "user": "alice", "source_ip": "203.0.113.50", "device": "UNKNOWN-01", "process": "", "status": "failed", "ground_truth": "suspicious"},
    {"event_id": "EVT006", "timestamp": "2026-10-18T08:11:00", "event_type": "login", "user": "alice", "source_ip": "203.0.113.50", "device": "UNKNOWN-01", "process": "", "status": "success", "ground_truth": "suspicious"},
    {"event_id": "EVT007", "timestamp": "2026-10-18T08:14:00", "event_type": "process", "user": "alice", "source_ip": "203.0.113.50", "device": "UNKNOWN-01", "process": "unknown_script", "status": "observed", "ground_truth": "suspicious"},
    {"event_id": "EVT008", "timestamp": "2026-10-18T08:20:00", "event_type": "login", "user": "carol", "source_ip": "10.0.0.22", "device": "LAPTOP-03", "process": "", "status": "success", "ground_truth": "normal"},
    {"event_id": "EVT009", "timestamp": "2026-10-18T08:25:00", "event_type": "login", "user": "bob", "source_ip": "198.51.100.77", "device": "UNKNOWN-02", "process": "", "status": "failed", "ground_truth": "suspicious"},
    {"event_id": "EVT010", "timestamp": "2026-10-18T08:25:15", "event_type": "login", "user": "bob", "source_ip": "198.51.100.77", "device": "UNKNOWN-02", "process": "", "status": "failed", "ground_truth": "suspicious"},
]

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(EVENTS)

print(f"Created {OUTPUT_FILE}")
print(f"Total events: {len(EVENTS)}")
print("Ground-truth labels are included for testing only.")