import pandas as pd


def detect_suspicious_activity(events: pd.DataFrame) -> list[dict]:
    """Detect suspicious patterns and preserve supporting event IDs."""

    alerts = []

    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])
    events["process"] = events["process"].fillna("")

    # Rule 1: Repeated failed logins within five minutes.
    failed = events[
        (events["event_type"] == "login")
        & (events["status"] == "failed")
    ].sort_values("timestamp")

    for (user, source_ip), group in failed.groupby(["user", "source_ip"]):
        group = group.sort_values("timestamp").reset_index(drop=True)

        for start in range(len(group)):
            window_start = group.loc[start, "timestamp"]
            window_end = window_start + pd.Timedelta(minutes=5)

            window = group[
                (group["timestamp"] >= window_start)
                & (group["timestamp"] <= window_end)
            ]

            if len(window) >= 2:
                severity = "high" if len(window) >= 3 else "medium"

                alerts.append({
                    "alert_type": "repeated_failed_logins",
                    "severity": severity,
                    "user": user,
                    "source_ip": source_ip,
                    "reason": (
                        f"{len(window)} failed login attempts "
                        "within five minutes"
                    ),
                    "evidence_ids": window["event_id"].tolist(),
                })
                break

    # Rule 2: Successful login following repeated failures.
    for (user, source_ip), group in events.groupby(["user", "source_ip"]):
        group = group.sort_values("timestamp").reset_index(drop=True)

        for index, row in group.iterrows():
            if row["event_type"] != "login" or row["status"] != "success":
                continue

            start_time = row["timestamp"] - pd.Timedelta(minutes=5)

            previous_failures = group[
                (group["timestamp"] >= start_time)
                & (group["timestamp"] < row["timestamp"])
                & (group["event_type"] == "login")
                & (group["status"] == "failed")
            ]

            if len(previous_failures) >= 3:
                evidence_ids = previous_failures["event_id"].tolist()
                evidence_ids.append(row["event_id"])

                alerts.append({
                    "alert_type": "success_after_repeated_failures",
                    "severity": "high",
                    "user": user,
                    "source_ip": source_ip,
                    "reason": (
                        "Successful login followed at least three "
                        "failed attempts within five minutes"
                    ),
                    "evidence_ids": evidence_ids,
                })

    # Rule 3: Flag a process explicitly named unknown_script.
    suspicious_processes = events[
        (events["event_type"] == "process")
        & (events["process"].str.lower() == "unknown_script")
    ]

    for _, row in suspicious_processes.iterrows():
        alerts.append({
            "alert_type": "unrecognized_process",
            "severity": "medium",
            "user": row["user"],
            "source_ip": row["source_ip"],
            "reason": "Process name matched the lab's suspicious-process rule",
            "evidence_ids": [row["event_id"]],
        })

    # Remove duplicate alerts while preserving the original order.
    unique_alerts = []
    seen = set()

    for alert in alerts:
        key = (
            alert["alert_type"],
            alert["user"],
            alert["source_ip"],
            tuple(alert["evidence_ids"]),
        )

        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts


if __name__ == "__main__":
    events = pd.read_csv("data/raw/security_events.csv")
    alerts = detect_suspicious_activity(events)

    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert {number}: {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"User: {alert['user']}")
        print(f"Reason: {alert['reason']}")
        print(f"Evidence IDs: {', '.join(alert['evidence_ids'])}")