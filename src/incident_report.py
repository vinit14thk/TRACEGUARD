from pathlib import Path
import json

import pandas as pd
try:
    from .detection_engine import detect_suspicious_activity
except ImportError:
    from detection_engine import detect_suspicious_activity

def generate_incident_report(events: pd.DataFrame) -> dict:
    """
    Create an incident report where every alert includes
    the IDs of the events that support it.
    """
    alerts = detect_suspicious_activity(events)

    event_lookup = {
        str(row["event_id"]): row.to_dict()
        for _, row in events.iterrows()
    }

    report_alerts = []

    for alert in alerts:
        evidence = []

        for event_id in alert.get("evidence_ids", []):
            event = event_lookup.get(str(event_id))

            if event is None:
                continue

            evidence.append({
                "event_id": str(event_id),
                "timestamp": str(event.get("timestamp", "")),
                "user": str(event.get("user", "")),
                "source_ip": str(event.get("source_ip", "")),
                "device": str(event.get("device", "")),
                "event_type": str(event.get("event_type", "")),
                "status": str(event.get("status", "")),
                "process": str(event.get("process", "") or ""),
            })

        report_alerts.append({
            "alert_type": alert["alert_type"],
            "severity": alert["severity"],
            "user": alert["user"],
            "source_ip": alert["source_ip"],
            "reason": alert["reason"],
            "evidence": evidence,
            "evidence_ids": [item["event_id"] for item in evidence],
        })

    return {
        "report_title": "TRACEGUARD Security Investigation Report",
        "events_reviewed": len(events),
        "alerts_generated": len(report_alerts),
        "alerts": report_alerts,
        "limitations": [
            "This report uses synthetic security events.",
            "An alert indicates suspicious patterns, not proof of compromise.",
            "Conclusions are limited to the available event evidence.",
        ],
    }


def main():
    input_path = Path("data/raw/security_events.csv")
    output_path = Path("reports/incident_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events = pd.read_csv(input_path)
    report = generate_incident_report(events)

    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("TRACEGUARD Incident Report")
    print("=" * 32)
    print(f"Events reviewed: {report['events_reviewed']}")
    print(f"Alerts generated: {report['alerts_generated']}")

    for number, alert in enumerate(report["alerts"], start=1):
        print(f"\nAlert {number}: {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"User: {alert['user']}")
        print(f"Reason: {alert['reason']}")
        print(f"Evidence IDs: {', '.join(alert['evidence_ids'])}")

    print(f"\nJSON report saved to: {output_path}")


if __name__ == "__main__":
    main()

def validate_report_evidence(
    report: dict,
    source_events: pd.DataFrame,
) -> list[str]:
    """
    Check that every evidence ID in the report exists in the source data.
    Return a list of validation errors; an empty list means all references exist.
    """
    known_ids = set(source_events["event_id"].astype(str))
    errors = []

    for alert_number, alert in enumerate(report.get("alerts", []), start=1):
        for evidence_id in alert.get("evidence_ids", []):
            if str(evidence_id) not in known_ids:
                errors.append(
                    f"Alert {alert_number} references unknown event: {evidence_id}"
                )

        evidence_item_ids = {
            str(item.get("event_id"))
            for item in alert.get("evidence", [])
        }
        cited_ids = {str(value) for value in alert.get("evidence_ids", [])}

        if evidence_item_ids != cited_ids:
            errors.append(
                f"Alert {alert_number} has a mismatch between evidence IDs "
                "and evidence details"
            )

    return errors