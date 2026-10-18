from pathlib import Path
import json
import sys

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "raw" / "security_events.csv"
INCIDENT_PATH = PROJECT_ROOT / "reports" / "incident_report.json"
REPLAY_PATH = PROJECT_ROOT / "reports" / "replay_comparison.json"

st.set_page_config(
    page_title="TRACEGUARD | Security Investigator",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }
    [data-testid="stMetric"] {
        background-color: #151f32;
        border: 1px solid #26354d;
        padding: 16px;
        border-radius: 12px;
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid #26354d;
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_events():
    if not DATA_PATH.exists():
        return pd.DataFrame()
    return pd.read_csv(DATA_PATH)


@st.cache_data
def load_json(path_string):
    path = Path(path_string)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


events = load_events()
incident_report = load_json(str(INCIDENT_PATH))
replay_report = load_json(str(REPLAY_PATH))

st.title("🛡️ TRACEGUARD")
st.caption("Evidence-First Security Investigation Platform")
st.markdown("---")

if events.empty:
    st.error("Security event data was not found.")
    st.stop()

# Sidebar filters
st.sidebar.title("Investigation Controls")
st.sidebar.caption("Filter the synthetic security-event dataset.")

users = sorted(events["user"].dropna().astype(str).unique())
selected_users = st.sidebar.multiselect(
    "Filter by user",
    users,
    default=users,
)

event_types = sorted(
    events["event_type"].dropna().astype(str).unique()
)
selected_types = st.sidebar.multiselect(
    "Filter by event type",
    event_types,
    default=event_types,
)

filtered_events = events[
    events["user"].astype(str).isin(selected_users)
    & events["event_type"].astype(str).isin(selected_types)
].copy()

# Overview
alerts = incident_report.get("alerts", [])
alert_count = len(alerts)

suspicious_count = (
    int((events["ground_truth"] == "suspicious").sum())
    if "ground_truth" in events.columns
    else None
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(events))
col2.metric("Filtered Events", len(filtered_events))
col3.metric("Generated Alerts", alert_count)
col4.metric(
    "Ground-Truth Suspicious",
    suspicious_count if suspicious_count is not None else "Not available",
)

st.markdown("---")

# Alerts
st.header("🚨 Security Alerts")

if alerts:
    alert_rows = []

    for alert in alerts:
        alert_rows.append({
            "Alert Type": alert.get("alert_type", "Unknown"),
            "Severity": alert.get("severity", "Unknown").upper(),
            "User": alert.get("user", "Unknown"),
            "Source IP": alert.get("source_ip", "Unknown"),
            "Reason": alert.get("reason", ""),
            "Evidence IDs": ", ".join(
                str(item)
                for item in alert.get("evidence_ids", [])
            ),
        })

    alert_df = pd.DataFrame(alert_rows)

    severity_filter = st.multiselect(
        "Filter alerts by severity",
        sorted(alert_df["Severity"].unique()),
        default=sorted(alert_df["Severity"].unique()),
    )

    visible_alerts = alert_df[
        alert_df["Severity"].isin(severity_filter)
    ]

    st.dataframe(
        visible_alerts,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Alert Severity Breakdown")
    severity_counts = (
        alert_df["Severity"].value_counts().rename_axis("Severity")
        .reset_index(name="Count")
    )
    st.bar_chart(
        severity_counts.set_index("Severity"),
        y="Count",
    )
else:
    st.info("No incident report alerts are available yet.")

# Event logs
st.markdown("---")
st.header("📋 Security Event Explorer")

search_id = st.text_input(
    "Search by event ID",
    placeholder="Example: EVT003",
)

if search_id:
    filtered_events = filtered_events[
        filtered_events["event_id"]
        .astype(str)
        .str.contains(search_id, case=False, na=False)
    ]

st.dataframe(
    filtered_events,
    use_container_width=True,
    hide_index=True,
)

# Incident details
st.markdown("---")
st.header("🔎 Incident Evidence")

if alerts:
    alert_options = [
        f"{index + 1}. {alert.get('alert_type', 'Unknown')} "
        f"— {alert.get('user', 'Unknown user')}"
        for index, alert in enumerate(alerts)
    ]

    chosen_alert = st.selectbox(
        "Select an alert to inspect",
        range(len(alerts)),
        format_func=lambda index: alert_options[index],
    )

    selected_alert = alerts[chosen_alert]

    st.write("*Reason:*", selected_alert.get("reason", "Not provided"))
    st.write("*Severity:*", selected_alert.get("severity", "Unknown"))
    st.write("*Evidence IDs:*")

    evidence_ids = selected_alert.get("evidence_ids", [])
    st.code(", ".join(str(item) for item in evidence_ids) or "No evidence IDs")

    if evidence_ids:
        evidence_rows = events[
            events["event_id"].astype(str).isin(
                [str(item) for item in evidence_ids]
            )
        ]
        st.dataframe(
            evidence_rows,
            use_container_width=True,
            hide_index=True,
        )

# Replay results
st.markdown("---")
st.header("⏪ Investigation Replay")

if replay_report:
    baseline = replay_report.get("baseline", {})
    st.write(
        f"Baseline: *{baseline.get('events_reviewed', 0)} events* "
        f"and *{baseline.get('alerts_generated', 0)} alerts*."
    )

    experiments = replay_report.get("experiments", [])

    if experiments:
        replay_rows = []

        for experiment in experiments:
            replay_rows.append({
                "Experiment": experiment.get("name", "Unknown"),
                "Events Remaining": experiment.get("events_remaining", "N/A"),
                "Alerts Before": experiment.get("original_alert_count", 0),
                "Alerts After": experiment.get("replayed_alert_count", 0),
                "Disappeared": len(
                    experiment.get("alerts_disappeared", [])
                ),
                "Appeared": len(
                    experiment.get("alerts_appeared", [])
                ),
            })

        st.dataframe(
            pd.DataFrame(replay_rows),
            use_container_width=True,
            hide_index=True,
        )

        with st.expander("View detailed replay differences"):
            st.json(experiments)
else:
    st.info(
        "Replay results are not available. Run the investigation replay module first."
    )

# Limitations
st.markdown("---")
with st.expander("⚠️ Dataset and investigation limitations"):
    st.write(
        "This dashboard uses synthetic security events and pre-generated "
        "reports. Alerts indicate patterns matching the current rules; "
        "they do not prove a real compromise. Replay comparisons reflect "
        "the current detection logic and the evidence available."
    )

st.caption("TRACEGUARD • Educational security investigation lab")