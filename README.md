\# TRACEGUARD

\### An Evidence-First, Replayable Security Investigation Toolkit



TRACEGUARD is a Python-based security investigation project that analyzes synthetic security logs, detects suspicious activity, connects related events through an evidence graph, and generates evidence-backed incident reports.



The project emphasizes traceability, testability, and transparent limitations rather than treating an alert as proof of a security breach.



\## Features



\- \*Rule-Based Detection:\* Identifies repeated failed logins, successful logins after repeated failures, and events involving a configured suspicious process.

\- \*Evidence Graph:\* Connects security events to users, source IP addresses, and devices using NetworkX.

\- \*Time-Aware Investigation:\* Finds related events within a configurable time window.

\- \*Incident Reporting:\* Generates a structured JSON report containing alert details and supporting event references.

\- \*Evidence Validation:\* Checks that cited event IDs exist in the source dataset and match the report's evidence details.

\- \*Evaluation:\* Calculates event-level precision, recall, and F1 score against synthetic test labels.

\- \*Automated Tests:\* Uses Python's unittest framework to test detection, graph relationships, and report validation.

\- \*Visualization:\* Produces a graph image for exploring relationships between events and entities.



\## Technology Stack



\- Python

\- Pandas

\- NetworkX

\- Matplotlib

\- SQLite (planned for further investigation workflows)

\- unittest



\## Project Structure



```text

TRACEGUARD/

├── data/

│   ├── raw/

│   │   ├── security\_events.csv

│   │   └── test\_security\_events.csv

│   └── processed/

├── docs/

├── reports/

│   ├── evidence\_graph.png

│   └── incident\_report.json

├── src/

│   ├── detection\_engine.py

│   ├── evaluation.py

│   ├── evidence\_graph.py

│   ├── incident\_report.py

│   └── visualize\_graph.py

├── tests/

│   ├── test\_detection\_engine.py

│   ├── test\_evidence\_graph.py

│   └── test\_incident\_report.py

├── generate\_logs.py

├── generate\_test\_logs.py

└── run\_traceguard.py



\---



\## Interactive Streamlit Dashboard



TRACEGUARD includes an interactive web dashboard for exploring security events, generated alerts, incident evidence, and investigation replay results.



\### Dashboard Features



\- \*Security Overview:\* View event counts and generated alerts.

\- \*Alert Explorer:\* Filter alerts by severity and inspect their evidence.

\- \*Event Explorer:\* Search security logs by user, event type, and event ID.

\- \*Incident Investigation:\* Inspect alerts and their supporting event evidence.

\- \*Investigation Replay:\* Compare alert changes after removing or delaying events.

\- \*Visual Analytics:\* Explore alert severity using charts.



\### Run the Dashboard on Windows



1\. Clone or download this repository and open PowerShell in the project folder.



2\. Create a virtual environment using Python 3.13:



&#x20;  ```powershell

&#x20;  py -3.13 -m venv .venv

