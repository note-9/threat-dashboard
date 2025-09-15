# Cybersecurity Threat Dashboard

An interactive Streamlit application that simulates and analyzes cybersecurity logs to detect suspicious activity.

## Features
- Log simulation (ACCESS, AUTH, SCAN events)
- Real-time dashboard with metrics and visualizations
- Brute-force attack detection (configurable thresholds)
- Top source IPs and suspicious event summaries
- Export logs as CSV for further analysis

## Run Locally
```bash
pip install streamlit pandas plotly
streamlit run app.py
```
## Dashboard Sections
- Key Metrics: Total events, unique IPs, failed logins, suspicious activity
- Event Timeline: Time-series chart of event types
- Top IPs: Most active IP addresses
- Brute-Force Detection: Identifies IPs exceeding failed login thresholds
- Raw Logs: Latest events with CSV export

## Applications
- Training & learning log analysis
- Prototyping threat detection pipelines
- Demonstration of SIEM-like dashboards
