# app.py
import streamlit as st
import pandas as pd
import datetime
import io
import random
from collections import Counter
import plotly.express as px

st.set_page_config(layout="wide", page_title="Cybersecurity Threat Dashboard")

# -------------------------
# Log simulator
# -------------------------
def simulate_logs(minutes=60, events_per_min=20, bruteforce_ips=None):
    """
    Simulate simple security logs:
      - type: ACCESS (OK), AUTH (SUCCESS/FAILED), SCAN (SUSPICIOUS)
    Returns a pandas.DataFrame with columns: ts, src_ip, type, service, status, user, msg
    """
    now = datetime.datetime.utcnow().replace(second=0, microsecond=0)
    lines = []
    if bruteforce_ips is None:
        bruteforce_ips = ["192.0.2.10", "198.51.100.5", "203.0.113.7"]

    users = ["alice", "bob", "root", "svc-agent", "charlie", "dave"]
    services = ["ssh", "http", "smtp", "rdp", "db"]

    for m in range(minutes):
        t = now - datetime.timedelta(minutes=(minutes - 1 - m))
        for e in range(events_per_min):
            r = random.random()
            # event type distribution
            if r < 0.80:
                typ, status = "ACCESS", "OK"
            elif r < 0.92:
                typ = "AUTH"
                # AUTH is more likely to be FAILED in this simulation
                status = random.choices(["FAILED", "SUCCESS"], weights=[3, 1])[0]
            else:
                typ, status = "SCAN", "SUSPICIOUS"

            # source IP: brute-force IPs more likely on AUTH failures
            if typ == "AUTH" and status == "FAILED" and random.random() < 0.6:
                ip = random.choice(bruteforce_ips)
            else:
                ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

            user = random.choice(users)
            service = random.choice(services)
            msg = f"{typ} {service} {status} user={user}"

            lines.append({
                "ts": (t.isoformat() + "Z"),
                "src_ip": ip,
                "type": typ,
                "service": service,
                "status": status,
                "user": user,
                "msg": msg
            })

    df = pd.DataFrame(lines)
    df["ts"] = pd.to_datetime(df["ts"])
    return df

# -------------------------
# Detection helpers
# -------------------------
def detect_bruteforce(df, window_minutes=10, threshold=10):
    """
    Detect IPs with >= threshold failed AUTH attempts within the last window_minutes.
    """
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "failed_count"])
    now = df["ts"].max()
    window_start = now - pd.Timedelta(minutes=window_minutes)
    sub = df[
        (df["ts"] >= window_start) &
        (df["type"] == "AUTH") &
        (df["status"] == "FAILED")
    ]
    if sub.empty:
        return pd.DataFrame(columns=["src_ip", "failed_count"])
    c = sub["src_ip"].value_counts()
    suspects = pd.DataFrame({"src_ip": c.index, "failed_count": c.values})
    return suspects[suspects["failed_count"] >= threshold].reset_index(drop=True)

# -------------------------
# Streamlit UI
# -------------------------
st.title("Cybersecurity Threat Dashboard (Simulated Logs)")
st.markdown("Simulated security logs demo — adjust controls in the sidebar and generate events.")

with st.sidebar:
    st.header("Simulation Controls")
    minutes = st.slider("Window (minutes)", min_value=10, max_value=240, value=60, step=10)
    events_per_min = st.slider("Events per minute", min_value=1, max_value=200, value=20)
    bf_ips_text = st.text_area("Brute-force IPs (comma-separated)", value="192.0.2.10,198.51.100.5", height=80)
    bf_ips = [ip.strip() for ip in bf_ips_text.split(",") if ip.strip()]
    gen = st.button("Generate Simulated Logs")
    st.markdown("---")
    st.markdown("Detection Settings")
    bf_window = st.slider("Brute-force detection window (minutes)", 1, 60, 10)
    bf_threshold = st.slider("Failed attempts threshold", 1, 50, 10)

# Initialize or regenerate dataset in session state
if "df" not in st.session_state:
    st.session_state.df = simulate_logs(60, 20, ["192.0.2.10", "198.51.100.5"])

if gen:
    st.session_state.df = simulate_logs(minutes, events_per_min, bf_ips or None)

df = st.session_state.df.copy()

# Top metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", f"{len(df):,}")
col2.metric("Unique Source IPs", f"{df['src_ip'].nunique():,}")
col3.metric("Auth Failures", f"{len(df[(df['type']=='AUTH') & (df['status']=='FAILED')]):,}")
col4.metric("Suspicious Events", f"{len(df[df['status']=='SUSPICIOUS']):,}")

# Time series (5-minute bins)
st.subheader("Events over time")
ts = df.set_index("ts").groupby([pd.Grouper(freq="5Min"), "type"]).size().unstack(fill_value=0)
ts = ts.reset_index()
if ts.shape[0] == 0:
    st.info("No events to show.")
else:
    # Plotly line chart
    fig = px.line(ts, x="ts", y=[c for c in ts.columns if c != "ts"], labels={"value":"count","ts":"time"})
    fig.update_layout(legend_title_text="Event Type", margin=dict(l=10, r=10, t=30, b=10))
    st.plotly_chart(fig, use_container_width=True)

# Top IPs
st.subheader("Top Source IPs (by total events)")
top_ips = df["src_ip"].value_counts().reset_index()
top_ips.columns = ["src_ip", "count"]
st.dataframe(top_ips.head(50), use_container_width=True)

# Brute-force detection
st.subheader("Brute-force / Failed Auth Detection")
suspects = detect_bruteforce(df, window_minutes=bf_window, threshold=bf_threshold)
if not suspects.empty:
    st.warning(f"Detected {len(suspects)} suspicious IP(s) with ≥ {bf_threshold} failed AUTH attempts in the last {bf_window} minutes")
    st.table(suspects)
else:
    st.success("No brute-force suspects found in the selected window")

# Raw logs and export
st.subheader("Raw logs (latest)")
st.dataframe(df.sort_values("ts", ascending=False).reset_index(drop=True).head(500), use_container_width=True)

# CSV download
buf = io.StringIO()
df.to_csv(buf, index=False)
st.download_button("Download CSV", buf.getvalue(), file_name="simulated_logs.csv", mime="text/csv")

# Small footer
st.markdown("---")
st.markdown("Demo: simulated logs only. For production-style ingestion, replace simulation with file or socket ingestion and add parsers for syslog/nginx/authlog formats.")
