"""Member 4 - Dashboard (Streamlit).  Run:  streamlit run app.py"""
import io
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from data_processor import DataValidationError, load_events
from detection_engine import DEFAULT_CONFIG
from generate_sample_data import generate
from pipeline import run_pipeline

st.set_page_config(page_title="IDS", page_icon="🛡️", layout="wide")

SEV_ORDER = ["Low", "Medium", "High", "Critical"]
SEV_COLORS = {"Low": "#7AA6C2", "Medium": "#E0A030", "High": "#D9534F", "Critical": "#8B1A1A"}
SAMPLE_PATH = Path(__file__).parent / "data" / "network_events.csv"


@st.cache_data(show_spinner="Analyzing events...")
def analyze(raw: bytes, cfg_items: tuple):
    events, report = load_events(io.BytesIO(raw))
    return report, run_pipeline(events, dict(cfg_items))


# ---------------- Sidebar ----------------
st.sidebar.title("🛡️ IDS")
st.sidebar.header("Data source")
source = st.sidebar.radio("Choose data", ["Sample dataset", "Upload CSV"])

if source == "Upload CSV":
    upload = st.sidebar.file_uploader("CSV file", type="csv")
    st.sidebar.caption("Required columns: timestamp, src_ip, dst_ip, protocol, dst_port, "
                       "event_type (connection / login_success / login_failed). "
                       "Optional: label (enables evaluation).")
    if upload is None:
        st.title("IDS - Intrusion Detection System")
        st.info("Upload a CSV file from the sidebar, or switch to the sample dataset.")
        st.stop()
    raw = upload.getvalue()
else:
    if not SAMPLE_PATH.exists():
        generate()
    raw = SAMPLE_PATH.read_bytes()

st.sidebar.header("Detection thresholds")
cfg = dict(DEFAULT_CONFIG)
with st.sidebar.expander("Failed logins", expanded=False):
    cfg["failed_login_threshold"] = st.number_input("Attempts", 1, 100, DEFAULT_CONFIG["failed_login_threshold"], key="fl_t")
    cfg["failed_login_window"] = st.number_input("Window (seconds)", 1, 3600, DEFAULT_CONFIG["failed_login_window"], key="fl_w")
with st.sidebar.expander("Port scanning", expanded=False):
    cfg["port_scan_threshold"] = st.number_input("Distinct ports", 1, 200, DEFAULT_CONFIG["port_scan_threshold"], key="ps_t")
    cfg["port_scan_window"] = st.number_input("Window (seconds)", 1, 3600, DEFAULT_CONFIG["port_scan_window"], key="ps_w")
with st.sidebar.expander("Connection rate", expanded=False):
    cfg["conn_rate_threshold"] = st.number_input("Connections", 1, 1000, DEFAULT_CONFIG["conn_rate_threshold"], key="cr_t")
    cfg["conn_rate_window"] = st.number_input("Window (seconds)", 1, 3600, DEFAULT_CONFIG["conn_rate_window"], key="cr_w")

try:
    report, res = analyze(raw, tuple(sorted(cfg.items())))
except DataValidationError as exc:
    st.error(str(exc))
    st.stop()

events, alerts = res["events"], res["alerts"]

# ---------------- Header ----------------
st.title("IDS - Intrusion Detection System")
st.caption("Rule-based detection on network events, stored in a SQL database.")
if report["rows_dropped"]:
    with st.expander(f"⚠️ {report['rows_dropped']} invalid rows were removed"):
        st.write(report["reasons"])

tab_over, tab_alerts, tab_events, tab_eval = st.tabs(["Overview", "Alerts", "Events", "Evaluation"])

# ---------------- Overview ----------------
with tab_over:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", f"{len(events):,}")
    c2.metric("Total alerts", len(alerts))
    c3.metric("Suspicious sources", alerts["src_ip"].nunique() if len(alerts) else 0)
    c4.metric("High / Critical alerts", int(alerts["severity"].isin(["High", "Critical"]).sum()) if len(alerts) else 0)

    if alerts.empty:
        st.success("No alerts were raised with the current thresholds.")
    else:
        left, right = st.columns(2)
        sev = res["by_severity"].set_index("severity").reindex(SEV_ORDER).dropna().reset_index()
        fig = px.bar(sev, x="severity", y="alerts", color="severity",
                     color_discrete_map=SEV_COLORS, title="Alerts by severity")
        fig.update_layout(showlegend=False)
        left.plotly_chart(fig, width="stretch")
        fig = px.pie(res["by_rule"], names="rule_name", values="alerts", title="Alerts by rule", hole=0.4)
        right.plotly_chart(fig, width="stretch")

    traffic = events.set_index("timestamp").resample("5min").size().reset_index(name="events")
    st.plotly_chart(px.bar(traffic, x="timestamp", y="events", title="Traffic volume (events per 5 minutes)"),
                    width="stretch")
    if len(alerts):
        fig = px.scatter(alerts, x="first_seen", y="rule_name", color="severity", size="event_count",
                         color_discrete_map=SEV_COLORS, hover_data=["src_ip", "dst_ip"],
                         title="Alert timeline")
        st.plotly_chart(fig, width="stretch")

# ---------------- Alerts ----------------
with tab_alerts:
    if alerts.empty:
        st.info("No alerts to show.")
    else:
        f1, f2, f3 = st.columns(3)
        rules = f1.multiselect("Rule", sorted(alerts["rule_name"].unique()))
        sevs = f2.multiselect("Severity", [s for s in SEV_ORDER if s in set(alerts["severity"])])
        ip_q = f3.text_input("Source IP contains")

        view = alerts
        if rules:
            view = view[view["rule_name"].isin(rules)]
        if sevs:
            view = view[view["severity"].isin(sevs)]
        if ip_q:
            view = view[view["src_ip"].str.contains(ip_q.strip(), regex=False)]

        st.dataframe(view.drop(columns=["description"]), hide_index=True)
        st.caption(f"{len(view)} of {len(alerts)} alerts shown")

        if len(view):
            st.subheader("Alert details")
            chosen = st.selectbox("Select an alert", view["alert_id"].tolist(),
                                  format_func=lambda i: f"#{i} - {view.set_index('alert_id').loc[i, 'rule_name']} "
                                                        f"({view.set_index('alert_id').loc[i, 'src_ip']})")
            a = view.set_index("alert_id").loc[chosen]
            st.markdown(f"**Why it was raised:** {a['description']}")
            st.markdown(f"**Severity:** {a['severity']}  |  **Window:** {a['first_seen']} to {a['last_seen']}")
            related = events[(events["src_ip"] == a["src_ip"]) &
                             (events["timestamp"] >= a["first_seen"]) &
                             (events["timestamp"] <= a["last_seen"])]
            st.markdown(f"**Related events ({len(related)}):**")
            st.dataframe(related.drop(columns=["label"]), hide_index=True)

# ---------------- Events ----------------
with tab_events:
    e1, e2 = st.columns(2)
    types = e1.multiselect("Event type", sorted(events["event_type"].unique()))
    ip_e = e2.text_input("Source IP contains", key="ip_events")
    ev = events
    if types:
        ev = ev[ev["event_type"].isin(types)]
    if ip_e:
        ev = ev[ev["src_ip"].str.contains(ip_e.strip(), regex=False)]
    st.dataframe(ev.head(1000), hide_index=True)
    st.caption(f"Showing {min(len(ev), 1000)} of {len(ev):,} matching events")

# ---------------- Evaluation ----------------
with tab_eval:
    m = res["metrics"]
    if m is None:
        st.info("This dataset has no 'label' column, so the system cannot be evaluated. "
                "Add a label column ('normal' or an attack name) to enable this tab.")
    else:
        st.write("Evaluation is done per **source IP** using the `label` column as ground truth.")
        k1, k2, k3 = st.columns(3)
        k1.metric("Precision", f"{m['precision']:.0%}")
        k2.metric("Recall", f"{m['recall']:.0%}")
        k3.metric("False positive rate", f"{m['fpr']:.0%}")
        st.table(pd.DataFrame(
            [[m["tp"], m["fn"]], [m["fp"], m["tn"]]],
            index=["Actually malicious", "Actually normal"],
            columns=["Alerted", "Not alerted"]))
        st.subheader("Detection per attack")
        st.dataframe(res["per_attack"], hide_index=True)
        st.caption("Try changing the thresholds in the sidebar and watch precision and recall move.")
