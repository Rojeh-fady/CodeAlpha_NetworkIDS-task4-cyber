"""Streamlit dashboard:  streamlit run dashboard.py"""
import sqlite3
import time

import pandas as pd
import streamlit as st

st.set_page_config(page_title="NIDS Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection - Dashboard")

db_path = st.sidebar.text_input("Database file", "demo.db")
auto = st.sidebar.checkbox("Auto-refresh (5s)", value=True)
bucket = st.sidebar.selectbox("Timeline resolution", ["10s", "1min", "5min"], index=1)

try:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY ts DESC", conn)
    conn.close()
except Exception as e:
    st.warning(f"No data yet ({e}). Run main.py first.")
    st.stop()

if df.empty:
    st.info("No alerts yet - the network looks quiet.")
else:
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    sev = st.sidebar.multiselect("Severity", ["critical", "high", "medium", "low"],
                                 default=["critical", "high", "medium", "low"])
    df = df[df["severity"].isin(sev)]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", len(df))
    c2.metric("Critical / High", int(df["severity"].isin(["critical", "high"]).sum()))
    c3.metric("Unique attackers", df["src_ip"].nunique())
    c4.metric("Blocked IPs", df.loc[df["action"].str.startswith(("BLOCKED", "DRY")), "src_ip"].nunique())

    l, r = st.columns(2)
    l.subheader("Alerts by type")
    l.bar_chart(df["rule"].value_counts())
    r.subheader("Top attacking IPs")
    r.bar_chart(df["src_ip"].value_counts().head(10))

    l2, r2 = st.columns(2)
    l2.subheader("Alerts over time")
    l2.line_chart(df.groupby(pd.Grouper(key="time", freq=bucket)).size())
    r2.subheader("Severity breakdown")
    r2.bar_chart(df["severity"].value_counts())

    st.subheader("Latest alerts")
    st.dataframe(df[["time", "severity", "rule", "src_ip", "dst_ip", "dst_port",
                     "proto", "message", "action"]].head(200), use_container_width=True)
    st.download_button("Download CSV", df.to_csv(index=False), "alerts.csv", "text/csv")

if auto:
    time.sleep(5)
    st.rerun()
