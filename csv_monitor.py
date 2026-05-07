import streamlit as st
from datetime import datetime, timedelta
from collections import Counter
from email_alert import classify_severity, send_summary_email

CONFIDENCE_THRESHOLD = 0.75
WINDOW_MINUTES       = 5
VOLUME_THRESHOLD     = 20
DEVICE_THRESHOLD     = 5

def check_csv_for_threats(df):

    # ── Initialize session state ──────────────────────────────
    if "alerted_indices" not in st.session_state:
        st.session_state.alerted_indices = set()
    if "threat_batch"    not in st.session_state:
        st.session_state.threat_batch = []
    if "last_sms_time"   not in st.session_state:
        st.session_state.last_sms_time = datetime.now()

    # ── Collect new threats ───────────────────────────────────
    for index, row in df.iterrows():
        if index in st.session_state.alerted_indices:
            continue

        prediction = str(row["prediction"]).strip().lower()
        confidence = float(row["confidence"])

        if prediction not in ("normal", "benign") and confidence >= CONFIDENCE_THRESHOLD:
            st.session_state.threat_batch.append({
                "device"    : row["device"],
                "household" : row["household"],
                "confidence": confidence,
                "severity"  : classify_severity(confidence),
                "cpu"       : float(row["cpu_usage"]),
                "ram"       : float(row["ram_usage"]),
            })
            st.session_state.alerted_indices.add(index)

    batch = st.session_state.threat_batch

    # ── Escalation Rule 1: Too many threats at once ───────────
    if len(batch) >= VOLUME_THRESHOLD:
        send_summary_email(batch, urgent=True, reason="High volume of threats detected")
        st.session_state.threat_batch  = []send
        st.session_state.last_sms_time = datetime.now()
        return

    # ── Escalation Rule 2: One device hit repeatedly ─────────
    device_counts = Counter(t["device"] for t in batch)
    for device, count in device_counts.items():
        if count >= DEVICE_THRESHOLD:
            send_summary_email(batch, urgent=True, reason=f"{device} repeatedly flagged")
            st.session_state.threat_batch  = []
            st.session_state.last_sms_time = datetime.now()
            return

    # ── Regular 5-min batch ───────────────────────────────────
    window_elapsed = (
        datetime.now() - st.session_state.last_sms_time
    ) >= timedelta(minutes=WINDOW_MINUTES)

    if window_elapsed and len(batch) > 0:
        send_summary_email(batch, urgent=False, reason="Scheduled summary")
        st.session_state.threat_batch  = []
        st.session_state.last_sms_time = datetime.now()