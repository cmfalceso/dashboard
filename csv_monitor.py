import streamlit as st
from datetime import datetime, timedelta
from collections import Counter
from alert import classify_severity, send_summary_email

CONFIDENCE_THRESHOLD = 0.75
WINDOW_MINUTES       = 1
VOLUME_THRESHOLD     = 5
DEVICE_THRESHOLD     = 5

def check_csv_for_threats(df):

    if "alerted_indices" not in st.session_state:
        st.session_state.alerted_indices = set()
    if "threat_batch"    not in st.session_state:
        st.session_state.threat_batch = []
    if "last_sms_time"   not in st.session_state:
        st.session_state.last_sms_time = datetime.now()

    for index, row in df.iterrows():
        if index in st.session_state.alerted_indices:
            continue

        prediction = str(row["prediction"]).strip().lower()
        try:
            confidence = float(str(row["confidence"]).strip())
        except (ValueError, TypeError):
            continue

        if prediction not in ("normal", "benign") and confidence >= CONFIDENCE_THRESHOLD:
            try:
                cpu = float(row["cpu_usage"])
            except (ValueError, TypeError):
                cpu = None
            try:
                ram = float(row["ram_usage"])
            except (ValueError, TypeError):
                ram = None

            st.session_state.threat_batch.append({
                "device"    : row["device"],
                "household" : row["household"],
                "confidence": confidence,
                "severity"  : classify_severity(confidence),
                "cpu"       : cpu,
                "ram"       : ram,
            })
            st.session_state.alerted_indices.add(index)

    batch = st.session_state.threat_batch

    if len(batch) >= VOLUME_THRESHOLD:
        st.write("DEBUG: Triggering urgent email — volume spike")
        send_summary_email(batch, urgent=True, reason="High volume of threats detected")
        st.session_state.threat_batch  = []
        st.session_state.last_sms_time = datetime.now()
        return

    device_counts = Counter(t["device"] for t in batch)
    for device, count in device_counts.items():
        if count >= DEVICE_THRESHOLD:
            st.write(f"DEBUG: Triggering urgent email — {device} repeatedly flagged")
            send_summary_email(batch, urgent=True, reason=f"{device} repeatedly flagged")
            st.session_state.threat_batch  = []
            st.session_state.last_sms_time = datetime.now()
            return

    window_elapsed = (
        datetime.now() - st.session_state.last_sms_time
    ) >= timedelta(minutes=WINDOW_MINUTES)

    if window_elapsed and len(batch) > 0:
        st.write("DEBUG: Triggering scheduled email")
        send_summary_email(batch, urgent=False, reason="Scheduled summary")
        st.session_state.threat_batch  = []
        st.session_state.last_sms_time = datetime.now()
    elif window_elapsed and len(batch) == 0:
        st.write("DEBUG: Window elapsed but batch is empty — no email sent")
    elif not window_elapsed:
        st.write("DEBUG: Window not elapsed yet — waiting")
