import streamlit as st
import math
from datetime import datetime, timedelta
from collections import Counter
from alert import classify_severity, send_summary_email

CONFIDENCE_THRESHOLD = 0.75
WINDOW_MINUTES       = 5
VOLUME_THRESHOLD     = 20
DEVICE_THRESHOLD     = 5

def check_csv_for_threats(df):

    if "threat_batch"    not in st.session_state:
        st.session_state.threat_batch = []
    if "last_sms_time"   not in st.session_state:
        st.session_state.last_sms_time = datetime.now()
    if "last_processed_len" not in st.session_state:
        st.session_state.last_processed_len = len(df)  # skip existing rows on first load
        return  # ← don't process anything on first load

    # ── Only look at NEW rows since last run ─────────────────
    new_rows = df.iloc[st.session_state.last_processed_len:]

    for index, row in new_rows.iterrows():
        prediction = str(row["prediction"]).strip().lower()
        try:
            confidence = float(str(row["confidence"]).strip())
        except (ValueError, TypeError):
            continue

        if prediction not in ("normal", "benign") and confidence >= CONFIDENCE_THRESHOLD:
            try:
                cpu = float(row["cpu_usage"])
                if math.isnan(cpu):
                    cpu = None
            except (ValueError, TypeError):
                cpu = None
            
            try:
                ram = float(row["ram_usage"])
                if math.isnan(ram):
                    ram = None
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

    # ── Update pointer ────────────────────────────────────────
    st.session_state.last_processed_len = len(df)

    batch = st.session_state.threat_batch

    if len(batch) >= VOLUME_THRESHOLD:
        send_summary_email(batch, urgent=True, reason="High volume of threats detected")
        st.session_state.threat_batch  = []
        st.session_state.last_sms_time = datetime.now()
        return

    device_counts = Counter(t["device"] for t in batch)
    for device, count in device_counts.items():
        if count >= DEVICE_THRESHOLD:
            send_summary_email(batch, urgent=True, reason=f"{device} repeatedly flagged")
            st.session_state.threat_batch  = []
            st.session_state.last_sms_time = datetime.now()
            return

    window_elapsed = (
        datetime.now() - st.session_state.last_sms_time
    ) >= timedelta(minutes=WINDOW_MINUTES)

    if window_elapsed and len(batch) > 0:
        send_summary_email(batch, urgent=False, reason="Scheduled summary")
        st.session_state.threat_batch  = []
        st.session_state.last_sms_time = datetime.now()
