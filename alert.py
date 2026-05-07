import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta
from collections import Counter
import streamlit as st

def email_alert(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['To'] = to
    msg['From'] = st.secrets["GMAIL_ADDRESS"]

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(st.secrets["GMAIL_ADDRESS"], st.secrets["GMAIL_APP_PSWD"])
    server.send_message(msg)
    server.quit()

def classify_severity(confidence: float) -> str:
    if confidence >= 0.95:
        return "Critical"
    elif confidence >= 0.85:
        return "High"
    elif confidence >= 0.75:
        return "Medium"
    else:
        return "Low"

def send_summary_email(batch: list, urgent: bool = False, reason: str = ""):
    if not batch:
        return

    total         = len(batch)
    severities    = Counter(t["severity"] for t in batch)
    device_counts = Counter(t["device"] for t in batch)
    top_devices   = device_counts.most_common(3)
    top_household = Counter(t["household"] for t in batch).most_common(1)[0][0]
    cpu_values = [t["cpu"] for t in batch if t["cpu"] is not None]
    ram_values = [t["ram"] for t in batch if t["ram"] is not None]
    avg_cpu    = sum(cpu_values) / len(cpu_values) if cpu_values else None
    avg_ram    = sum(ram_values) / len(ram_values) if ram_values else None
    resource_line = (
        f"Avg CPU: {avg_cpu:.1f}%\nAvg RAM: {avg_ram:.1f}%\n──────────────────\n"
        if avg_cpu is not None and avg_ram is not None
        else ""
    )
    PH_TZ     = timezone(timedelta(hours=8))
    timestamp = datetime.now(PH_TZ).strftime("%H:%M %b %d")
    header        = "URGENT THREAT ALERT" if urgent else "THREAT SUMMARY"
    device_lines  = "\n".join(f"  • {d} ({c}x)" for d, c in top_devices)

    body = f"""
{header} — {timestamp}
Reason: {reason}
Household: {top_household}
──────────────────
Total: {total} threats
Critical: {severities.get('Critical', 0)}
High: {severities.get('High', 0)}
Medium: {severities.get('Medium', 0)}
Low: {severities.get('Low', 0)}
──────────────────
Top devices:
{device_lines}
──────────────────
{resource_line} Check your dashboard immediately.
    """

    try:
        email_alert(
            subject=f"⚠️ IoT Malware Detector — {header} ({total} threats)",
            body=body,
            to=st.secrets["OWNER_EMAIL"]
        )
        print(f"[EMAIL SENT] {reason} — {total} threats")
    except Exception as e:
        print(f"[EMAIL FAILED] {e}")
        st.error(f"Email failed: {e}")
