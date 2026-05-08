import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from collections import deque
from streamlit_autorefresh import st_autorefresh
from csv_monitor import check_csv_for_threats

# ------------------------------------------------
# PAGE CONFIG
# ------------------------------------------------
st.set_page_config(page_title="IoT Malware Detection", layout="wide")

# ------------------------------------------------
# CUSTOM CSS
# ------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700&family=Poppins:wght@300;400;500&display=swap');

[data-testid="stAppViewContainer"] {
    font-family: 'Poppins', sans-serif;
}

h1, h2, h3 {
    font-family: 'Montserrat', sans-serif !important;
}

.metric-box {
    background-color:#1e1e1e;
    padding:10px;
    border-radius:8px;
    margin-bottom:10px;
    text-align:center;
}

.metric-value {
    font-size:60px;
    font-weight:bold;
}

.metric-label {
    font-size:20px;
    color:#bbbbbb;
}

.red-bar {
    border-left:10px solid #E35335;
}

.blue-bar {
    border-left:10px solid #008080;
}

/* Top metrics */
div[data-testid="stMetric"] {
    background-color: #296B6B;
    padding: 10px;
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

# ------------------------------------------------
# TITLE
# ------------------------------------------------
st.title("IoT Malware Detection Security Dashboard")

# ------------------------------------------------
# AUTO REFRESH
# ------------------------------------------------
st_autorefresh(interval=1000)

# ------------------------------------------------
# LOAD DATA
# ------------------------------------------------
df = pd.read_csv(
    "detections.csv",
    names=["timestamp", "household", "device", "attack_type", "prediction", "confidence", "cpu_usage", "ram_usage"],
    on_bad_lines='skip'   # ← skips any malformed old rows
)

df = df[df["confidence"] != "confidence"]  # drop the accidental header row
df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
df["cpu_usage"]  = pd.to_numeric(df["cpu_usage"],  errors="coerce")
df["ram_usage"]  = pd.to_numeric(df["ram_usage"],  errors="coerce")

MAX_POINTS = 50

if "timeline_data" not in st.session_state:
    st.session_state.timeline_data = deque(maxlen=MAX_POINTS)

# ------------------------------------------------
# TRAFFIC CLASSIFICATION
# ------------------------------------------------
benign_count = (df["prediction"] == "benign").sum()
malware_count = (df["prediction"] == "malware").sum()
total = len(df)

security_counts = df["prediction"].value_counts().reset_index()
security_counts.columns = ["type", "count"]

security_colors = {
    "benign": "#008080",
    "malware": "#E35335"
}

security_fig = px.pie(
    security_counts,
    names="type",
    values="count",
    color="type",
    color_discrete_map=security_colors,
    hole=0.6
)

# REMOVE LABELS COMPLETELY
security_fig.update_traces(
    textinfo="none",
    texttemplate=None,
    hoverinfo="skip"
)

security_fig.update_layout(
    template="plotly_dark",
    showlegend=False,
    height=350,
    annotations=[dict(
        text=f"<b>{total}</b><br>Total Events",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=18)
    )]
)

# ------------------------------------------------
# TOP METRICS
# ------------------------------------------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Traffic Analyzed", total)
col2.metric("Malware Detected", malware_count)
col3.metric("Active Devices", df["device"].nunique())
col4.metric("Avg Confidence", round(df["confidence"].mean(), 2))

st.divider()

# ------------------------------------------------
# NETWORK OVERVIEW (MAIN SECTION)
# ------------------------------------------------
#t.subheader("Network Overview")

left_col, right_col = st.columns([2, 3])

# -------- LEFT: DONUT + METRICS --------
with left_col:

    st.markdown("### Traffic Classification")

    inner_col1, inner_col2 = st.columns([2,1])

    with inner_col1:
        st.plotly_chart(security_fig, width='stretch')

    with inner_col2:
        st.markdown(f"""
        <div class="metric-box red-bar">
            <div class="metric-value">{malware_count}</div>
            <div class="metric-label">Malicious</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="metric-box blue-bar">
            <div class="metric-value">{benign_count}</div>
            <div class="metric-label">Benign</div>
        </div>
        """, unsafe_allow_html=True)

# -------- RIGHT: HOUSEHOLDS --------
with right_col:

    st.markdown("### Infection Status")

    household_infection = (
        df.groupby("household")["prediction"]
        .apply(lambda x: (x == "malware").sum() / len(x) * 100)
    )

    households = list(household_infection.items())

    def make_gauge(household, infection):
        color = "green" if infection <= 20 else \
                "yellow" if infection < 50 else \
                "orange" if infection < 80 else "red"

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=round(infection, 1),
            title={'text': household},
            gauge={'axis': {'range': [0, 100]}, 'bar': {'color': color}}
        ))

        fig.update_layout(
            height=200,
            margin=dict(t=40, b=10, l=20, r=20)  # ← kills the extra whitespace
        )
        return fig

    # Top row (3 gauges)
    cols_top = st.columns(3)
    for i, (household, infection) in enumerate(households[:3]):
        cols_top[i].plotly_chart(make_gauge(household, infection), width='stretch')

    # Bottom row (2 gauges, centered)
    _, col_a, col_b, _ = st.columns([0.5, 1, 1, 0.5])

    for col, (household, infection) in zip([col_a, col_b], households[3:]):
        col.plotly_chart(make_gauge(household, infection), width='stretch')

st.divider()

# ------------------------------------------------
# TASK MANAGER STYLE DETECTION TIMELINE
# ------------------------------------------------
st.subheader("Detection Timeline")

MAX_POINTS = 50  # how many time steps to show (scrolling window)

# Initialize session state buffers per device
devices_to_monitor = ["RasPi", "VM1"]  # 🔧 adjust to match your device names in the CSV

# Initialize deques AND a row counter
for device in devices_to_monitor:
    if f"{device}_cpu" not in st.session_state:
        st.session_state[f"{device}_cpu"] = deque([0] * MAX_POINTS, maxlen=MAX_POINTS)
    if f"{device}_ram" not in st.session_state:
        st.session_state[f"{device}_ram"] = deque([0] * MAX_POINTS, maxlen=MAX_POINTS)

if "last_row_read" not in st.session_state:
    st.session_state.last_row_read = 0

# Read only NEW rows since last refresh
current_total = len(df)
new_rows = df.iloc[st.session_state.last_row_read:]
st.session_state.last_row_read = current_total  # update the pointer

# Append only new data points into each device's deque
for device in devices_to_monitor:
    device_new = new_rows[new_rows["device"] == device].dropna(subset=["cpu_usage", "ram_usage"])
    for _, row in device_new.iterrows():
        st.session_state[f"{device}_cpu"].append(row["cpu_usage"])
        st.session_state[f"{device}_ram"].append(row["ram_usage"])

def make_taskmanager_chart(data, label, color):
    """Renders a scrolling filled line chart like Windows Task Manager."""
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        y=list(data),
        mode="lines",
        fill="tozeroy",
        line=dict(color=color, width=2),
        fillcolor=color.replace(")", ", 0.2)").replace("rgb", "rgba"),
    ))

    fig.update_layout(
        height=120,
        margin=dict(t=20, b=20, l=10, r=10),
        template="plotly_dark",
        xaxis=dict(visible=False),
        yaxis=dict(range=[0, 100], showgrid=True, gridcolor="#333", tickfont=dict(size=9)),
        plot_bgcolor="#111111",
        paper_bgcolor="#111111",
        annotations=[dict(
            text=label,
            x=0, y=1.15,
            xref="paper", yref="paper",
            showarrow=False,
            font=dict(size=11, color="#aaaaaa")
        )]
    )
    return fig

# Render one row per device
for device in devices_to_monitor:
    is_expanded = (device == "RasPi")
    with st.expander(f"📟 {device}", expanded=is_expanded):
        col_cpu, col_ram, col_stats = st.columns([2, 2, 1])

        cpu_data = st.session_state[f"{device}_cpu"]
        ram_data = st.session_state[f"{device}_ram"]
        current_cpu = list(cpu_data)[-1]
        current_ram = list(ram_data)[-1]

        with col_cpu:
            st.plotly_chart(
                make_taskmanager_chart(cpu_data, "CPU", "rgb(0, 200, 150)"),
                width='stretch',
                key=f"{device}_cpu_chart"
            )

        with col_ram:
            st.plotly_chart(
                make_taskmanager_chart(ram_data, "RAM", "rgb(100, 149, 237)"),
                width='stretch',
                key=f"{device}_ram_chart"
            )

        with col_stats:
            device_df = df[df["device"] == device]
            malware_pct = (
                (device_df["prediction"] == "malware").sum() / len(device_df) * 100
                if not device_df.empty else 0
            )
            status = "🔴 Infected" if malware_pct > 0 else "🟢 Safe"

            st.markdown(f"""
            <div class="metric-box" style="margin-top:10px">
                <div style="font-size:13px; color:#aaa">CPU</div>
                <div style="font-size:22px; font-weight:bold; color:#00c896">{current_cpu:.1f}%</div>
                <div style="font-size:13px; color:#aaa; margin-top:6px">RAM</div>
                <div style="font-size:22px; font-weight:bold; color:#6495ed">{current_ram:.1f}%</div>
                <div style="font-size:13px; color:#aaa; margin-top:6px">Status</div>
                <div style="font-size:15px">{status}</div>
                <div style="font-size:13px; color:#aaa; margin-top:6px">Malware Rate</div>
                <div style="font-size:18px; font-weight:bold; color:#e35335">{malware_pct:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<hr style='border:1px solid #2a2a2a; margin:4px 0 12px 0'>", unsafe_allow_html=True)
    

# ------------------------------------------------
# TIMELINE
# ------------------------------------------------
# st.subheader("Detection Timeline")
# timeline = df.groupby("timestamp").size()
# st.line_chart(timeline)

# st.divider()

# ------------------------------------------------
# DEVICE STATUS + LIVE ALERTS (combined row)
# ------------------------------------------------
col_devices, col_alerts = st.columns([2, 2])

with col_devices:
    st.subheader("IoT Device Status")

    device_status = df.groupby("device")["prediction"].apply(
        lambda x: "🔴 Infected" if "malware" in x.values else "🟢 Safe"
    )

    device_table = pd.DataFrame({
        "Device": device_status.index,
        "Status": device_status.values
    })

    st.dataframe(device_table, use_container_width=True, hide_index=True)

# Initialize alert log 
if "alert_log" not in st.session_state:
    st.session_state.alert_log = []

# Append only NEW alerts since last read 
new_alerts = df.iloc[st.session_state.last_row_read - len(df):]  
new_malware = new_alerts[new_alerts["prediction"] == "malware"]

for _, row in new_malware.iterrows():
    st.session_state.alert_log.append({
        "timestamp": row["timestamp"],
        "device": row["device"],
        "attack_type": row["attack_type"],
        "confidence": row["confidence"]
    })

with col_alerts:
    alert_header, alert_btn = st.columns([3, 1])
    
    with alert_header:
        st.subheader("🚨 Live Malware Alerts")
    
    with alert_btn:
        st.write("")  # vertical alignment nudge
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.alert_log = []
            st.session_state.last_row_read = len(df)
            st.rerun()

    if not st.session_state.alert_log:
        st.success("No malware detected.")
    else:
        st.caption(f"Total alerts logged: {len(st.session_state.alert_log)}")
        with st.container(height=370):
            for alert in reversed(st.session_state.alert_log):
                st.error(
                    f"**{alert['timestamp']}** — `{alert['device']}` detected "
                    f"**{alert['attack_type']}** (confidence: {alert['confidence']})"
                )

# Email alert monitor
pending = len(st.session_state.get("threat_batch", []))
if pending > 0:
    st.warning(f" {pending} threats queued — email sends in next batch window.")

# ── TEMPORARY TEST BUTTON ─────────────────────────────────────
if st.button("Send Test Email"):
    from alert import email_alert
    try:
        email_alert(
            subject="Test Email from IoT Dashboard",
            body="This is a test. If you receive this, email sending works.",
            to=st.secrets["OWNER_EMAIL"]
        )
        st.success("Test email sent!")
    except Exception as e:
        st.error(f"Email failed: {e}")
# ─────────────────────────────────────────────────────────────

check_csv_for_threats(df)
