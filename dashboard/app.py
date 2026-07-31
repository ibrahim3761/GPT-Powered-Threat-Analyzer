"""
==============================================================================
 GPT-Powered Threat Analyzer — Streamlit Dashboard
==============================================================================
 University Capstone Project — Tier S

 Premium SOC (Security Operations Center) Dashboard with:
   - Real-time system status indicators
   - Sniffing control panel
   - Live alert feed with color-coded threat levels
   - Interactive charts (Plotly): threat distribution, timeline, protocol breakdown
   - Alert detail expansion with full LLM explanation
   - Dark theme with cyan/teal accent colors

 Run with: streamlit run dashboard/app.py
==============================================================================
"""

import os
import time
import requests
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ── Page Configuration ───────────────────────────────────────────────────────

st.set_page_config(
    page_title="GPT-Powered Threat Analyzer — Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Configuration ────────────────────────────────────────────────────────────

API_BASE = os.getenv("API_BASE", "http://localhost:8000")
REFRESH_INTERVAL = 3  # seconds


# ── Custom CSS — Premium Dark SOC Theme ──────────────────────────────────────

st.markdown("""
<style>
    /* ── Global Dark Theme ──────────────────────────────────────── */
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1525 50%, #0a1628 100%);
    }

    /* ── Header Styling ─────────────────────────────────────────── */
    .main-header {
        background: linear-gradient(90deg, rgba(0,212,255,0.1) 0%, rgba(0,40,80,0.3) 50%, rgba(0,212,255,0.1) 100%);
        border: 1px solid rgba(0,212,255,0.2);
        border-radius: 16px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        backdrop-filter: blur(10px);
        text-align: center;
    }
    .main-header h1 {
        background: linear-gradient(90deg, #00d4ff, #00ff88, #00d4ff);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.2rem;
        font-weight: 800;
        margin: 0;
        animation: gradientShift 3s ease infinite;
    }
    @keyframes gradientShift {
        0% { background-position: 0% center; }
        50% { background-position: 100% center; }
        100% { background-position: 0% center; }
    }
    .main-header p {
        color: #7a8ba5;
        margin: 0.3rem 0 0;
        font-size: 0.95rem;
    }

    /* ── Status Indicators ──────────────────────────────────────── */
    .status-bar {
        display: flex;
        gap: 1.2rem;
        justify-content: center;
        flex-wrap: wrap;
        margin: 1rem 0;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.4rem 1rem;
        border-radius: 999px;
        font-size: 0.82rem;
        font-weight: 600;
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(255,255,255,0.03);
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        animation: pulse 2s ease-in-out infinite;
    }
    .status-dot.active { background: #00ff88; box-shadow: 0 0 8px #00ff88; }
    .status-dot.inactive { background: #ff4757; box-shadow: 0 0 8px #ff4757; }
    .status-dot.warning { background: #ffa502; box-shadow: 0 0 8px #ffa502; }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
    }

    /* ── Metric Cards ───────────────────────────────────────────── */
    .metric-card {
        background: linear-gradient(145deg, rgba(13,21,37,0.9), rgba(10,14,26,0.9));
        border: 1px solid rgba(0,212,255,0.15);
        border-radius: 14px;
        padding: 1.4rem;
        text-align: center;
        transition: all 0.3s ease;
    }
    .metric-card:hover {
        border-color: rgba(0,212,255,0.4);
        box-shadow: 0 4px 20px rgba(0,212,255,0.1);
        transform: translateY(-2px);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        margin: 0.3rem 0;
        line-height: 1;
    }
    .metric-label {
        color: #7a8ba5;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }
    .metric-value.cyan { color: #00d4ff; }
    .metric-value.green { color: #00ff88; }
    .metric-value.orange { color: #ffa502; }
    .metric-value.red { color: #ff4757; }
    .metric-value.purple { color: #a855f7; }

    /* ── Alert Table ────────────────────────────────────────────── */
    .alert-row {
        background: rgba(13,21,37,0.8);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 0.8rem 1.2rem;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
        transition: all 0.2s ease;
    }
    .alert-row:hover {
        border-color: rgba(0,212,255,0.3);
        background: rgba(13,21,37,0.95);
    }
    .threat-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        min-width: 70px;
        text-align: center;
    }
    .threat-critical {
        background: rgba(255,71,87,0.2);
        color: #ff4757;
        border: 1px solid rgba(255,71,87,0.4);
    }
    .threat-high {
        background: rgba(255,165,2,0.2);
        color: #ffa502;
        border: 1px solid rgba(255,165,2,0.4);
    }
    .threat-medium {
        background: rgba(168,85,247,0.2);
        color: #a855f7;
        border: 1px solid rgba(168,85,247,0.4);
    }
    .threat-low {
        background: rgba(0,212,255,0.15);
        color: #00d4ff;
        border: 1px solid rgba(0,212,255,0.3);
    }

    /* ── Section Headers ────────────────────────────────────────── */
    .section-header {
        color: #e2e8f0;
        font-size: 1.1rem;
        font-weight: 700;
        margin: 1.5rem 0 0.8rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid rgba(0,212,255,0.15);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    /* ── Streamlit Component Overrides ───────────────────────────── */
    .stButton > button {
        background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
        color: #0a0e1a;
        border: none;
        border-radius: 10px;
        padding: 0.6rem 2rem;
        font-weight: 700;
        font-size: 0.9rem;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
        box-shadow: 0 4px 15px rgba(0,255,136,0.3);
        transform: translateY(-1px);
    }
    .stSelectbox label, .stMultiSelect label {
        color: #7a8ba5 !important;
    }
    div[data-testid="stExpander"] {
        background: rgba(13,21,37,0.6);
        border: 1px solid rgba(0,212,255,0.1);
        border-radius: 10px;
    }
    .stSidebar {
        background: linear-gradient(180deg, #0a0e1a 0%, #0d1525 100%);
    }
    .stSidebar .stMarkdown h2 {
        color: #00d4ff;
    }

    /* ── Plotly Chart Container ──────────────────────────────────── */
    .chart-container {
        background: rgba(13,21,37,0.5);
        border: 1px solid rgba(0,212,255,0.1);
        border-radius: 14px;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# ── Helper Functions ─────────────────────────────────────────────────────────

def api_call(endpoint: str, method: str = "GET", json_data: dict = None, timeout: int = 5):
    """Make an API call to the FastAPI backend with error handling."""
    url = f"{API_BASE}{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(url, timeout=timeout)
        elif method == "POST":
            resp = requests.post(url, json=json_data or {}, timeout=timeout)
        else:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"API connection failed: {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"API timeout: {url}")
        return None
    except Exception as e:
        print(f"API request error for {url}: {e}")
        return None


def format_timestamp(ts):
    """Convert unix timestamp to readable format."""
    if ts:
        try:
            return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        except Exception:
            return "—"
    return "—"


def get_threat_badge_html(level: str) -> str:
    """Generate HTML for a color-coded threat level badge."""
    level = (level or "unknown").lower()
    css_class = f"threat-{level}" if level in ("critical", "high", "medium", "low") else "threat-low"
    return f'<span class="threat-badge {css_class}">{level.upper()}</span>'


# ── Main Dashboard ───────────────────────────────────────────────────────────

def main():
    """Main dashboard rendering function."""

    # ── Header ───────────────────────────────────────────────────────
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ GPT-Powered Threat Analyzer</h1>
        <p>Real-Time AI Threat Analysis • Tier S Capstone Project</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Fetch System Status ──────────────────────────────────────────
    status = api_call("/status")
    api_online = status is not None

    # ── Status Bar ───────────────────────────────────────────────────
    if api_online:
        sniffer_active = status.get("sniffer", {}).get("is_running", False)
        llm_active = status.get("llm_analyzer", {}).get("is_running", False)
        rag_active = status.get("rag_engine", {}).get("initialized", False)
        db_connected = status.get("database", {}).get("connected", False)

        st.markdown(f"""
        <div class="status-bar">
            <div class="status-pill">
                <span class="status-dot {'active' if api_online else 'inactive'}"></span>
                <span style="color: #e2e8f0;">API Server</span>
            </div>
            <div class="status-pill">
                <span class="status-dot {'active' if sniffer_active else 'inactive'}"></span>
                <span style="color: #e2e8f0;">Sniffer {'Active' if sniffer_active else 'Stopped'}</span>
            </div>
            <div class="status-pill">
                <span class="status-dot {'active' if llm_active else 'inactive'}"></span>
                <span style="color: #e2e8f0;">Groq AI</span>
            </div>
            <div class="status-pill">
                <span class="status-dot {'active' if rag_active else 'warning'}"></span>
                <span style="color: #e2e8f0;">RAG Engine</span>
            </div>
            <div class="status-pill">
                <span class="status-dot {'active' if db_connected else 'inactive'}"></span>
                <span style="color: #e2e8f0;">Database</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-bar">
            <div class="status-pill">
                <span class="status-dot inactive"></span>
                <span style="color: #ff4757; font-weight: 700;">API Server Offline — Start with: python main.py</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.error("⚠️ Cannot connect to the API server. Run `python main.py` from the project directory first.")
        st.stop()

    # ── Sidebar: Controls ────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## ⚙️ Control Panel")
        st.divider()

        # Interface selector
        interfaces_data = api_call("/interfaces")
        available_interfaces = interfaces_data.get("interfaces", ["Wi-Fi"]) if interfaces_data else ["Wi-Fi"]
        current_interface = interfaces_data.get("current", "Wi-Fi") if interfaces_data else "Wi-Fi"

        selected_interface = st.selectbox(
            "Network Interface",
            options=available_interfaces,
            index=available_interfaces.index(current_interface) if current_interface in available_interfaces else 0
        )

        st.caption(f"API_BASE: {API_BASE}")

        # Start/Stop toggle
        st.divider()
        if sniffer_active:
            if st.button("⏹ Stop Sniffing", use_container_width=True, type="primary"):
                result = api_call("/toggle-sniffing", method="POST", json_data={"interface": selected_interface})
                if result:
                    st.success(f"Sniffer stopped")
                    time.sleep(1)
                    st.rerun()
        else:
            if st.button("▶ Start Sniffing", use_container_width=True, type="primary"):
                result = api_call("/toggle-sniffing", method="POST", json_data={"interface": selected_interface})
                if result:
                    st.success(f"Sniffer started on {selected_interface}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to start sniffer. Run as Administrator.")

        # Queue status
        st.divider()
        st.markdown("## 📊 Queue Status")
        queues = status.get("queues", {})
        pq_size = queues.get("packet_queue_size", 0)
        pq_max = queues.get("packet_queue_max", 1)
        lq_size = queues.get("llm_queue_size", 0)
        lq_max = queues.get("llm_queue_max", 1)

        st.progress(min(pq_size / max(pq_max, 1), 1.0), text=f"Packet Queue: {pq_size}/{pq_max}")
        st.progress(min(lq_size / max(lq_max, 1), 1.0), text=f"LLM Queue: {lq_size}/{lq_max}")

        # Auto-refresh toggle
        st.divider()
        auto_refresh = st.toggle("⟳ Auto-Refresh", value=True)
        refresh_rate = st.slider("Refresh Rate (sec)", 2, 15, REFRESH_INTERVAL)

        # Manual analysis section
        st.divider()
        st.markdown("## 🧪 Manual Analysis")
        with st.expander("Submit Test Packet"):
            test_src = st.text_input("Source IP", "192.168.1.100")
            test_dst = st.text_input("Dest IP", "10.0.0.1")
            test_dport = st.number_input("Dest Port", value=4444, min_value=1, max_value=65535)
            test_proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
            test_flags = st.text_input("TCP Flags", "S")

            if st.button("🔍 Analyze", use_container_width=True):
                with st.spinner("Analyzing with GPT..."):
                    result = api_call("/analyze-sample", method="POST", json_data={
                        "src_ip": test_src,
                        "dst_ip": test_dst,
                        "dst_port": test_dport,
                        "protocol": test_proto,
                        "tcp_flags": test_flags,
                        "packet_size": 64,
                        "flags": ["MANUAL_SUBMISSION"]
                    }, timeout=45)

                    if result and result.get("success"):
                        analysis = result["analysis"]
                        st.success(f"**{analysis['threat_level']}** — {analysis['attack_vector']}")
                        st.info(analysis.get("human_readable_explanation", ""))
                    elif result:
                        st.error(result.get("error", "Analysis failed"))
                    else:
                        st.error("API request failed")

    # ── Metrics Row ──────────────────────────────────────────────────
    sniffer_stats = status.get("sniffer", {})
    triage_stats = status.get("triage", {})
    llm_stats = status.get("llm_analyzer", {})

    stats_data = api_call("/statistics")
    counts = stats_data.get("counts", {}) if stats_data else {}

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Packets Captured</div>
            <div class="metric-value cyan">{(sniffer_stats.get('packets_captured') or 0):,}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Flagged Packets</div>
            <div class="metric-value orange">{(triage_stats.get('packets_flagged') or 0):,}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">AI Analyzed</div>
            <div class="metric-value green">{(llm_stats.get('analyzed_count') or 0):,}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Critical Alerts</div>
            <div class="metric-value red">{(counts.get('critical') or 0):,}</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">High Alerts</div>
            <div class="metric-value purple">{(counts.get('high') or 0):,}</div>
        </div>
        """, unsafe_allow_html=True)

    # ── Charts Row ───────────────────────────────────────────────────
    st.markdown('<div class="section-header">📊 Threat Analytics</div>', unsafe_allow_html=True)

    chart_col1, chart_col2, chart_col3 = st.columns([1, 1, 1])

    with chart_col1:
        # Threat Level Distribution — Donut Chart
        threat_dist = stats_data.get("threat_distribution", []) if stats_data else []
        if threat_dist:
            labels = [d["threat_level"] for d in threat_dist]
            values = [d["count"] for d in threat_dist]
            colors = {
                "Critical": "#ff4757",
                "High": "#ffa502",
                "Medium": "#a855f7",
                "Low": "#00d4ff"
            }
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.55,
                marker_colors=[colors.get(l, "#7a8ba5") for l in labels],
                textfont=dict(size=12, color="white"),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>"
            )])
            fig.update_layout(
                title=dict(text="Threat Distribution", font=dict(color="#e2e8f0", size=14)),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#7a8ba5"),
                legend=dict(font=dict(color="#e2e8f0")),
                margin=dict(l=20, r=20, t=40, b=20),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data yet. Start sniffing to collect alerts.")

    with chart_col2:
        # Protocol Breakdown — Bar Chart
        proto_data = stats_data.get("protocol_breakdown", []) if stats_data else []
        if proto_data:
            protocols = [d["protocol"] for d in proto_data]
            proto_counts = [d["count"] for d in proto_data]
            fig = go.Figure(data=[go.Bar(
                x=protocols,
                y=proto_counts,
                marker_color=["#00d4ff", "#00ff88", "#ffa502", "#a855f7"][:len(protocols)],
                text=proto_counts,
                textposition="auto",
                textfont=dict(color="white", size=12),
            )])
            fig.update_layout(
                title=dict(text="Protocol Breakdown", font=dict(color="#e2e8f0", size=14)),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#7a8ba5"),
                xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                margin=dict(l=20, r=20, t=40, b=20),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data yet.")

    with chart_col3:
        # Top Attack Vectors — Horizontal Bar
        attack_data = stats_data.get("top_attack_vectors", []) if stats_data else []
        if attack_data:
            vectors = [d["attack_vector"][:25] for d in attack_data][::-1]
            vector_counts = [d["count"] for d in attack_data][::-1]
            fig = go.Figure(data=[go.Bar(
                y=vectors,
                x=vector_counts,
                orientation="h",
                marker_color="#a855f7",
                text=vector_counts,
                textposition="auto",
                textfont=dict(color="white", size=11),
            )])
            fig.update_layout(
                title=dict(text="Top Attack Vectors", font=dict(color="#e2e8f0", size=14)),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#7a8ba5"),
                xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                margin=dict(l=20, r=20, t=40, b=20),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack vector data yet.")

    # ── Top Source IPs ───────────────────────────────────────────────
    top_sources = stats_data.get("top_sources", []) if stats_data else []
    if top_sources:
        st.markdown('<div class="section-header">🎯 Top Source IPs (by alert count)</div>', unsafe_allow_html=True)
        source_cols = st.columns(min(len(top_sources), 5))
        for i, src in enumerate(top_sources[:5]):
            with source_cols[i]:
                st.markdown(f"""
                <div class="metric-card" style="padding: 1rem;">
                    <div class="metric-label" style="font-size: 0.75rem;">Source IP</div>
                    <div style="color: #ffa502; font-size: 0.95rem; font-weight: 700; margin: 0.3rem 0;word-break: break-all;">
                        {src['src_ip']}
                    </div>
                    <div style="color: #00d4ff; font-size: 1.8rem; font-weight: 800;">{src['count']}</div>
                    <div class="metric-label" style="font-size: 0.7rem;">alerts</div>
                </div>
                """, unsafe_allow_html=True)

    # ── Alert Feed ───────────────────────────────────────────────────
    st.markdown('<div class="section-header">🚨 Recent Security Alerts</div>', unsafe_allow_html=True)

    # Fetch alerts
    alerts_data = api_call("/alerts?limit=50")
    alerts = alerts_data.get("alerts", []) if alerts_data else []

    if alerts:
        # Filter controls
        filter_col1, filter_col2, filter_col3 = st.columns([1, 1, 2])
        with filter_col1:
            level_filter = st.selectbox(
                "Threat Level",
                ["All", "Critical", "High", "Medium", "Low"],
                key="level_filter"
            )
        with filter_col2:
            status_filter = st.selectbox(
                "Status",
                ["All", "analyzed", "pending", "error"],
                key="status_filter"
            )

        # Apply filters
        filtered = alerts
        if level_filter != "All":
            filtered = [a for a in filtered if a.get("threat_level") == level_filter]
        if status_filter != "All":
            filtered = [a for a in filtered if a.get("status") == status_filter]

        st.markdown(f"*Showing {len(filtered)} of {len(alerts)} alerts*")

        # Render alerts
        for alert in filtered[:30]:
            threat_level = alert.get("threat_level", "Unknown") or "Pending"
            badge = get_threat_badge_html(threat_level)
            ts = format_timestamp(alert.get("timestamp"))
            attack = alert.get("attack_vector", "—") or "Analyzing..."
            src = alert.get("src_ip", "—")
            dst = alert.get("dst_ip", "—")
            proto = alert.get("protocol", "—")
            flags = alert.get("triage_flags", "—")
            confidence = alert.get("confidence")
            conf_str = f"{confidence:.0%}" if confidence else "—"

            # Alert row
            st.markdown(f"""
            <div class="alert-row">
                <span style="color: #4a5568; font-size: 0.8rem; min-width: 65px;">{ts}</span>
                {badge}
                <span style="color: #e2e8f0; font-weight: 600; min-width: 180px;">{attack}</span>
                <span style="color: #7a8ba5; font-size: 0.85rem;">
                    {src} → {dst} | {proto} | {flags}
                </span>
                <span style="color: #00d4ff; font-size: 0.8rem; margin-left: auto;">{conf_str}</span>
            </div>
            """, unsafe_allow_html=True)

            # Expandable detail
            with st.expander(f"📋 Alert #{alert.get('id', '?')} — Full Analysis"):
                detail_col1, detail_col2 = st.columns(2)
                with detail_col1:
                    st.markdown(f"""
                    **Source:** `{src}:{alert.get('src_port', '—')}`  
                    **Dest:** `{dst}:{alert.get('dst_port', '—')}`  
                    **Protocol:** `{proto}`  
                    **TCP Flags:** `{alert.get('tcp_flags', '—')}`  
                    **Triage Flags:** `{flags}`  
                    """)
                with detail_col2:
                    st.markdown(f"""
                    **Threat Level:** {threat_level}  
                    **Confidence:** {conf_str}  
                    **Attack Vector:** {attack}  
                    **MITRE ATT&CK:** `{alert.get('mitre_technique', '—') or '—'}`  
                    **Recommended Action:** {alert.get('recommended_action', '—') or '—'}  
                    """)

                explanation = alert.get("explanation", "")
                if explanation:
                    st.info(f"**AI Analysis:** {explanation}")

                if alert.get("raw_payload_hex"):
                    st.code(alert["raw_payload_hex"][:256], language="text")
    else:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; color: #4a5568;">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
            <div style="font-size: 1.1rem;">No alerts detected yet</div>
            <div style="font-size: 0.9rem; margin-top: 0.5rem;">
                Start the sniffer and generate network traffic to see alerts appear here.
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Auto-refresh ─────────────────────────────────────────────────
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
