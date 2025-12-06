import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import os
from datetime import datetime, timedelta
from collections import Counter

# --- Configuration ---
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
INDEX_NAME = "honeypot-logs"

# --- Page Config ---
st.set_page_config(
    page_title="P.A.L.A.D.I.N",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Enhanced Cyberpunk Styling ---
st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
        
        .stApp { 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0a1a 100%);
            color: #00ff41; 
            font-family: 'Share Tech Mono', monospace;
        }
        
        /* Animated Background Grid */
        .stApp::before {
            content: "";
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image: 
                linear-gradient(rgba(0, 255, 65, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 65, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            animation: gridScroll 20s linear infinite;
        }
        
        @keyframes gridScroll {
            0% { transform: translateY(0); }
            100% { transform: translateY(50px); }
        }
        
        /* Main Title */
        h1 {
            font-family: 'Orbitron', monospace !important;
            font-weight: 900 !important;
            font-size: 3rem !important;
            text-align: center;
            background: linear-gradient(90deg, #00ff41, #00d4ff, #ff00ff, #00ff41);
            background-size: 300% 300%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientShift 3s ease infinite;
            text-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
            margin-bottom: 0 !important;
        }
        
        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        /* Subtitle */
        .subtitle {
            text-align: center;
            color: #888;
            font-size: 0.9rem;
            letter-spacing: 3px;
            margin-top: -10px;
            margin-bottom: 30px;
        }
        
        /* Metric Cards - Enhanced */
        .metric-card { 
            background: linear-gradient(135deg, #0d0d0d 0%, #1a1a1a 100%);
            border: 1px solid #00ff41;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.2), inset 0 0 20px rgba(0, 255, 65, 0.05);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .metric-card::before {
            content: "";
            position: absolute;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 255, 65, 0.1), transparent);
            transform: rotate(45deg);
            animation: shine 3s infinite;
        }
        
        @keyframes shine {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }
        
        /* Status Indicators */
        .status-normal { 
            color: #00ff41; 
            text-shadow: 0 0 10px #00ff41;
            animation: pulse 2s infinite;
        }
        .status-elevated { 
            color: #ffaa00; 
            text-shadow: 0 0 10px #ffaa00;
            animation: pulse 1.5s infinite;
        }
        .status-critical { 
            color: #ff003c; 
            text-shadow: 0 0 15px #ff003c;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        /* Section Headers */
        h2, h3 {
            font-family: 'Orbitron', monospace !important;
            color: #00d4ff !important;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 10px;
            margin-top: 20px !important;
        }
        
        /* Data Tables */
        .stDataFrame {
            border: 1px solid #00ff41;
            border-radius: 5px;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        }
        
        /* Sidebar */
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0a0a0a 0%, #1a0a1a 100%);
            border-right: 2px solid #00ff41;
        }
        
        section[data-testid="stSidebar"] h2 {
            color: #00ff41 !important;
        }
        
        /* Alert Box */
        .alert-box {
            background: rgba(255, 0, 60, 0.1);
            border: 2px solid #ff003c;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            animation: alertBlink 2s infinite;
        }
        
        @keyframes alertBlink {
            0%, 100% { border-color: #ff003c; box-shadow: 0 0 10px rgba(255, 0, 60, 0.3); }
            50% { border-color: #ff6600; box-shadow: 0 0 20px rgba(255, 0, 60, 0.6); }
        }
        
        /* Info Panel */
        .info-panel {
            background: rgba(0, 212, 255, 0.05);
            border-left: 4px solid #00d4ff;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        ::-webkit-scrollbar-track {
            background: #0a0a0a;
        }
        ::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 5px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #00d4ff;
        }
        
        /* Glowing Divider */
        hr {
            border: none;
            height: 2px;
            background: linear-gradient(90deg, transparent, #00ff41, transparent);
            margin: 30px 0;
        }
    </style>
""", unsafe_allow_html=True)

# --- Database Connection ---
@st.cache_resource
def get_es_client():
    try:
        return Elasticsearch(ES_HOST, request_timeout=5)
    except Exception as e:
        return None

es = get_es_client()

# --- Enhanced Data Fetchers ---
def fetch_dashboard_stats():
    if not es: return None
    
    query = {
        "size": 0,
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "30s"
                },
                "aggs": {
                    "by_type": {"terms": {"field": "ai_attack_type.keyword"}},
                    "avg_risk": {"avg": {"field": "mitre.risk_score"}}
                }
            },
            "attack_distribution": {
                "terms": {"field": "ai_attack_type.keyword", "size": 15}
            },
            "service_distribution": {
                "terms": {"field": "service.keyword", "size": 10}
            },
            "mitre_tactics": {
                "terms": {"field": "mitre.tactics.keyword", "size": 10}
            },
            "top_attackers": {
                "terms": {"field": "src_ip.keyword", "size": 10},
                "aggs": {
                    "attack_count": {"value_count": {"field": "@timestamp"}},
                    "max_risk": {"max": {"field": "mitre.risk_score"}}
                }
            },
            "max_risk": {"max": {"field": "mitre.risk_score"}},
            "avg_risk": {"avg": {"field": "mitre.risk_score"}},
            "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "total_attacks": {"value_count": {"field": "@timestamp"}},
            "blocked_attacks": {
                "filter": {"term": {"ai_final_status.keyword": "BLOCKED"}}
            }
        }
    }
    
    try:
        return es.search(index=INDEX_NAME, body=query)
    except:
        return None

def fetch_recent_logs(limit=25):
    if not es: return []
    try:
        resp = es.search(
            index=INDEX_NAME,
            body={
                "size": limit,
                "sort": [{"@timestamp": "desc"}],
                "query": {"match_all": {}},
                "_source": ["@timestamp", "src_ip", "service", "ai_attack_type", 
                           "mitre.risk_score", "ai_final_status", "mitre.tactics", 
                           "mitre.techniques", "username", "password"]
            }
        )
        return [h["_source"] for h in resp["hits"]["hits"]]
    except:
        return []

def fetch_geographic_data():
    """Fetch IP location data for threat map (placeholder for demo)"""
    if not es: return []
    try:
        resp = es.search(
            index=INDEX_NAME,
            body={
                "size": 0,
                "aggs": {
                    "by_country": {
                        "terms": {"field": "src_ip.keyword", "size": 50}
                    }
                }
            }
        )
        # In real implementation, you'd use GeoIP enrichment
        return resp["aggregations"]["by_country"]["buckets"]
    except:
        return []

# --- Sidebar Configuration ---
with st.sidebar:
    st.markdown("### ⚙️ CONTROL PANEL")
    
    refresh_rate = st.slider("🔄 Refresh Rate (seconds)", 1, 10, 2)
    
    st.markdown("---")
    st.markdown("### 📊 DISPLAY OPTIONS")
    show_timeline = st.checkbox("Timeline Chart", value=True)
    show_distribution = st.checkbox("Attack Distribution", value=True)
    show_mitre = st.checkbox("MITRE ATT&CK", value=True)
    show_services = st.checkbox("Service Analytics", value=True)
    
    st.markdown("---")
    st.markdown("### 🎯 FILTERS")
    risk_threshold = st.slider("Min Risk Score", 0.0, 5.0, 0.0, 0.5)
    
    st.markdown("---")
    st.markdown("### 📡 SYSTEM STATUS")
    if es:
        st.success("✅ Neural Core: ONLINE")
        st.info(f"🔗 Host: {ES_HOST}")
    else:
        st.error("❌ Neural Core: OFFLINE")
    
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; font-size: 0.8rem;'>
        <b>PALADIN v2.0</b><br>
        Protective Advanced Learning<br>
        AI Defense Intelligence Network
    </div>
    """, unsafe_allow_html=True)

# --- Main Dashboard ---
st.markdown("<h1>🛡️ PALADIN</h1>", unsafe_allow_html=True)
st.markdown("<p class='subtitle'>NEURAL DEFENSE CORE :: ACTIVE THREAT MONITORING</p>", unsafe_allow_html=True)

# Live update container
live_container = st.empty()

while True:
    with live_container.container():
        stats = fetch_dashboard_stats()
        raw_logs = fetch_recent_logs(25)
        
        if stats and "aggregations" in stats:
            aggs = stats["aggregations"]
            
            # === ROW 1: KPI METRICS ===
            st.markdown("### 📈 THREAT INTELLIGENCE OVERVIEW")
            kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
            
            total = aggs["total_attacks"]["value"]
            max_risk = aggs["max_risk"]["value"] or 0.0
            avg_risk = aggs["avg_risk"]["value"] or 0.0
            active_ips = aggs["unique_ips"]["value"]
            blocked = aggs["blocked_attacks"]["doc_count"]
            
            # Dynamic Status
            if max_risk > 4:
                status = '<span class="status-critical">🔴 CRITICAL BREACH</span>'
            elif max_risk > 2:
                status = '<span class="status-elevated">🟡 ELEVATED RISK</span>'
            else:
                status = '<span class="status-normal">🟢 SYSTEM SECURE</span>'
            
            with kpi1:
                st.markdown(f"""
                <div class="metric-card">
                    <div style="font-size: 2rem;">📡</div>
                    <div style="font-size: 0.9rem; color: #888; margin-top: 10px;">TOTAL EVENTS</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #00ff41; margin-top: 5px;">{total:,}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with kpi2:
                st.markdown(f"""
                <div class="metric-card">
                    <div style="font-size: 2rem;">🔥</div>
                    <div style="font-size: 0.9rem; color: #888; margin-top: 10px;">PEAK RISK</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #00ff41; margin-top: 5px;">{max_risk:.2f} / 5.0</div>
                </div>
                """, unsafe_allow_html=True)
            
            with kpi3:
                st.markdown(f"""
                <div class="metric-card">
                    <div style="font-size: 2rem;">⚡</div>
                    <div style="font-size: 0.9rem; color: #888; margin-top: 10px;">AVG RISK</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #00ff41; margin-top: 5px;">{avg_risk:.2f}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with kpi4:
                st.markdown(f"""
                <div class="metric-card">
                    <div style="font-size: 2rem;">🌍</div>
                    <div style="font-size: 0.9rem; color: #888; margin-top: 10px;">HOSTILE IPs</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #00ff41; margin-top: 5px;">{active_ips}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with kpi5:
                st.markdown(f"""
                <div class="metric-card">
                    <div style="font-size: 2rem;">🛡️</div>
                    <div style="font-size: 0.9rem; color: #888; margin-top: 10px;">BLOCKED</div>
                    <div style="font-size: 2rem; font-weight: bold; color: #00ff41; margin-top: 5px;">{blocked}</div>
                </div>
                """, unsafe_allow_html=True)
            
            # Status Banner
            st.markdown(f"<div style='text-align: center; font-size: 1.5rem; margin: 20px 0;'>{status}</div>", 
                       unsafe_allow_html=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # === ROW 2: MAIN VISUALIZATIONS ===
            col_left, col_right = st.columns([2, 1])
            
            with col_left:
                if show_timeline:
                    st.markdown("### 📉 THREAT VELOCITY :: TEMPORAL ANALYSIS")
                    buckets = aggs["timeline"]["buckets"]
                    timeline_data = []
                    risk_data = []
                    
                    for b in buckets:
                        ts = b["key_as_string"]
                        avg_risk_val = b.get("avg_risk", {}).get("value", 0)
                        risk_data.append({"Time": ts, "Avg Risk": avg_risk_val or 0})
                        
                        for bucket in b["by_type"]["buckets"]:
                            timeline_data.append({
                                "Time": ts, 
                                "Count": bucket["doc_count"], 
                                "Type": bucket["key"]
                            })
                    
                    if timeline_data:
                        # Create dual-axis chart
                        fig = make_subplots(specs=[[{"secondary_y": True}]])
                        
                        df_time = pd.DataFrame(timeline_data)
                        df_risk = pd.DataFrame(risk_data)
                        
                        # Add attack count as area chart
                        for attack_type in df_time["Type"].unique():
                            df_filtered = df_time[df_time["Type"] == attack_type]
                            fig.add_trace(
                                go.Scatter(
                                    x=df_filtered["Time"], 
                                    y=df_filtered["Count"],
                                    mode='lines',
                                    name=attack_type,
                                    stackgroup='one',
                                    fillcolor=f'rgba({hash(attack_type) % 255}, {(hash(attack_type) * 2) % 255}, {(hash(attack_type) * 3) % 255}, 0.4)'
                                ),
                                secondary_y=False
                            )
                        
                        # Add risk score as line
                        fig.add_trace(
                            go.Scatter(
                                x=df_risk["Time"], 
                                y=df_risk["Avg Risk"],
                                mode='lines+markers',
                                name='Avg Risk Score',
                                line=dict(color='#ff003c', width=3, dash='dot'),
                                marker=dict(size=6)
                            ),
                            secondary_y=True
                        )
                        
                        fig.update_layout(
                            template="plotly_dark",
                            height=400,
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(10,10,10,0.5)",
                            hovermode='x unified',
                            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
                        )
                        
                        fig.update_yaxes(title_text="Attack Count", secondary_y=False)
                        fig.update_yaxes(title_text="Risk Score", secondary_y=True)
                        
                        st.plotly_chart(fig, use_container_width=True, key=f"timeline_{time.time()}")
                    else:
                        st.info("⏳ Monitoring network traffic...")
            
            with col_right:
                if show_distribution:
                    st.markdown("### 🎯 ATTACK VECTOR DISTRIBUTION")
                    pie_buckets = aggs["attack_distribution"]["buckets"]
                    if pie_buckets:
                        df_pie = pd.DataFrame(pie_buckets)
                        fig_pie = go.Figure(data=[go.Pie(
                            labels=df_pie["key"],
                            values=df_pie["doc_count"],
                            hole=0.6,
                            marker=dict(
                                colors=px.colors.qualitative.Bold,
                                line=dict(color='#000000', width=2)
                            ),
                            textposition='inside',
                            textinfo='percent+label'
                        )])
                        
                        fig_pie.update_layout(
                            template="plotly_dark",
                            height=400,
                            paper_bgcolor="rgba(0,0,0,0)",
                            showlegend=False,
                            annotations=[dict(text='ATTACKS', x=0.5, y=0.5, font_size=20, showarrow=False)]
                        )
                        
                        st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{time.time()}")
                    else:
                        st.info("⏳ Awaiting attack vectors...")
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # === ROW 3: ADDITIONAL ANALYTICS ===
            col_mitre, col_services = st.columns(2)
            
            with col_mitre:
                if show_mitre:
                    st.markdown("### 🎯 MITRE ATT&CK TACTICS")
                    mitre_buckets = aggs["mitre_tactics"]["buckets"]
                    if mitre_buckets:
                        df_mitre = pd.DataFrame(mitre_buckets)
                        df_mitre = df_mitre.sort_values("doc_count", ascending=True)
                        
                        fig_mitre = go.Figure(go.Bar(
                            x=df_mitre["doc_count"],
                            y=df_mitre["key"],
                            orientation='h',
                            marker=dict(
                                color=df_mitre["doc_count"],
                                colorscale='Reds',
                                line=dict(color='#ff003c', width=1)
                            ),
                            text=df_mitre["doc_count"],
                            textposition='auto'
                        ))
                        
                        fig_mitre.update_layout(
                            template="plotly_dark",
                            height=350,
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(10,10,10,0.5)",
                            xaxis_title="Frequency",
                            yaxis_title=""
                        )
                        
                        st.plotly_chart(fig_mitre, use_container_width=True, key=f"mitre_{time.time()}")
                    else:
                        st.info("⏳ Loading MITRE data...")
            
            with col_services:
                if show_services:
                    st.markdown("### 🔌 TARGETED SERVICES")
                    service_buckets = aggs["service_distribution"]["buckets"]
                    if service_buckets:
                        df_services = pd.DataFrame(service_buckets)
                        
                        fig_services = go.Figure(data=[go.Pie(
                            labels=df_services["key"],
                            values=df_services["doc_count"],
                            hole=0.5,
                            marker=dict(
                                colors=px.colors.sequential.Plasma,
                                line=dict(color='#000000', width=2)
                            )
                        )])
                        
                        fig_services.update_layout(
                            template="plotly_dark",
                            height=350,
                            paper_bgcolor="rgba(0,0,0,0)",
                            showlegend=True,
                            legend=dict(orientation="v", yanchor="middle", y=0.5)
                        )
                        
                        st.plotly_chart(fig_services, use_container_width=True, key=f"services_{time.time()}")
                    else:
                        st.info("⏳ Analyzing services...")
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # === ROW 4: TOP ATTACKERS ===
            st.markdown("### 🌐 HOSTILE IP INTELLIGENCE")
            top_attackers = aggs["top_attackers"]["buckets"]
            if top_attackers:
                attacker_data = []
                for attacker in top_attackers:
                    attacker_data.append({
                        "IP Address": attacker["key"],
                        "Total Attempts": attacker["doc_count"],
                        "Peak Risk": attacker["max_risk"]["value"] or 0.0
                    })
                
                df_attackers = pd.DataFrame(attacker_data)
                
                col_att1, col_att2 = st.columns([2, 1])
                
                with col_att1:
                    fig_attackers = go.Figure(data=[
                        go.Bar(
                            x=df_attackers["IP Address"],
                            y=df_attackers["Total Attempts"],
                            marker=dict(
                                color=df_attackers["Peak Risk"],
                                colorscale='Turbo',
                                showscale=True,
                                colorbar=dict(title="Risk")
                            ),
                            text=df_attackers["Total Attempts"],
                            textposition='auto'
                        )
                    ])
                    
                    fig_attackers.update_layout(
                        template="plotly_dark",
                        height=300,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(10,10,10,0.5)",
                        xaxis_title="Source IP",
                        yaxis_title="Attack Attempts"
                    )
                    
                    st.plotly_chart(fig_attackers, use_container_width=True, key=f"attackers_{time.time()}")
                
                with col_att2:
                    st.dataframe(
                        df_attackers,
                        use_container_width=True,
                        height=300,
                        column_config={
                            "Peak Risk": st.column_config.ProgressColumn(
                                "Peak Risk",
                                min_value=0,
                                max_value=5,
                                format="%.2f"
                            )
                        },
                        key=f"att_table_{time.time()}"
                    )
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # === ROW 5: LIVE FEED ===
            st.markdown("### 📜 LIVE INTERCEPT LOG :: NEURAL TRACE")
            if raw_logs:
                flat_logs = []
                for log in raw_logs:
                    flat_log = log.copy()
                    mitre = flat_log.pop("mitre", {})
                    flat_log["risk_score"] = mitre.get("risk_score", 0.0) if isinstance(mitre, dict) else 0.0
                    flat_log["tactics"] = ", ".join(mitre.get("tactics", [])[:2]) if isinstance(mitre, dict) else ""
                    flat_logs.append(flat_log)
                
                df_logs = pd.DataFrame(flat_logs)
                
                # Filter by risk threshold
                if risk_threshold > 0:
                    df_logs = df_logs[df_logs["risk_score"] >= risk_threshold]
                
                # High-risk alerts
                high_risk_count = len(df_logs[df_logs["risk_score"] >= 4])
                if high_risk_count > 0:
                    st.markdown(f"""
                    <div class='alert-box'>
                        <b>⚠️ CRITICAL ALERT</b><br>
                        {high_risk_count} high-risk attack(s) detected in recent activity!
                    </div>
                    """, unsafe_allow_html=True)
                
                st.dataframe(
                    df_logs,
                    column_order=["@timestamp", "src_ip", "service", "ai_attack_type", 
                                 "risk_score", "tactics", "ai_final_status"],
                    column_config={
                        "@timestamp": st.column_config.DatetimeColumn("Timestamp", format="DD/MM/YY HH:mm:ss"),
                        "src_ip": st.column_config.TextColumn("Source IP", width="medium"),
                        "service": st.column_config.TextColumn("Service", width="small"),
                        "ai_attack_type": st.column_config.TextColumn("Attack Type", width="medium"),
                        "risk_score": st.column_config.ProgressColumn(
                            "Risk",
                            min_value=0,
                            max_value=5,
                            format="%.2f",
                            width="small"
                        ),
                        "tactics": st.column_config.TextColumn("MITRE Tactics", width="medium"),
                        "ai_final_status": st.column_config.TextColumn("Status", width="small"),
                    },
                    use_container_width=True,
                    height=400,
                    key=f"logs_{time.time()}"
                )
            else:
                st.info("⏳ Neural network initializing... Awaiting threat data.")
        
        else:
            st.markdown("""
            <div class='alert-box' style='text-align: center; padding: 40px;'>
                <h2>⚠️ NEURAL CORE CONNECTION LOST</h2>
                <p>Unable to establish connection to Elasticsearch</p>
                <p style='color: #666; font-size: 0.9rem;'>Retrying in {refresh_rate} seconds...</p>
            </div>
            """.format(refresh_rate=refresh_rate), unsafe_allow_html=True)
    
    time.sleep(refresh_rate)