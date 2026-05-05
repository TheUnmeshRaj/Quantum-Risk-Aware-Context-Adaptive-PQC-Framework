import streamlit as st
import requests
import pandas as pd
import numpy as np
from backend.utils.devices import DEVICE_PROFILES

st.set_page_config(layout="wide", page_title="Unisys · PQC Platform", page_icon="🔐")


# ─────────────────────────────────────────────────────────────
# PREMIUM DESIGN SYSTEM
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');

/* ── Reset & Base ─────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [class*="css"], .stApp {
  font-family: 'Inter', -apple-system, sans-serif !important;
  background: #050a18 !important;
}

/* ── Animated gradient mesh background ──────── */
.stApp {
  background:
    radial-gradient(ellipse 80% 50% at 20% 10%, rgba(56,189,248,0.07) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 80% 80%, rgba(99,102,241,0.08) 0%, transparent 60%),
    radial-gradient(ellipse 50% 60% at 50% 50%, rgba(16,185,129,0.04) 0%, transparent 70%),
    #050a18 !important;
}

.block-container { padding: 1.8rem 2.5rem 3rem !important; max-width: 1400px !important; }

/* ── Typography ──────────────────────────────── */
h1, h2, h3, h4 { color: #f1f5f9 !important; font-family: 'Space Grotesk', sans-serif !important; }
p, label, .stMarkdown, .stCaption { color: #94a3b8 !important; }
code { color: #a5f3fc !important; background: rgba(165,243,252,0.08) !important;
       border-radius: 4px !important; padding: 1px 6px !important; }

/* ── Page header gradient title ─────────────── */
.page-hero {
  background: linear-gradient(135deg, #0f172a 0%, #0c1a35 50%, #0a0f1e 100%);
  border: 1px solid rgba(56,189,248,0.15);
  border-radius: 20px;
  padding: 2rem 2.5rem;
  margin-bottom: 1.5rem;
  position: relative;
  overflow: hidden;
}
.page-hero::before {
  content:'';
  position:absolute; top:-40%; left:-10%;
  width:50%; height:200%;
  background: radial-gradient(ellipse, rgba(56,189,248,0.12) 0%, transparent 70%);
  pointer-events:none;
}
.page-hero::after {
  content:'';
  position:absolute; bottom:-40%; right:-5%;
  width:40%; height:200%;
  background: radial-gradient(ellipse, rgba(99,102,241,0.10) 0%, transparent 70%);
  pointer-events:none;
}
.hero-title {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 2.2rem; font-weight: 800; letter-spacing: -0.02em;
  background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #34d399 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text; margin: 0; line-height: 1.2;
}
.hero-sub {
  color: #64748b !important; font-size: 0.92rem;
  margin-top: 0.5rem; letter-spacing: 0.02em;
}
.hero-badges { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }
.hero-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 0.3rem 0.85rem;
  background: rgba(56,189,248,0.08);
  border: 1px solid rgba(56,189,248,0.2);
  border-radius: 99px; font-size: 0.75rem; color: #7dd3fc;
  font-family: 'JetBrains Mono', monospace;
}

/* ── Tabs ────────────────────────────────────── */
[data-baseweb="tab-list"] {
  background: rgba(15,23,42,0.8) !important;
  border: 1px solid rgba(255,255,255,0.06) !important;
  border-radius: 14px !important;
  padding: 5px !important; gap: 4px !important;
  backdrop-filter: blur(12px) !important;
}
[data-baseweb="tab"] {
  color: #475569 !important;
  border-radius: 10px !important;
  font-weight: 600 !important;
  font-size: 0.83rem !important;
  padding: 0.5rem 1.2rem !important;
  transition: all 0.2s ease !important;
  letter-spacing: 0.01em !important;
}
[data-baseweb="tab"]:hover { color: #94a3b8 !important; background: rgba(255,255,255,0.04) !important; }
[aria-selected="true"][data-baseweb="tab"] {
  background: linear-gradient(135deg, rgba(56,189,248,0.15), rgba(99,102,241,0.15)) !important;
  color: #38bdf8 !important;
  box-shadow: 0 0 20px rgba(56,189,248,0.12), inset 0 1px 0 rgba(255,255,255,0.08) !important;
  border: 1px solid rgba(56,189,248,0.25) !important;
}

/* ── Metric Cards ────────────────────────────── */
[data-testid="metric-container"] {
  background: linear-gradient(145deg, rgba(17,24,39,0.9) 0%, rgba(15,23,42,0.95) 100%) !important;
  border: 1px solid rgba(56,189,248,0.15) !important;
  border-radius: 16px !important;
  padding: 1.2rem 1.4rem !important;
  backdrop-filter: blur(8px);
  box-shadow: 0 4px 24px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.05);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}
[data-testid="metric-container"]:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 32px rgba(56,189,248,0.1), inset 0 1px 0 rgba(255,255,255,0.05);
}
[data-testid="metric-container"] label {
  color: #475569 !important; font-size: 0.72rem !important;
  text-transform: uppercase; letter-spacing: 0.1em !important; font-weight: 600 !important;
}
[data-testid="stMetricValue"] {
  color: #38bdf8 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 1.6rem !important; font-weight: 600 !important;
}
[data-testid="stMetricDelta"] { font-size: 0.78rem !important; }
[data-testid="stMetricDeltaIcon-Up"]   { color: #10b981 !important; }
[data-testid="stMetricDeltaIcon-Down"] { color: #ef4444 !important; }

/* ── Glass Cards ─────────────────────────────── */
.glass-card {
  background: linear-gradient(145deg, rgba(17,24,39,0.85), rgba(15,23,42,0.9));
  border: 1px solid rgba(255,255,255,0.07);
  border-radius: 18px; padding: 1.5rem;
  backdrop-filter: blur(12px);
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  margin-bottom: 1rem;
}

/* ── Strategy cards ──────────────────────────── */
.winner-card {
  background: linear-gradient(145deg, rgba(6,78,59,0.6) 0%, rgba(4,120,87,0.4) 100%);
  border: 1px solid rgba(16,185,129,0.4);
  border-radius: 16px; padding: 1.3rem 1.6rem; margin-bottom: 0.8rem;
  box-shadow: 0 0 30px rgba(16,185,129,0.08), inset 0 1px 0 rgba(255,255,255,0.05);
}
.loser-card {
  background: linear-gradient(145deg, rgba(69,10,10,0.6) 0%, rgba(127,29,29,0.3) 100%);
  border: 1px solid rgba(239,68,68,0.25);
  border-radius: 16px; padding: 1.3rem 1.6rem; margin-bottom: 0.8rem;
}
.neutral-card {
  background: linear-gradient(145deg, rgba(15,23,42,0.8), rgba(30,41,59,0.7));
  border: 1px solid rgba(100,116,139,0.2);
  border-radius: 16px; padding: 1.3rem 1.6rem; margin-bottom: 0.8rem;
}
.card-title  { font-size: 0.95rem; font-weight: 700; color: #f1f5f9 !important; }
.card-stat   { font-size: 1.9rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.card-label  { font-size: 0.72rem; color: #64748b; margin-top: 0.2rem; }

/* ── Section Headers ─────────────────────────── */
.section-header {
  display: flex; align-items: center; gap: 0.6rem;
  font-size: 0.75rem; font-weight: 700; color: #38bdf8;
  text-transform: uppercase; letter-spacing: 0.14em;
  border-bottom: 1px solid rgba(56,189,248,0.15);
  padding-bottom: 0.5rem; margin: 1.6rem 0 1rem;
}
.section-header::before {
  content: ''; display: inline-block;
  width: 3px; height: 14px;
  background: linear-gradient(180deg, #38bdf8, #6366f1);
  border-radius: 2px;
}

/* ── Buttons ─────────────────────────────────── */
.stButton > button {
  background: linear-gradient(135deg, rgba(56,189,248,0.12), rgba(99,102,241,0.12)) !important;
  border: 1px solid rgba(56,189,248,0.3) !important;
  color: #38bdf8 !important;
  border-radius: 10px !important;
  font-weight: 600 !important; font-size: 0.85rem !important;
  padding: 0.55rem 1.3rem !important;
  transition: all 0.2s ease !important;
  letter-spacing: 0.02em !important;
}
.stButton > button:hover {
  background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(99,102,241,0.22)) !important;
  border-color: rgba(56,189,248,0.5) !important;
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 20px rgba(56,189,248,0.2) !important;
}
.stButton > button:active { transform: translateY(0) !important; }

/* ── Inputs / Selects ────────────────────────── */
.stSelectbox > div > div, .stNumberInput > div > div > input,
.stTextInput > div > div > input, .stSlider > div {
  background: rgba(15,23,42,0.8) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  border-radius: 10px !important;
  color: #e2e8f0 !important;
}

/* ── Expander ────────────────────────────────── */
[data-testid="stExpander"] {
  background: rgba(15,23,42,0.6) !important;
  border: 1px solid rgba(255,255,255,0.07) !important;
  border-radius: 12px !important;
}
[data-testid="stExpander"] summary {
  color: #94a3b8 !important; font-weight: 600 !important;
}

/* ── Progress ────────────────────────────────── */
.stProgress > div > div {
  background: linear-gradient(90deg, #38bdf8, #6366f1, #10b981) !important;
  border-radius: 99px !important;
}

/* ── Alerts ──────────────────────────────────── */
.stAlert { border-radius: 12px !important; }

/* ── HR ──────────────────────────────────────── */
hr { border-color: rgba(255,255,255,0.06) !important; margin: 1.5rem 0 !important; }

/* ── API-specific atoms ──────────────────────── */
.api-badge {
  display:inline-block; padding:.22rem .65rem; border-radius:6px;
  font-size:.72rem; font-family:'JetBrains Mono',monospace;
  font-weight:700; margin-right:.4rem; vertical-align:middle;
  letter-spacing:.05em;
}
.badge-get  { background:rgba(13,61,31,0.8); color:#4ade80; border:1px solid rgba(22,101,52,0.6); }
.badge-post { background:rgba(30,26,13,0.8); color:#fbbf24; border:1px solid rgba(146,64,14,0.6); }

.step-row {
  background: rgba(15,23,42,0.7);
  border-left: 3px solid #6366f1;
  border-radius: 10px; padding:.65rem 1.1rem; margin-bottom:.4rem;
  color:#e2e8f0; font-size:.84rem; line-height: 1.5;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
  transition: border-color 0.2s;
}
.step-row:hover { border-color: #38bdf8; }

.pill {
  display:inline-block; padding:.18rem .6rem; border-radius:99px;
  font-size:.72rem; font-weight:700; margin:.1rem;
  font-family:'JetBrains Mono',monospace;
}
.pill-green  { background:rgba(4,120,87,0.3); color:#34d399; border:1px solid rgba(16,185,129,0.3); }
.pill-red    { background:rgba(127,29,29,0.3); color:#fca5a5; border:1px solid rgba(239,68,68,0.3); }
.pill-blue   { background:rgba(30,58,95,0.4); color:#7dd3fc; border:1px solid rgba(56,189,248,0.3); }
.pill-yellow { background:rgba(120,53,15,0.3); color:#fcd34d; border:1px solid rgba(245,158,11,0.3); }

.api-out {
  background: #0d1117; border: 1px solid rgba(255,255,255,0.07);
  border-radius: 12px; padding:1.1rem;
  font-family:'JetBrains Mono',monospace;
  font-size:.78rem; color:#a5f3fc;
  white-space:pre-wrap; max-height:360px; overflow-y:auto;
  line-height: 1.6;
}

/* ── Glow pulse for CRITICAL tier ───────────── */
@keyframes glowPulse {
  0%, 100% { box-shadow: 0 0 8px rgba(239,68,68,0.3); }
  50%       { box-shadow: 0 0 20px rgba(239,68,68,0.6); }
}
.glow-critical { animation: glowPulse 2s ease-in-out infinite; }

/* ── Scrollbar ───────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(56,189,248,0.25); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover { background: rgba(56,189,248,0.45); }

/* ── Chart containers ────────────────────────── */
[data-testid="stVegaLiteChart"], [data-testid="element-container"] canvas {
  border-radius: 12px !important;
}
</style>
""", unsafe_allow_html=True)

# ── Page Hero Header ─────────────────────────────────────────
st.markdown("""
<div class="page-hero">
  <div class="hero-title">🔐 Unisys · PQC Platform</div>
  <div class="hero-sub">Quantum Risk-Aware · Context-Adaptive · Post-Quantum Cryptographic Framework</div>
  <div class="hero-badges">
    <span class="hero-badge">⚡ NIST FIPS 203/204/205</span>
    <span class="hero-badge">🛡 Kyber · Dilithium · SPHINCS+</span>
    <span class="hero-badge">📡 Live FastAPI Backend</span>
    <span class="hero-badge">🧠 Production API v2.0</span>
  </div>
</div>
""", unsafe_allow_html=True)

API_URL      = "http://127.0.0.1:8000"
PROD_API_URL = "http://127.0.0.1:8002"

tab1, tab2, tab3, tab4 = st.tabs([
    "  ⚙️  Decision Engine  ",
    "  ⚛️  Quantum Attack Sim  ",
    "  📊  Migration Analysis  ",
    "  🧠  Production API  ",
])

# ═══════════════════════════════════════════════════════════════
# TAB 1 — DECISION ENGINE
# ═══════════════════════════════════════════════════════════════
with tab1:
    def render_device(device, idx):
        with st.container():
            st.subheader(device["name"])
            s = st.slider(f"Sensitivity {idx}", 0.0, 10.0, device["data_sensitivity"], key=f"s{idx}")
            e = st.slider(f"Exposure {idx}", 0.0, 10.0, device["exposure_level"], key=f"e{idx}")
            l = st.number_input(f"Lifetime (yrs) {idx}", 1, 30, int(device["data_lifetime_yrs"]), key=f"l{idx}")
            t = st.slider(f"Threat Window {idx}", 0.0, 10.0, device["threat_window"], key=f"t{idx}")
            adversary = st.selectbox(f"Adversary {idx}", ["low", "medium", "nation_state"], key=f"a{idx}")
            st.caption("**Hardware**")
            hw = device.get("hardware", {})
            ram_default = min(hw.get("ram_kb", 64), 2_000_000)
            ram = st.number_input(f"RAM KB {idx}", 32, 2_000_000, ram_default, key=f"ram{idx}")
            cpu = st.text_input(f"CPU {idx}", hw.get("cpu", "Cortex-M0"), key=f"cpu{idx}")
            fpu = st.checkbox(f"FPU {idx}", value=hw.get("has_fpu", False), key=f"fpu{idx}")
            bw  = st.number_input(f"Bandwidth kbps {idx}", 10, 1000000, hw.get("bandwidth_kbps", 50), key=f"bw{idx}")
            return {
                "data_sensitivity": s, "exposure_level": e,
                "data_lifetime_yrs": l, "threat_window": t,
                "adversary": adversary,
                "ram_kb": ram, "cpu": cpu, "has_fpu": fpu, "bandwidth_kbps": bw
            }

    cols = st.columns(3)
    inputs = []
    for i, col in enumerate(cols):
        if i < len(DEVICE_PROFILES):
            with col:
                inputs.append(render_device(DEVICE_PROFILES[i], i))
        else:
            inputs.append(None)

    st.markdown("---")
    if st.button("🚀 Run Analysis", key="run_analysis"):
        result_cols = st.columns(3)
        for i, device_input in enumerate(inputs):
            if device_input is None: continue
            try:
                response = requests.post(f"{API_URL}/analyze", json=device_input)
                data = response.json()
                risk, decision = data["risk"], data["decision"]
                with result_cols[i]:
                    qri = risk["qri"]
                    tier = risk["qri_tier"]
                    tier_colors = {"LOW": "#10b981", "MODERATE": "#f59e0b", "ELEVATED": "#f97316", "HIGH": "#ef4444", "CRITICAL": "#dc2626"}
                    col_hex = tier_colors.get(tier, "#64748b")
                    st.markdown(f"""
                    <div style="border-left: 4px solid {col_hex}; background:#111827; border-radius:10px; padding:1rem; margin-bottom:1rem;">
                      <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.1em;">Device {i+1} Result</div>
                      <div style="font-size:2rem;font-weight:700;color:{col_hex};font-family:'JetBrains Mono',monospace;">QRI {qri}</div>
                      <div style="font-size:0.9rem;color:{col_hex}">● {tier}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.success(f"✅ **{decision.get('algorithm_key', 'N/A')}**")
                    if decision.get("security_gap", 0) > 0:
                        st.error(f"⚠️ {decision.get('warning', 'Security gap')}")
                    bd = decision.get("breakdown", {})
                    df = pd.DataFrame({"Component": ["Security", "RAM", "Bandwidth"],
                                       "Score": [bd.get("security_fit",0), bd.get("ram_fit",0), bd.get("bandwidth_fit",0)]})
                    st.bar_chart(df.set_index("Component"), color="#38bdf8")
                    with st.expander("Alternatives & Rejected"):
                        for alt in decision.get("alternatives", []):
                            st.write(f"→ **{alt['key']}** (score: {alt['score']})")
                        for r in decision.get("rejected", []):
                            st.write(f"✗ {r['algorithm']} — {r['reason']}")
            except Exception as ex:
                with result_cols[i]:
                    st.error(f"API error: {ex}")

# ═══════════════════════════════════════════════════════════════
# TAB 2 — QUANTUM ATTACK SIM
# ═══════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-header">Shor\'s Algorithm — RSA-2048 Break Time Analysis</div>', unsafe_allow_html=True)
    st.write("Simulates quantum circuit complexity for factoring an RSA modulus and extrapolates realistic break times.")

    if st.button("⚛️ Run Quantum Attack Simulation", key="run_qa"):
        with st.spinner("Building quantum circuit and extrapolating..."):
            try:
                res = requests.get(f"{API_URL}/simulate/quantum_attack")
                data = res.json()

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Circuit Qubits", data["circuit_qubits"])
                col2.metric("Circuit Depth", data["circuit_depth"])
                col3.metric("RSA-2048 (Classical)", f"{data['classical_years']:.2e} yrs")
                col4.metric("RSA-2048 (Quantum)", f"{data['quantum_hours']:.2f} hrs")

                st.markdown("---")
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("""
                    <div style="background:linear-gradient(135deg,#1f1a1a,#2d1515);border:1.5px solid #ef4444;border-radius:14px;padding:1.5rem;">
                      <div style="color:#ef4444;font-size:0.8rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem;">🔓 RSA-2048 · BROKEN</div>
                      <div style="color:#f1f5f9;font-size:2.4rem;font-weight:700;font-family:'JetBrains Mono',monospace;">HOURS</div>
                      <div style="color:#94a3b8;font-size:0.85rem;margin-top:.5rem;">
                        A fault-tolerant quantum computer running Shor's algorithm
                        reduces RSA-2048 to a polynomial-time problem.
                        At 1 MHz logical clock speed, break time is measured in <strong style="color:#ef4444">hours</strong>, not decades.
                      </div>
                    </div>
                    """, unsafe_allow_html=True)
                with c2:
                    st.markdown("""
                    <div style="background:linear-gradient(135deg,#0f3d2e,#064e3b);border:1.5px solid #10b981;border-radius:14px;padding:1.5rem;">
                      <div style="color:#10b981;font-size:0.8rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem;">🛡️ ML-KEM (Kyber) · SECURE</div>
                      <div style="color:#f1f5f9;font-size:2.4rem;font-weight:700;font-family:'JetBrains Mono',monospace;">CENTURIES</div>
                      <div style="color:#94a3b8;font-size:0.85rem;margin-top:.5rem;">
                        Kyber relies on the Learning With Errors (LWE) problem over
                        lattices. No known quantum algorithm — including Shor's —
                        provides polynomial speedup. Grover's search only yields √n,
                        mitigated by larger key sizes.
                      </div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")
                st.markdown('<div class="section-header">Gate Composition</div>', unsafe_allow_html=True)
                gates = data.get("gate_counts", {})
                gdf = pd.DataFrame({"Gate": list(gates.keys()), "Count": list(gates.values())})
                st.bar_chart(gdf.set_index("Gate"), color="#6366f1")
                st.caption("Gate counts shown for the simplified conceptual QPE circuit. A production Shor circuit for RSA-2048 would require ~4,096 logical qubits and millions of Toffoli gates.")

            except Exception as ex:
                st.error(f"Simulation error: {ex}")

# ═══════════════════════════════════════════════════════════════
# TAB 3 — MIGRATION ANALYSIS
# ═══════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-header">Enterprise Migration Strategy Comparison</div>', unsafe_allow_html=True)
    st.write(
        "Simulates 6 heterogeneous enterprise devices over a 10-step quantum threat escalation timeline. "
        "Compares three deployment strategies across reward, financial cost, breach count, and NIST compliance."
    )

    if st.button("📊 Run Full Migration Simulation", key="run_migration"):
        with st.spinner("Running 30-episode RL simulation across all strategies..."):
            try:
                res = requests.get(f"{API_URL}/simulate/migration")
                data = res.json()

                sq  = data["status_quo"]
                pr  = data["paranoid"]
                ad  = data["adaptive"]

                # ── KPI Summary Row ──
                st.markdown('<div class="section-header">Key Performance Indicators</div>', unsafe_allow_html=True)
                k1, k2, k3, k4 = st.columns(4)

                def delta_str(a_val, b_val, higher_is_better=True, prefix="", suffix=""):
                    diff = a_val - b_val
                    sign = "↑" if diff > 0 else "↓"
                    color = "#10b981" if (diff > 0) == higher_is_better else "#ef4444"
                    return f"<span style='color:{color}'>{sign} {prefix}{abs(diff):,.0f}{suffix} vs Status Quo</span>"

                k1.metric("Adaptive Reward", ad["total_reward"],
                           delta=f"{ad['total_reward'] - sq['total_reward']:+.0f} vs Status Quo")
                k2.metric("Adaptive Cost (USD)", f"${ad['total_cost_usd']:,.0f}",
                           delta=f"${ad['total_cost_usd'] - sq['total_cost_usd']:+,.0f} vs Status Quo")
                k3.metric("Adaptive Breaches", ad["total_breaches"],
                           delta=f"{ad['total_breaches'] - sq['total_breaches']:+d} vs Status Quo")
                k4.metric("Adaptive Compliance", f"{ad['avg_compliance']:.0f}%",
                           delta=f"{ad['avg_compliance'] - sq['avg_compliance']:+.0f}% vs Status Quo")

                st.markdown("---")

                # ── Strategy Summary Cards ──
                st.markdown('<div class="section-header">Strategy Scorecard</div>', unsafe_allow_html=True)
                c1, c2, c3 = st.columns(3)

                strategies_display = [
                    ("status_quo",  "🔴 Status Quo (RSA-2048)",  sq,  "loser-card"),
                    ("paranoid",    "🟡 Paranoid (Max PQC)",      pr,  "neutral-card"),
                    ("adaptive",    "🟢 Adaptive (Our Framework)", ad, "winner-card"),
                ]

                reward_color = {"status_quo": "#ef4444", "paranoid": "#f59e0b", "adaptive": "#10b981"}
                for col, (key, title, s_data, card_class) in zip([c1, c2, c3], strategies_display):
                    rcolor = reward_color[key]
                    with col:
                        st.markdown(f"""
                        <div class="{card_class}">
                          <div class="card-title">{title}</div>
                          <div class="card-stat" style="color:{rcolor}">{s_data['total_reward']:+}</div>
                          <div class="card-label">Cumulative Reward</div>
                          <hr style="border-color:#334155;margin:.6rem 0">
                          <div style="display:grid;grid-template-columns:1fr 1fr;gap:.4rem;font-size:.8rem;">
                            <div><span style="color:#64748b">Cost</span><br><b style="color:#e2e8f0">${s_data['total_cost_usd']:,.0f}</b></div>
                            <div><span style="color:#64748b">Breaches</span><br><b style="color:#ef4444">{s_data['total_breaches']}</b></div>
                            <div><span style="color:#64748b">Crashes</span><br><b style="color:#f59e0b">{s_data['total_crashes']}</b></div>
                            <div><span style="color:#64748b">Compliance</span><br><b style="color:#38bdf8">{s_data['avg_compliance']:.0f}%</b></div>
                          </div>
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown("---")

                # ── Time-Series Charts ──
                st.markdown('<div class="section-header">Simulation Timeline</div>', unsafe_allow_html=True)

                steps = list(range(1, 11))

                chart_tab1, chart_tab2, chart_tab3, chart_tab4 = st.tabs(
                    ["Reward per Step", "Breaches per Step", "Compliance Score", "Cumulative Cost"]
                )

                with chart_tab1:
                    rdf = pd.DataFrame({
                        "Step": steps,
                        "Status Quo": sq["hist"]["reward"],
                        "Paranoid":   pr["hist"]["reward"],
                        "Adaptive":   ad["hist"]["reward"],
                    }).set_index("Step")
                    st.line_chart(rdf, color=["#ef4444", "#f59e0b", "#10b981"])
                    st.caption("Each step represents one quarter of threat escalation. Positive reward = secure + efficient devices. Negative = breached or crashed.")

                with chart_tab2:
                    hdf = pd.DataFrame({
                        "Step": steps,
                        "Status Quo": sq["hist"]["hacked"],
                        "Paranoid":   pr["hist"]["hacked"],
                        "Adaptive":   ad["hist"]["hacked"],
                    }).set_index("Step")
                    st.bar_chart(hdf, color=["#ef4444", "#f59e0b", "#10b981"])
                    st.caption("Devices breached per step. Adaptive eliminates breaches through timely, targeted upgrades.")

                with chart_tab3:
                    cdf = pd.DataFrame({
                        "Step": steps,
                        "Status Quo": sq["hist"]["compliance"],
                        "Paranoid":   pr["hist"]["compliance"],
                        "Adaptive":   ad["hist"]["compliance"],
                    }).set_index("Step")
                    st.line_chart(cdf, color=["#ef4444", "#f59e0b", "#10b981"])
                    st.caption("Mean NIST PQC compliance across the device fleet. Score 0 = RSA only, 100 = full NIST L5 coverage.")

                with chart_tab4:
                    cumcost = lambda hist: np.cumsum(hist["total_cost"]).tolist()
                    costdf = pd.DataFrame({
                        "Step":       steps,
                        "Status Quo": cumcost(sq["hist"]),
                        "Paranoid":   cumcost(pr["hist"]),
                        "Adaptive":   cumcost(ad["hist"]),
                    }).set_index("Step")
                    st.line_chart(costdf, color=["#ef4444", "#f59e0b", "#10b981"])
                    st.caption("Cumulative financial cost (migration cost + breach/crash cost). Paranoid over-spends on hardware overhead; Status Quo incurs catastrophic breach costs.")

                st.markdown("---")

                # ── Per-Device Final Allocation ──
                st.markdown('<div class="section-header">Final Device Allocation (End of Simulation)</div>', unsafe_allow_html=True)
                st.write("Shows which algorithm each strategy deployed on each device at the highest threat level.")

                compliance_color = lambda c: ("#10b981" if c >= 80 else "#f59e0b" if c >= 50 else "#ef4444")
                border_color_map = {0: "#ef4444", 1: "#f97316", 2: "#eab308", 3: "#22c55e", 4: "#10b981"}

                for strategy_key, strategy_label, s_data in [
                    ("status_quo",  "🔴 Status Quo",      sq),
                    ("paranoid",    "🟡 Paranoid",         pr),
                    ("adaptive",    "🟢 Adaptive",         ad),
                ]:
                    with st.expander(f"{strategy_label} — Device Allocation", expanded=(strategy_key == "adaptive")):
                        for dev in s_data["per_device"]:
                            bc = border_color_map.get(dev["final_crypto_idx"], "#334155")
                            cc = compliance_color(dev["compliance"])
                            st.markdown(f"""
                            <div style="display:flex;align-items:center;gap:12px;
                                        background:#111827;border-radius:10px;
                                        padding:.6rem 1rem;margin-bottom:.4rem;
                                        border-left:4px solid {bc}">
                              <div style="flex:3;color:#e2e8f0;font-weight:600;font-size:.85rem">{dev['device']}</div>
                              <div style="flex:3;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#38bdf8">{dev['final_crypto']}</div>
                              <div style="flex:1;text-align:right;font-size:.8rem;color:{cc};font-weight:700">{dev['compliance']}%</div>
                            </div>
                            """, unsafe_allow_html=True)

                st.markdown("---")

                # ── Why Adaptive Wins ──
                st.markdown('<div class="section-header">Why Adaptive Outperforms</div>', unsafe_allow_html=True)
                reward_gain = ad["total_reward"] - sq["total_reward"]
                breach_saved = sq["total_breaches"] - ad["total_breaches"]
                cost_vs_paranoid = pr["total_cost_usd"] - ad["total_cost_usd"]

                st.markdown(f"""
                <div style="background:linear-gradient(135deg,#0f172a,#0c1a2e);
                            border:1px solid #1e3a5f;border-radius:14px;padding:1.5rem;">
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.5rem;">
                    <div>
                      <div style="color:#10b981;font-size:1.6rem;font-weight:700;font-family:'JetBrains Mono',monospace">+{reward_gain}</div>
                      <div style="color:#64748b;font-size:.8rem">Reward points gained<br>vs. Status Quo</div>
                    </div>
                    <div>
                      <div style="color:#38bdf8;font-size:1.6rem;font-weight:700;font-family:'JetBrains Mono',monospace">{breach_saved}</div>
                      <div style="color:#64748b;font-size:.8rem">Breaches prevented<br>vs. Status Quo</div>
                    </div>
                    <div>
                      <div style="color:#a78bfa;font-size:1.6rem;font-weight:700;font-family:'JetBrains Mono',monospace">${cost_vs_paranoid:,.0f}</div>
                      <div style="color:#64748b;font-size:.8rem">Cost saved vs.<br>Paranoid over-deployment</div>
                    </div>
                  </div>
                  <hr style="border-color:#1e293b;margin:1rem 0">
                  <div style="color:#94a3b8;font-size:.85rem;line-height:1.6">
                    The <strong style="color:#10b981">Adaptive Framework</strong> uniquely integrates hardware profiling,
                    real-time threat scoring, and NIST compliance targets to select the <em>precise</em> PQC algorithm
                    for each device at each threat level. Unlike Status Quo (which ignores quantum risk entirely) or
                    Paranoid (which crashes constrained IoT devices under excessive overhead), the Adaptive approach
                    matches security to actual risk — delivering maximum protection with minimum operational disruption.
                  </div>
                </div>
                """, unsafe_allow_html=True)

            except Exception as ex:
                st.error(f"Simulation error: {ex}")
                st.exception(ex)

# ═══════════════════════════════════════════════════════════════
# TAB 4 — PRODUCTION API EXPLORER
# ═══════════════════════════════════════════════════════════════
with tab4:

    # ── CSS extras for this tab ──────────────────────────────────
    st.markdown("""
    <style>
    .api-badge {
        display:inline-block; padding:.2rem .6rem; border-radius:6px;
        font-size:.72rem; font-family:'JetBrains Mono',monospace;
        font-weight:700; margin-right:.4rem;
    }
    .badge-get  { background:#0d3d1f; color:#4ade80; border:1px solid #166534; }
    .badge-post { background:#1e1a0d; color:#fbbf24; border:1px solid #92400e; }
    .step-row {
        background:#111827; border-left:3px solid #6366f1;
        border-radius:8px; padding:.55rem 1rem; margin-bottom:.35rem;
        color:#e2e8f0; font-size:.83rem;
    }
    .pill {
        display:inline-block; padding:.15rem .55rem; border-radius:99px;
        font-size:.75rem; font-weight:700; margin:.1rem;
    }
    .pill-green  { background:#064e3b; color:#34d399; }
    .pill-red    { background:#7f1d1d; color:#fca5a5; }
    .pill-blue   { background:#1e3a5f; color:#7dd3fc; }
    .pill-yellow { background:#78350f; color:#fcd34d; }
    .api-out {
        background:#0d1117; border:1px solid #1e293b; border-radius:10px;
        padding:1rem; font-family:'JetBrains Mono',monospace;
        font-size:.8rem; color:#a5f3fc; white-space:pre-wrap;
        max-height:340px; overflow-y:auto;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("### 🧠 Production API Explorer")
    st.caption("Live interface to the upgraded `api.app` — running on port 8002. Shows /health, /analyze, /simulate, and /explain.")

    # ── Health banner ────────────────────────────────────────────
    try:
        hr = requests.get(f"{PROD_API_URL}/health", timeout=2).json()
        st.markdown(f"""
        <div style="background:linear-gradient(90deg,#0f3d2e,#064e3b);
                    border:1px solid #10b981;border-radius:12px;
                    padding:.8rem 1.4rem;display:flex;align-items:center;gap:1.5rem;margin-bottom:1rem">
          <div style="font-size:1.6rem">✅</div>
          <div>
            <div style="color:#10b981;font-weight:700;font-size:1rem">{hr['service']}</div>
            <div style="color:#94a3b8;font-size:.82rem">
              v{hr['version']} &nbsp;·&nbsp; uptime {hr['uptime_sec']}s &nbsp;·&nbsp;
              <span style="color:#34d399">● ONLINE</span>
            </div>
          </div>
          <div style="margin-left:auto;font-family:'JetBrains Mono',monospace;
                      color:#38bdf8;font-size:.85rem">
            GET /health → 200 OK
          </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.error("⚠️ Production API (port 8002) is not reachable. Run: `uvicorn api.app:app --port 8002`")
        st.stop()

    st.markdown("---")

    # ── Device picker ────────────────────────────────────────────
    device_names = [d["name"] for d in DEVICE_PROFILES]
    col_pick, col_adv = st.columns([3, 1])
    with col_pick:
        chosen_name = st.selectbox("Select a device profile", device_names, key="prod_device")
    with col_adv:
        adv = st.selectbox("Adversary", ["low", "medium", "nation_state"], index=1, key="prod_adv")

    profile = next(d for d in DEVICE_PROFILES if d["name"] == chosen_name)
    hw = profile.get("hardware", {})

    device_payload = {
        "name":              profile["name"],
        "description":       profile.get("description", ""),
        "data_sensitivity":  profile["data_sensitivity"],
        "exposure_level":    profile["exposure_level"],
        "data_lifetime_yrs": profile["data_lifetime_yrs"],
        "threat_window":     profile["threat_window"],
        "adversary":         adv,
        "hardware": {
            "ram_kb":         min(hw.get("ram_kb", 64), 2_000_000),
            "cpu":            hw.get("cpu", "unknown"),
            "has_fpu":        hw.get("has_fpu", False),
            "bandwidth_kbps": hw.get("bandwidth_kbps", 100),
        },
    }

    run_col1, run_col2, run_col3 = st.columns(3)
    run_analyze = run_col1.button("🔍 Run /analyze",  key="pa")
    run_explain = run_col2.button("📖 Run /explain",  key="pe")
    run_fleet   = run_col3.button("🚀 Run /simulate (all 6 devices)", key="ps")

    st.markdown("---")

    # ════════════════════════════════════════════════════════
    # /ANALYZE
    # ════════════════════════════════════════════════════════
    if run_analyze:
        with st.spinner("Calling POST /analyze …"):
            try:
                resp = requests.post(f"{PROD_API_URL}/analyze", json=device_payload).json()

                tier_colors = {"LOW":"#10b981","MODERATE":"#f59e0b","ELEVATED":"#f97316","HIGH":"#ef4444","CRITICAL":"#dc2626"}
                tc = tier_colors.get(resp["qri_tier"], "#94a3b8")

                st.markdown(f'<span class="api-badge badge-post">POST</span><code>/analyze</code>', unsafe_allow_html=True)

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("QRI Score", resp["qri"], delta=resp["qri_tier"])
                c2.metric("Required NIST Level", f"L{resp['required_nist_level']}")
                c3.metric("Achieved NIST Level", f"L{resp['achieved_nist_level']}")
                c4.metric("Processing Time", f"{resp['processing_time_ms']:.2f} ms")

                # Selected algorithm card
                gap = resp["security_gap"]
                gap_color = "#ef4444" if gap > 0 else "#10b981"
                st.markdown(f"""
                <div style="background:#111827;border:1.5px solid {tc};
                            border-radius:14px;padding:1.2rem 1.5rem;margin:.8rem 0">
                  <div style="color:{tc};font-size:.75rem;text-transform:uppercase;
                              letter-spacing:.1em;margin-bottom:.4rem">Selected Algorithm</div>
                  <div style="color:#f1f5f9;font-size:1.4rem;font-weight:700;
                              font-family:'JetBrains Mono',monospace">{resp['selected_algorithm']}</div>
                  <div style="color:#94a3b8;font-size:.85rem;margin-top:.3rem">
                    {resp.get('mode','')} &nbsp;·&nbsp; {resp.get('security_level','')} &nbsp;·&nbsp;
                    Score: <b style="color:#38bdf8">{resp['score']:.4f}</b>
                  </div>
                  <div style="margin-top:.6rem;font-size:.83rem;color:#cbd5e1">{resp['reason']}</div>
                  {"<div style='margin-top:.5rem;color:#ef4444;font-size:.82rem'>⚠️ "+resp['warning']+"</div>" if gap > 0 else ""}
                </div>
                """, unsafe_allow_html=True)

                # Score breakdown radar-like bar
                st.markdown("**Scoring Breakdown**")
                bd = resp["breakdown"]
                bdf = pd.DataFrame({
                    "Factor":  ["Security Fit", "RAM Fit", "Bandwidth Fit", "Penalty", "Final Score"],
                    "Score":   [bd["security_fit"], bd["ram_fit"], bd["bandwidth_fit"], bd["penalty"], bd["final_score"]],
                })
                st.bar_chart(bdf.set_index("Factor"), color="#6366f1")

                # Alternatives
                if resp["alternatives"]:
                    st.markdown("**Alternatives (ranked)**")
                    for a in resp["alternatives"]:
                        st.markdown(f"""
                        <div style="background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;
                                    padding:.5rem 1rem;margin-bottom:.3rem;font-size:.83rem">
                          <span style="color:#38bdf8;font-family:'JetBrains Mono',monospace">{a['key']}</span>
                          &nbsp; NIST L{a['level']} &nbsp;·&nbsp; score {a['score']:.4f}
                        </div>""", unsafe_allow_html=True)

                # Rejected
                if resp["rejected"]:
                    with st.expander(f"❌ Rejected algorithms ({len(resp['rejected'])})"):
                        for r in resp["rejected"]:
                            st.markdown(f"""
                            <div style="background:#1f1a1a;border-left:3px solid #7f1d1d;
                                        border-radius:6px;padding:.4rem .8rem;margin-bottom:.3rem;font-size:.82rem">
                              <span style="color:#fca5a5;font-family:'JetBrains Mono',monospace">{r['algorithm']}</span>
                              &nbsp;—&nbsp; <span style="color:#94a3b8">{r['reason']}</span>
                            </div>""", unsafe_allow_html=True)

                # Raw JSON
                with st.expander("📄 Raw API response (JSON)"):
                    import json
                    st.markdown(f'<div class="api-out">{json.dumps(resp, indent=2)}</div>', unsafe_allow_html=True)

            except Exception as ex:
                st.error(f"Error: {ex}")

    # ════════════════════════════════════════════════════════
    # /EXPLAIN
    # ════════════════════════════════════════════════════════
    if run_explain:
        with st.spinner("Calling POST /explain …"):
            try:
                resp = requests.post(f"{PROD_API_URL}/explain", json=device_payload).json()
                st.markdown(f'<span class="api-badge badge-post">POST</span><code>/explain</code>', unsafe_allow_html=True)

                c1, c2 = st.columns(2)
                c1.metric("QRI", resp["qri"])
                c2.metric("Required NIST Level", f"L{resp['required_level']}")

                st.markdown("**Step-by-step Decision Walkthrough**")
                step_icons = ["📥","💻","📊","🎯","🔍","⚖️","✅","🔒"]
                for i, step in enumerate(resp["step_by_step"]):
                    icon = step_icons[i] if i < len(step_icons) else "▸"
                    st.markdown(f'<div class="step-row">{icon} {step}</div>', unsafe_allow_html=True)

                st.markdown(f"""
                <div style="background:#0f3d2e;border:1px solid #10b981;border-radius:10px;
                            padding:1rem 1.2rem;margin-top:.8rem">
                  <div style="color:#10b981;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em">Final Decision</div>
                  <div style="color:#f1f5f9;font-size:1.1rem;font-weight:700;
                              font-family:'JetBrains Mono',monospace;margin-top:.3rem">{resp['selected']}</div>
                  <div style="color:#94a3b8;font-size:.82rem;margin-top:.4rem">{resp['selected_reason']}</div>
                </div>""", unsafe_allow_html=True)

                if resp["rejected"]:
                    st.markdown(f"**Filtered out:** " + " ".join(
                        f'<span class="pill pill-red">{r["algorithm"]}</span>' for r in resp["rejected"]
                    ), unsafe_allow_html=True)

            except Exception as ex:
                st.error(f"Error: {ex}")

    # ════════════════════════════════════════════════════════
    # /SIMULATE (full fleet)
    # ════════════════════════════════════════════════════════
    if run_fleet:
        with st.spinner("Calling POST /simulate on all 6 device profiles …"):
            try:
                fleet_payload = []
                for p in DEVICE_PROFILES:
                    hw2 = p.get("hardware", {})
                    fleet_payload.append({
                        "name":              p["name"],
                        "data_sensitivity":  p["data_sensitivity"],
                        "exposure_level":    p["exposure_level"],
                        "data_lifetime_yrs": p["data_lifetime_yrs"],
                        "threat_window":     p["threat_window"],
                        "adversary":         adv,
                        "hardware": {
                            "ram_kb":         min(hw2.get("ram_kb", 64), 2_000_000),
                            "cpu":            hw2.get("cpu", "unknown"),
                            "has_fpu":        hw2.get("has_fpu", False),
                            "bandwidth_kbps": hw2.get("bandwidth_kbps", 100),
                        },
                    })

                resp = requests.post(f"{PROD_API_URL}/simulate", json={"devices": fleet_payload}).json()
                fm   = resp["fleet_metrics"]
                results = resp["results"]

                st.markdown(f'<span class="api-badge badge-post">POST</span><code>/simulate</code>', unsafe_allow_html=True)

                # Fleet KPIs
                k1, k2, k3, k4, k5 = st.columns(5)
                k1.metric("Devices",       fm["device_count"])
                k2.metric("Avg QRI",       fm["avg_qri"])
                k3.metric("Critical",      fm["critical_count"])
                k4.metric("Compliance",    f"{fm['avg_compliance_score']}%")
                k5.metric("Total Time",    f"{fm['total_processing_ms']:.1f} ms")

                st.markdown("---")
                st.markdown("**Per-Device Results**")

                tier_c = {"LOW":"#10b981","MODERATE":"#f59e0b","ELEVATED":"#f97316","HIGH":"#ef4444","CRITICAL":"#dc2626"}
                level_border = {1:"#ef4444",3:"#f59e0b",5:"#10b981"}

                for r in results:
                    tc2 = tier_c.get(r["qri_tier"], "#94a3b8")
                    lb  = level_border.get(r["achieved_nist_level"], "#334155")
                    gap_badge = f'<span class="pill pill-red">gap {r["security_gap"]}</span>' if r["security_gap"] > 0 else '<span class="pill pill-green">compliant</span>'
                    st.markdown(f"""
                    <div style="background:#111827;border:1px solid #1e293b;
                                border-left:4px solid {tc2};border-radius:10px;
                                padding:.7rem 1.1rem;margin-bottom:.4rem;
                                display:flex;align-items:center;gap:12px;flex-wrap:wrap">
                      <div style="flex:3;color:#f1f5f9;font-weight:600;font-size:.88rem">{r['device']}</div>
                      <div style="flex:1;text-align:center">
                        <div style="color:{tc2};font-size:1rem;font-weight:700;
                                    font-family:'JetBrains Mono',monospace">{r['qri']}</div>
                        <div style="color:#64748b;font-size:.72rem">{r['qri_tier']}</div>
                      </div>
                      <div style="flex:3;font-family:'JetBrains Mono',monospace;
                                  font-size:.8rem;color:#38bdf8">{r['selected_algorithm']}</div>
                      <div style="flex:1;text-align:center">
                        <span style="color:{lb};font-weight:700">L{r['achieved_nist_level']}</span>
                        &nbsp;{gap_badge}
                      </div>
                      <div style="flex:1;text-align:right;color:#475569;font-size:.75rem">{r['processing_time_ms']:.1f} ms</div>
                    </div>
                    """, unsafe_allow_html=True)

                # QRI bar chart
                st.markdown("**QRI Distribution**")
                qdf = pd.DataFrame({
                    "Device": [r["device"].split(" ")[0] + "…" if len(r["device"]) > 20 else r["device"] for r in results],
                    "QRI":    [r["qri"] for r in results],
                })
                st.bar_chart(qdf.set_index("Device"), color="#6366f1")

                # Compliance timeline
                st.markdown("**NIST Compliance per Device**")
                cdf = pd.DataFrame({
                    "Device":     [r["device"][:22] for r in results],
                    "Achieved %": [r["achieved_nist_level"] / 5 * 100 for r in results],
                    "Required %": [min(r["required_nist_level"] / 5 * 100, 100) for r in results],
                })
                st.bar_chart(cdf.set_index("Device"), color=["#10b981", "#6366f1"])

            except Exception as ex:
                st.error(f"Error: {ex}")
                st.exception(ex)