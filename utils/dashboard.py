import streamlit as st
import requests
import pandas as pd
import numpy as np
from devices import DEVICE_PROFILES

st.set_page_config(layout="wide", page_title="Unysis PQC Platform", page_icon="🔐")

# ─────────────────────────────────────────────────────────────
# Global Styles
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
  }
  .stApp { background: #0a0f1e; }

  .block-container { padding: 1.5rem 2rem; }

  h1, h2, h3 { color: #e2e8f0 !important; }
  p, label, .stMarkdown { color: #94a3b8 !important; }

  /* ── Metric Cards ── */
  [data-testid="metric-container"] {
    background: linear-gradient(135deg, #111827 0%, #1e2a3a 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1rem 1.2rem;
  }
  [data-testid="metric-container"] label { color: #64748b !important; font-size: 0.75rem; }
  [data-testid="metric-container"] [data-testid="stMetricValue"] { color: #38bdf8 !important; font-family: 'JetBrains Mono', monospace; font-size: 1.5rem; }

  /* ── KPI Winner Card ── */
  .winner-card {
    background: linear-gradient(135deg, #0f3d2e 0%, #064e3b 40%, #065f46 100%);
    border: 1.5px solid #10b981;
    border-radius: 14px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 0.8rem;
  }
  .loser-card {
    background: linear-gradient(135deg, #1f1a1a 0%, #2d1515 100%);
    border: 1px solid #7f1d1d;
    border-radius: 14px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 0.8rem;
  }
  .neutral-card {
    background: linear-gradient(135deg, #1a1f2e 0%, #1e293b 100%);
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 0.8rem;
  }
  .card-title { font-size: 1rem; font-weight: 700; color: #f1f5f9 !important; margin-bottom: 0.3rem; }
  .card-stat  { font-size: 1.8rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .card-label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem; }

  /* ── Device Table ── */
  .device-row {
    display: flex; align-items: center; gap: 10px;
    background: #111827; border-radius: 10px;
    padding: 0.6rem 1rem; margin-bottom: 0.4rem;
    border-left: 4px solid;
  }
  .device-name { font-weight: 600; color: #e2e8f0; flex: 2; }
  .device-algo { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; flex: 3; }
  .device-comp { font-size: 0.75rem; color: #94a3b8; flex: 1; text-align: right; }

  /* ── Section Headers ── */
  .section-header {
    font-size: 1.1rem; font-weight: 700; color: #38bdf8;
    text-transform: uppercase; letter-spacing: 0.12em;
    border-bottom: 1px solid #1e3a5f; padding-bottom: 0.4rem;
    margin: 1.2rem 0 0.8rem;
  }

  /* ── Tabs ── */
  [data-baseweb="tab-list"] {
    background: #111827 !important; border-radius: 10px;
    padding: 4px; gap: 4px;
  }
  [data-baseweb="tab"] {
    color: #64748b !important; border-radius: 8px;
    font-weight: 600;
  }
  [aria-selected="true"][data-baseweb="tab"] {
    background: #1e3a5f !important; color: #38bdf8 !important;
  }

  /* ── Alerts ── */
  .stAlert { border-radius: 10px; }

  /* ── Expander ── */
  [data-testid="stExpander"] {
    background: #111827; border: 1px solid #1e2d3d; border-radius: 10px;
  }

  /* ── Progress bar ── */
  .stProgress > div > div { background: linear-gradient(90deg, #0ea5e9, #6366f1); border-radius: 99px; }

  hr { border-color: #1e293b; }
</style>
""", unsafe_allow_html=True)

st.title("🔐 Unysis · PQC Decision Platform")
st.caption("Quantum Risk Assessment, Algorithm Selection & Migration Strategy Analysis")

API_URL = "http://127.0.0.1:8000"

tab1, tab2, tab3 = st.tabs(["  ⚙️  Decision Engine  ", "  ⚛️  Quantum Attack Sim  ", "  📊  Migration Analysis  "])

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