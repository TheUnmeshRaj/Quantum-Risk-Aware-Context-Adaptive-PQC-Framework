import streamlit as st
import requests
from devices import DEVICE_PROFILES

st.set_page_config(layout="wide")
st.title("🔐 PQC Decision Dashboard")

API_URL = "http://127.0.0.1:8000/analyze"

# -------------------------------
# Helper: Render Device Panel
# -------------------------------

def render_device(device, idx):
    with st.container():
        st.subheader(device["name"])

        # Sliders
        s = st.slider(f"Sensitivity {idx}", 0.0, 10.0, device["data_sensitivity"], key=f"s{idx}")
        e = st.slider(f"Exposure {idx}", 0.0, 10.0, device["exposure_level"], key=f"e{idx}")
        l = st.number_input(f"Lifetime {idx}", 1, 30, int(device["data_lifetime_yrs"]), key=f"l{idx}")
        t = st.slider(f"Threat {idx}", 0.0, 10.0, device["threat_window"], key=f"t{idx}")

        adversary = st.selectbox(
            f"Adversary {idx}",
            ["low", "medium", "nation_state"],
            key=f"a{idx}"
        )

        st.markdown("**Hardware**")

        ram = st.number_input(f"RAM KB {idx}", 32, 2000000, 64, key=f"ram{idx}")
        cpu = st.text_input(f"CPU {idx}", "Cortex-M0", key=f"cpu{idx}")
        fpu = st.checkbox(f"FPU {idx}", key=f"fpu{idx}")
        bw = st.number_input(f"Bandwidth {idx}", 10, 1000000, 50, key=f"bw{idx}")

        return {
            "data_sensitivity": s,
            "exposure_level": e,
            "data_lifetime_yrs": l,
            "threat_window": t,
            "adversary": adversary,
            "ram_kb": ram,
            "cpu": cpu,
            "has_fpu": fpu,
            "bandwidth_kbps": bw
        }


# -------------------------------
# Layout: 3 Columns
# -------------------------------

cols = st.columns(3)

inputs = []

for i, col in enumerate(cols):
    if i < len(DEVICE_PROFILES):
        with col:
            inputs.append(render_device(DEVICE_PROFILES[i], i))
    else:
        inputs.append(None)

# -------------------------------
# Analyze Button
# -------------------------------

st.markdown("---")

if st.button("🚀 Run Analysis"):

    result_cols = st.columns(3)

    for i, device_input in enumerate(inputs):
        if device_input is None:
            continue

        response = requests.post(API_URL, json=device_input)
        data = response.json()

        risk = data["risk"]
        decision = data["decision"]

        with result_cols[i]:

            st.subheader(f"Result {i+1}")

            # -------------------------------
            # Risk Metrics
            # -------------------------------
            st.metric("QRI", risk["qri"])
            st.metric("Risk Tier", risk["qri_tier"])

            # -------------------------------
            # Algorithm Selection
            # -------------------------------
            st.success(f"Selected: {decision['algorithm_key']}")

            # -------------------------------
            # Security Gap Warning
            # -------------------------------
            if decision.get("security_gap", 0) > 0:
                st.error(decision.get("warning", "Security gap detected"))

            # -------------------------------
            # Levels
            # -------------------------------
            st.markdown("### 📊 Score Breakdown")

            bd = decision.get("breakdown", {})

            # st.write(f"Security Fit: {bd.get('security_fit')}")
            # st.write(f"RAM Fit: {bd.get('ram_fit')}")
            # st.write(f"Bandwidth Fit: {bd.get('bandwidth_fit')}")
            # st.write(f"Penalty: {bd.get('penalty')}")
            # st.write(f"Final Score: {bd.get('final_score')}")
            import pandas as pd

            bd = decision.get("breakdown", {})

            df = pd.DataFrame({
                "Component": ["Security", "RAM", "Bandwidth"],
                "Score": [
                    bd.get("security_fit", 0),
                    bd.get("ram_fit", 0),
                    bd.get("bandwidth_fit", 0)
                ]
            })

            st.bar_chart(df.set_index("Component"))
                                    # -------------------------------
            # Alternatives
            # -------------------------------
            st.markdown("**Alternatives**")
            for alt in decision.get("alternatives", []):
                st.write(f"- {alt['key']} (score: {alt['score']})")

            # -------------------------------
            # Rejected Algorithms
            # -------------------------------
            with st.expander("Rejected Algorithms"):
                for r in decision.get("rejected", []):
                    st.write(f"{r['algorithm']} → {r['reason']}")