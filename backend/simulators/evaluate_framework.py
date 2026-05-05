"""
evaluate_framework.py
=====================
Advanced PQC Migration Strategy Evaluation Engine

Simulates three enterprise deployment strategies over a 10-step quantum
threat escalation timeline, capturing:
  - Security outcomes (breaches, crashes)
  - Financial cost model (migration cost vs. breach cost)
  - Compliance scoring (NIST PQC readiness level)
  - Per-device granular analytics
  - Cumulative reward (security vs. overhead tradeoff)

Strategies
----------
  status_quo  : Keep RSA-2048 everywhere. Never migrate.
  paranoid    : Immediately deploy the heaviest PQC suite on every device.
  adaptive    : Our framework — context-aware, device-aware, threat-aware.
"""

import numpy as np
import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from .migration_env import PQCMigrationEnv, CRYPTO_REQUIREMENTS, CRYPTO_SECURITY

# ─────────────────────────────────────────────────────────────
# Cost Model
# ─────────────────────────────────────────────────────────────

# One-time migration cost per device per crypto tier (USD equivalent units)
MIGRATION_COST = {
    0: 0,     # RSA - no migration
    1: 500,   # Hybrid
    2: 700,   # Kyber-512
    3: 1200,  # Kyber-768
    4: 2000,  # Kyber-1024 + Sphincs
}

 

# Cost of a successful breach per device (based on data sensitivity tier)
# Indexed by device index (maps to DEVICE_PROFILES order)
BREACH_COST_PER_DEVICE = [
    5_000,     # IoT Temp Sensor (low sensitivity)
    250_000,   # Developer Workstation (IP/credentials)
    180_000,   # Public API Server (PII + auth tokens)
    2_000_000, # Hospital Records DB (PHI / HIPAA)
    800_000,   # Industrial PLC (critical infrastructure)
    30_000,    # Smart Home Hub (consumer)
]

# Cost of crashing a device (operational downtime)
CRASH_COST_PER_DEVICE = [
    1_000,    # IoT Temp Sensor
    15_000,   # Developer Workstation
    50_000,   # Public API Server (revenue loss per hour)
    100_000,  # Hospital Records DB (patient safety, fines)
    500_000,  # Industrial PLC (SCADA downtime at facility)
    2_000,    # Smart Home Hub
]

# NIST PQC compliance score: how close to full NIST compliance per crypto choice
COMPLIANCE_SCORE = {
    0: 0,   # RSA-2048: NOT compliant with NIST PQC migration guidance
    1: 30,  # Hybrid: partial (transitional)
    2: 65,  # Kyber-512: NIST L1 certified
    3: 85,  # Kyber-768: NIST L3 certified
    4: 100, # Kyber-1024 + Sphincs: NIST L5 maximum assurance
}

# Human-readable names for crypto choices
CRYPTO_NAMES = {
    0: "RSA-2048",
    1: "Hybrid RSA+Kyber-512",
    2: "Kyber-512 / Dilithium-2",
    3: "Kyber-768 / Dilithium-3",
    4: "Kyber-1024 / SPHINCS+",
}

# ─────────────────────────────────────────────────────────────
# Adaptive Decision Logic
# ─────────────────────────────────────────────────────────────

def _adaptive_choose(cap: float, threat_level: int, device_idx: int) -> int:
    """
    Context-aware algorithm selection — proactive threat anticipation.

    Key design: deploys one threat-level AHEAD of current threat to prevent
    breaches during escalation. This is what makes it 'adaptive' vs reactive.
    High-value devices get an additional urgency boost.
    """
    high_value_devices = {3, 4}  # Hospital DB, Industrial PLC
    urgency_boost = 1 if device_idx in high_value_devices else 0

    # Look one step ahead — anticipate the NEXT threat level
    anticipated_threat = min(5, threat_level + 1 + urgency_boost)

    if anticipated_threat >= 4:
        if cap >= 8:   return 4
        if cap >= 5:   return 3
        if cap >= 2:   return 2
        return 1
    elif anticipated_threat >= 3:
        if cap >= 5:   return 3
        if cap >= 2:   return 2
        return 1
    elif anticipated_threat >= 2:
        if cap >= 5:   return 2
        if cap >= 2:   return 2
        return 1
    elif anticipated_threat >= 1:
        if cap >= 2:   return 1
        return 1
    else:
        # Threat=0: baseline — always at least hybrid for high-value
        if device_idx in high_value_devices:
            return 2 if cap >= 2 else 1
        return 1 if cap >= 2 else 0


# ─────────────────────────────────────────────────────────────
# Core Agent Runner
# ─────────────────────────────────────────────────────────────

def run_agent(env: PQCMigrationEnv, strategy: str):
    """
    Run one full episode (10 steps) under a given strategy.
    Returns total reward + granular history.
    """
    obs, _ = env.reset()
    terminated = False
    step_idx = 0

    total_reward = 0
    total_cost = 0

    # Track last deployed tier per device to charge migration cost only once per upgrade
    last_deployed = [-1] * env.num_devices

    history = {
        "reward": [],
        "hacked": [],
        "crashed": [],
        "threat_level": [],
        "total_cost": [],
        "compliance": [],
        "per_device_crypto": [],   # list of lists
    }

    while not terminated:
        num_devices = env.num_devices
        threat_level = env.threat_level
        action = []

        for i in range(num_devices):
            cap = env.device_capabilities[i]
            if strategy == "status_quo":
                action.append(0)
            elif strategy == "paranoid":
                # Paranoid: highest tier the device can actually run (capped by capability)
                # Tier 4 needs cap>=8, Tier 3 needs cap>=5, Tier 2 needs cap>=2, else Tier 1
                if cap >= 8:   action.append(4)
                elif cap >= 5: action.append(3)
                elif cap >= 2: action.append(2)
                else:          action.append(1)
            elif strategy == "adaptive":
                action.append(_adaptive_choose(cap, threat_level, i))

        obs, reward, terminated, truncated, info = env.step(action)
        total_reward += reward

        # ── Financial cost — one-time per device per tier upgrade only ──
        step_cost = 0
        for i, crypto in enumerate(action):
            if crypto > last_deployed[i]:
                # New deployment or upgrade — charge migration cost once
                step_cost += MIGRATION_COST.get(crypto, 0)
                last_deployed[i] = crypto

        # Track per-device breach/crash costs
        n = max(num_devices, 1)
        avg_breach = sum(BREACH_COST_PER_DEVICE[:n]) / n
        avg_crash  = sum(CRASH_COST_PER_DEVICE[:n]) / n
        breach_cost = info["hacked"]  * avg_breach
        crash_cost  = info["crashed"] * avg_crash
        step_cost += breach_cost + crash_cost
        total_cost += step_cost

        # ── Compliance score (mean across devices) ──
        compliance = np.mean([COMPLIANCE_SCORE[c] for c in action])

        history["reward"].append(reward)
        history["hacked"].append(info["hacked"])
        history["crashed"].append(info["crashed"])
        history["threat_level"].append(info["threat_level"])
        history["total_cost"].append(round(step_cost, 2))
        history["compliance"].append(round(compliance, 2))
        history["per_device_crypto"].append(list(action))

        step_idx += 1

    return total_reward, total_cost, history


# ─────────────────────────────────────────────────────────────
# Main Evaluation Entry Point
# ─────────────────────────────────────────────────────────────

def run_evaluation():
    """
    Runs the full simulation across all three strategies.
    Returns a rich result dict suitable for API serialization.
    """
    env = PQCMigrationEnv()
    strategies = ["status_quo", "paranoid", "adaptive"]
    results = {}

    for s in strategies:
        reward, total_cost, hist = run_agent(env, strategy=s)

        # Derived metrics
        total_breaches = sum(hist["hacked"])
        total_crashes  = sum(hist["crashed"])
        final_compliance = hist["compliance"][-1] if hist["compliance"] else 0
        avg_compliance   = round(float(np.mean(hist["compliance"])), 2)

        # Per-device final crypto allocation
        final_allocation = hist["per_device_crypto"][-1] if hist["per_device_crypto"] else []
        device_names = [d["name"] for d in env.devices]

        per_device_summary = []
        for i, (name, crypto_idx) in enumerate(zip(device_names, final_allocation)):
            cap = env.device_capabilities[i]
            per_device_summary.append({
                "device": name,
                "capability": cap,
                "final_crypto": CRYPTO_NAMES[crypto_idx],
                "final_crypto_idx": crypto_idx,
                "compliance": COMPLIANCE_SCORE[crypto_idx],
            })

        # Efficiency ratio: reward earned per $1000 spent
        efficiency = round(reward / max(total_cost / 1000, 1), 4)

        results[s] = {
            "total_reward":      reward,
            "total_cost_usd":    round(total_cost, 2),
            "efficiency_ratio":  efficiency,
            "total_breaches":    total_breaches,
            "total_crashes":     total_crashes,
            "avg_compliance":    avg_compliance,
            "final_compliance":  round(float(final_compliance), 2),
            "per_device":        per_device_summary,
            "hist": {
                "reward":         hist["reward"],
                "hacked":         hist["hacked"],
                "crashed":        hist["crashed"],
                "threat_level":   hist["threat_level"],
                "total_cost":     hist["total_cost"],
                "compliance":     hist["compliance"],
            }
        }

    return results


if __name__ == "__main__":
    res = run_evaluation()
    for strategy, data in res.items():
        print(f"\n{'='*50}")
        print(f"  Strategy: {strategy.upper()}")
        print(f"  Total Reward:     {data['total_reward']}")
        print(f"  Total Cost (USD): ${data['total_cost_usd']:,.0f}")
        print(f"  Breaches:         {data['total_breaches']}")
        print(f"  Crashes:          {data['total_crashes']}")
        print(f"  Avg Compliance:   {data['avg_compliance']}%")
        print(f"  Efficiency Ratio: {data['efficiency_ratio']}")
