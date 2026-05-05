# ================== decision_engine.py ==================

# ---------------------------------------------------------------------------
# Algorithm Catalogue (UPDATED with constraints)
# ---------------------------------------------------------------------------

ALGORITHM_CATALOGUE = {
    "hybrid_kyber512": {
        "label": "Hybrid RSA-2048 + Kyber-512",
        "mode": "Hybrid",
        "kem": "Kyber-512",
        "signature": "RSA-2048 (classical)",
        "security_level": "NIST Level 1",
        "network_cost": 3,
        "constraints": {"min_ram_kb": 32, "requires_fpu": False},
    },
    "kyber768_dilithium3": {
        "label": "Kyber-768 + Dilithium-3",
        "mode": "Pure PQC",
        "kem": "Kyber-768",
        "signature": "Dilithium-3",
        "network_cost": 3,
        "security_level": "NIST Level 3",
        "constraints": {"min_ram_kb": 128, "requires_fpu": False},
    },
    "kyber768_falcon512": {
        "label": "Kyber-768 + FALCON-512",
        "mode": "Pure PQC",
        "kem": "Kyber-768",
        "signature": "FALCON-512",
        "network_cost": 1,
        "security_level": "NIST Level 3",
        "constraints": {"min_ram_kb": 256, "requires_fpu": True},
    },
    "kyber1024_dilithium5": {
        "label": "Kyber-1024 + Dilithium-5",
        "mode": "High Assurance",
        "kem": "Kyber-1024",
        "signature": "Dilithium-5",
        "network_cost": 2,
        "security_level": "NIST Level 5",
        "constraints": {"min_ram_kb": 256, "requires_fpu": False},
    },
    "kyber1024_dilithium5_sphincs": {
        "label": "Kyber-1024 + Dilithium-5 + SPHINCS+",
        "mode": "Maximum Assurance",
        "kem": "Kyber-1024",
        "network_cost": 5,
        "signature": "Dilithium-5 + SPHINCS+",
        "security_level": "NIST Level 5",
        "constraints": {"min_ram_kb": 512, "requires_fpu": False},
    },
    "kyber512_constrained": {
        "label": "Kyber-512 (Constrained)",
        "mode": "Constrained Device",
        "kem": "Kyber-512",
        "signature": "Dilithium-2",
        "network_cost": 1,
        "security_level": "NIST Level 1",
        "constraints": {"min_ram_kb": 32, "requires_fpu": False},
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _required_security_level(qri: float, device: dict) -> float:
    """
    Compute required NIST security level (1–5) based on:
    - QRI (current risk)
    - data lifetime (future risk / HNDL)
    - adversary capability
    """

    # --- Base from QRI ---
    level = qri / 20   # maps 0–100 → 0–5

    # --- Future risk (HNDL effect) ---
    lifetime = device.get("data_lifetime_yrs", 0)

    if lifetime > 10:
        level += 1
    if lifetime > 20:
        level += 1

    # --- Adversary strength ---
    adversary = device.get("adversary", "medium")

    if adversary == "nation_state":
        level += 1.5
    elif adversary == "medium":
        level += 0.5

    return min(level, 5)
def _extract_level(security_str: str) -> int:
    for i in range(1, 6):
        if f"Level {i}" in security_str:
            return i
    return 1


def _check_constraints(algo: dict, hardware: dict):
    c = algo.get("constraints", {})

    if hardware["ram_kb"] < c.get("min_ram_kb", 0):
        return False, "Insufficient RAM"

    if c.get("requires_fpu", False) and not hardware.get("has_fpu", False):
        return False, "FPU required"

    return True, ""


def _score_algorithm(algo, qri, hardware, device):
    valid, reason = _check_constraints(algo, hardware)
    if not valid:
        return 0, {"valid": False, "reason": reason}

    required_level = _required_security_level(qri, device)
    algo_level = _extract_level(algo["security_level"])

    # -------------------------
    # Security Fit
    # -------------------------
    security_fit = 1 - abs(algo_level - required_level) / 5

    penalty = 0.4 if algo_level < required_level else 1.0

    # -------------------------
    # RAM Fit
    # -------------------------
    ram_req = algo["constraints"]["min_ram_kb"]
    ram_fit = min(hardware["ram_kb"] / ram_req, 1)

    # -------------------------
    # Bandwidth Fit
    # -------------------------
    bandwidth_fit = _bandwidth_fit(algo, hardware)

    # -------------------------
    # Final Score
    # -------------------------
    score = penalty * (
        0.6 * security_fit +
        0.2 * ram_fit +
        0.2 * bandwidth_fit
    )

    breakdown = {
        "valid": True,
        "required_level": round(required_level, 2),
        "algo_level": algo_level,
        "security_fit": round(security_fit, 3),
        "ram_fit": round(ram_fit, 3),
        "bandwidth_fit": round(bandwidth_fit, 3),
        "penalty": penalty,
        "final_score": round(score, 3)
    }

    return score, breakdown
def _bandwidth_fit(algo, hardware):
    """
    Compute how suitable the algorithm is for device bandwidth.
    Higher = better
    """

    bandwidth = hardware.get("bandwidth_kbps", 1000)
    cost = algo.get("network_cost", 3)

    # normalize bandwidth
    if bandwidth < 100:
        capacity = 1   # very constrained
    elif bandwidth < 1000:
        capacity = 3
    else:
        capacity = 5   # high bandwidth

    # fit: closer match is better
    return 1 - abs(cost - capacity) / 5
# ---------------------------------------------------------------------------
# NEW SCORING-BASED ENGINE
# ---------------------------------------------------------------------------

def select_algorithm_scored(qri: float, hardware: dict, device):
    scored = []
    rejected = []

    for key, algo in ALGORITHM_CATALOGUE.items():
        valid, reason = _check_constraints(algo, hardware)

        if not valid:
            rejected.append({"algorithm": key, "reason": reason})
            continue

        score, breakdown = _score_algorithm(algo, qri, hardware, device)
        scored.append((key, algo, score, breakdown))

    if not scored:
        return {
            "error": "No feasible algorithm",
            "rejected": rejected
        }

    scored.sort(key=lambda x: x[2], reverse=True)

    best_key, best_algo, best_score, best_breakdown = scored[0]

    best_level = _extract_level(best_algo["security_level"])
    required_level = _required_security_level(qri, device)

    if best_level < required_level:
        gap = round(required_level - best_level, 2)
        security_warning = f"SECURITY GAP: required level {required_level:.2f}, but only {best_level} achievable"
    else:
        gap = 0
        security_warning = ""

    return {
        "algorithm_key": best_key,
        "algorithm_info": best_algo,
        "score": round(best_score, 3),

        "required_level": round(required_level, 2),
        "achieved_level": best_level,
        "security_gap": gap,
        "warning": security_warning,

        "breakdown": best_breakdown,

        "alternatives": [
            {"key": k, "score": round(s, 3)}
            for k, _, s, _ in scored[1:3]
        ],

        "rejected": rejected,
    }
# ---------------------------------------------------------------------------
# LEGACY FUNCTION (unchanged)
# ---------------------------------------------------------------------------

def _qri_to_tier(qri: float) -> str:
    if qri < 30: return "LOW"
    elif qri < 50: return "MODERATE"
    elif qri < 70: return "ELEVATED"
    elif qri < 85: return "HIGH"
    else: return "CRITICAL"

def compute_capability_from_hardware(hardware: dict) -> float:
    """
    Convert structured hardware profile into a normalized 0–10 capability score.

    This is used by risk_engine (indirectly) and can also be used for analytics.
    """

    # --- RAM contribution (dominant factor for PQC feasibility) ---
    # 1MB RAM → score 10
    ram_score = min(hardware.get("ram_kb", 0) / 1024, 10)

    # --- CPU contribution ---
    cpu = hardware.get("cpu", "").lower()

    if "x86" in cpu:
        cpu_score = 3
    elif "a53" in cpu or "arm cortex-a" in cpu:
        cpu_score = 2.5
    elif "m4" in cpu:
        cpu_score = 2
    else:
        cpu_score = 1  # low-end MCU

    # --- FPU contribution ---
    fpu_score = 2 if hardware.get("has_fpu", False) else 0

    # --- Combine ---
    capability = ram_score + cpu_score + fpu_score

    return min(capability, 10)