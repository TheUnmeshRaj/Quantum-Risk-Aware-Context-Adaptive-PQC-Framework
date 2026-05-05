"""
risk_engine.py
==============
Quantum Risk Evaluation Engine

Computes the Quantum Risk Index (QRI) — a 0–100 score representing
how urgently a device or system needs post-quantum cryptographic protection.

Weight Justification
--------------------
The five input factors are weighted to reflect their relative contribution
to quantum-era risk, derived from NIST SP 800-30 risk assessment guidance:

  data_sensitivity  (30%) — the PRIMARY driver. If the data is not sensitive,
                            quantum risk is low regardless of other factors.
  data_lifetime     (25%) — directly determines "harvest now, decrypt later"
                            exposure. Long-lived data is already at risk today.
  threat_window     (20%) — how long the data must stay confidential. Long
                            windows overlap with realistic Q-Day timelines.
  exposure_level    (15%) — how reachable the system is to an adversary.
                            Air-gapped systems have lower interception risk.
  device_capability (10%) — inversely contributes. Weaker devices have fewer
                            algorithmic options, increasing migration urgency.
                            (Note: capability is INVERTED before weighting —
                             a low-capability device adds more risk.)
"""

WEIGHTS = {
    "data_sensitivity": 0.30,
    "data_lifetime":    0.25,
    "threat_window":    0.20,
    "exposure_level":   0.15,
    "device_capability": 0.10,   # will be inverted: (10 - capability)
}


def _validate(name: str, value: float, min_val=0.0, max_val=10.0) -> float:
    """Clamp and validate a factor score into the expected range."""
    if not (min_val <= value <= max_val):
        print(f"  [WARNING] '{name}' value {value} out of range [{min_val}, {max_val}]. Clamping.")
        value = max(min_val, min(max_val, value))
    return value


def _amplify(qri_raw: float, sensitivity: float, threat_window: float) -> float:
    """
    Non-linear amplifier: when BOTH sensitivity and threat_window are high,
    the combined risk is greater than the sum of parts — the 'harvest now,
    decrypt later' scenario is most acute in this quadrant.

    Amplification applies when sensitivity × threat_window > 40 (i.e., both
    are scored 6.3+ simultaneously). Capped at 100.
    """
    if sensitivity * threat_window > 40:
        return min(qri_raw * 1.20, 100.0)
    return qri_raw


def compute_qri(
    data_sensitivity: float,
    exposure_level: float,
    data_lifetime: float,
    threat_window: float,
    device_capability: float,
) -> dict:
    """
    Compute the Quantum Risk Index for a single device or system.

    Parameters
    ----------
    data_sensitivity  : 0–10  (0=public, 10=top-secret / national security)
    exposure_level    : 0–10  (0=air-gapped, 10=fully internet-facing)
    data_lifetime     : years, normalized to 0–10 (≥20 years maps to 10)
    threat_window     : 0–10  (0=hours, 10=30+ years confidentiality needed)
    device_capability : 0–10  (0=extremely constrained, 10=high-end server)

    Returns
    -------
    dict with:
        qri         — float, 0–100 final risk score
        qri_tier    — str, risk tier label
        factor_scores — dict of individual weighted contributions
        raw_score   — float, pre-amplification score
    """
    # Validate all inputs
    s = _validate("data_sensitivity",  data_sensitivity)
    e = _validate("exposure_level",    exposure_level)
    l = _validate("data_lifetime",     data_lifetime)
    t = _validate("threat_window",     threat_window)
    c = _validate("device_capability", device_capability)

    # Invert capability: weak device = higher risk contribution
    c_inv = 10.0 - c

    # Weighted contributions (each factor contributes 0–10, scaled by weight)
    contributions = {
        "data_sensitivity":  s   * WEIGHTS["data_sensitivity"],
        "data_lifetime":     l   * WEIGHTS["data_lifetime"],
        "threat_window":     t   * WEIGHTS["threat_window"],
        "exposure_level":    e   * WEIGHTS["exposure_level"],
        "device_capability": c_inv * WEIGHTS["device_capability"],
    }

    # Sum weighted factors → raw score on 0–10 scale, then scale to 0–100
    raw_score = sum(contributions.values()) * 10.0

    # Apply non-linear amplifier for high-risk combinations
    qri = _amplify(raw_score, s, t)

    # Assign tier
    tier = _get_tier(qri)

    return {
        "qri":            round(qri, 1),
        "qri_tier":       tier,
        "raw_score":      round(raw_score, 1),
        "amplified":      qri > raw_score,
        "factor_scores":  {k: round(v * 10, 2) for k, v in contributions.items()},
        "inputs": {
            "data_sensitivity":  s,
            "exposure_level":    e,
            "data_lifetime":     l,
            "threat_window":     t,
            "device_capability": c,
        },
    }


def _get_tier(qri: float) -> str:
    if qri < 30:
        return "LOW"
    elif qri < 50:
        return "MODERATE"
    elif qri < 70:
        return "ELEVATED"
    elif qri < 85:
        return "HIGH"
    else:
        return "CRITICAL"


def normalize_lifetime(years: float) -> float:
    """
    Convert a data lifetime in years to a 0–10 normalized score.
    Scale: 0 years → 0,  ≥20 years → 10
    This is a helper for device profile construction.
    """
    return min(years / 2.0, 10.0)
