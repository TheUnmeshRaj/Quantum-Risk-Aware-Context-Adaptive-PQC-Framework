"""
core/risk_engine.py
===================
Quantum Risk Index (QRI) computation engine.

Weight Justification (NIST SP 800-30 derived)
----------------------------------------------
  data_sensitivity  30%  — primary driver; low sensitivity → low quantum risk
  data_lifetime     25%  — HNDL exposure: data encrypted today may be decrypted later
  threat_window     20%  — confidentiality lifetime vs Q-Day timeline overlap
  exposure_level    15%  — attack surface; air-gapped systems have lower interception risk
  device_capability 10%  — inverted: weaker device = fewer algorithm choices = higher urgency
-----------------------------------------------
"""

from __future__ import annotations

from backend.utils.logger import get_logger

logger = get_logger(__name__)

WEIGHTS = {
    "data_sensitivity":   0.30,
    "data_lifetime":      0.25,
    "threat_window":      0.20,
    "exposure_level":     0.15,
    "device_capability":  0.10,  
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clamp(name: str, value: float, lo: float = 0.0, hi: float = 10.0) -> float:
    if not (lo <= value <= hi):
        logger.warning("'%s' value %.2f out of range [%.1f, %.1f] — clamping", name, value, lo, hi)
        return max(lo, min(hi, value))
    return value


def _amplify(raw: float, sensitivity: float, threat_window: float) -> float:
    """
    Non-linear amplifier: when BOTH sensitivity and threat_window exceed 6.3+
    (product > 40), the combined risk exceeds the linear sum.
    This models the 'harvest now, decrypt later' (HNDL) worst-case quadrant.
    """
    if sensitivity * threat_window > 40:
        amplified = min(raw * 1.20, 100.0)
        logger.debug("HNDL amplifier triggered: %.1f → %.1f", raw, amplified)
        return amplified
    return raw


def normalize_lifetime(years: float) -> float:
    """Convert data lifetime in years to a 0–10 normalised score (≥20 yrs → 10)."""
    return min(years / 2.0, 10.0)


# ── Public API ────────────────────────────────────────────────────────────────

def compute_qri(
    data_sensitivity:  float,
    exposure_level:    float,
    data_lifetime:     float,
    threat_window:     float,
    device_capability: float,
) -> dict:
    """
    Compute the Quantum Risk Index for a single device.

    Parameters
    ----------
    data_sensitivity  : 0–10  (0 = public data, 10 = top-secret)
    exposure_level    : 0–10  (0 = air-gapped, 10 = fully internet-facing)
    data_lifetime     : 0–10  normalised (use normalize_lifetime() for raw years)
    threat_window     : 0–10  (0 = hours, 10 = 30+ years confidentiality required)
    device_capability : 0–10  (0 = extremely constrained MCU, 10 = high-end server)

    Returns
    -------
    dict  with keys: qri, qri_tier, raw_score, amplified, factor_scores, inputs
    """
    s = _clamp("data_sensitivity",  data_sensitivity)
    e = _clamp("exposure_level",    exposure_level)
    l = _clamp("data_lifetime",     data_lifetime)
    t = _clamp("threat_window",     threat_window)
    c = _clamp("device_capability", device_capability)

    c_inv = 10.0 - c  # weaker device = higher risk contribution

    contributions = {
        "data_sensitivity":  s     * WEIGHTS["data_sensitivity"],
        "data_lifetime":     l     * WEIGHTS["data_lifetime"],
        "threat_window":     t     * WEIGHTS["threat_window"],
        "exposure_level":    e     * WEIGHTS["exposure_level"],
        "device_capability": c_inv * WEIGHTS["device_capability"],
    }

    raw_score = sum(contributions.values()) * 10.0
    qri       = _amplify(raw_score, s, t)
    tier      = _get_tier(qri)

    logger.info(
        "QRI computed: %.1f (%s) | sensitivity=%.1f exposure=%.1f lifetime=%.1f "
        "threat=%.1f cap=%.1f",
        qri, tier, s, e, l, t, c,
    )

    return {
        "qri":          round(qri, 1),
        "qri_tier":     tier,
        "raw_score":    round(raw_score, 1),
        "amplified":    qri > raw_score,
        "factor_scores": {k: round(v * 10, 2) for k, v in contributions.items()},
        "inputs": {
            "data_sensitivity":  s,
            "exposure_level":    e,
            "data_lifetime":     l,
            "threat_window":     t,
            "device_capability": c,
        },
    }


def _get_tier(qri: float) -> str:
    if qri < 30:   return "LOW"
    if qri < 50:   return "MODERATE"
    if qri < 70:   return "ELEVATED"
    if qri < 85:   return "HIGH"
    return "CRITICAL"
