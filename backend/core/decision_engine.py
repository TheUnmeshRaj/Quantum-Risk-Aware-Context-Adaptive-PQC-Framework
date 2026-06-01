"""
core/decision_engine.py
=======================
Production-grade PQC Algorithm Decision Engine.

Architecture
------------
  1. Constraint filtering   — hard-fail any algorithm the hardware cannot run
  2. Required level calc    — derive NIST security level needed from QRI + context
  3. Multi-factor scoring   — security fit, RAM fit, bandwidth fit, with penalties
  4. Full explainability    — every selection AND every rejection is explained

All catalogue data lives in core/constants.py — this module contains ONLY logic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from backend.core.constants import ALGORITHM_CATALOGUE, AlgorithmSpec
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── Internal typed result ─────────────────────────────────────────────────────

@dataclass
class AlgorithmScore:
    """Scoring result for a single candidate algorithm."""
    spec:            AlgorithmSpec
    security_fit:    float
    ram_fit:         float
    bandwidth_fit:   float
    penalty:         float
    final_score:     float
    required_level:  float
    reason:          str = ""


@dataclass
class DecisionResult:
    """Full typed decision output — serialised by the schema layer."""
    algorithm_key:       str
    algorithm_info:      dict
    score:               float
    required_level:      float
    achieved_level:      int
    security_gap:        float
    warning:             str
    reason:              str
    breakdown:           dict
    alternatives:        list[dict]
    rejected:            list[dict]
    processing_time_ms:  float


# ── Required security level ───────────────────────────────────────────────────

def _required_security_level(qri: float, device: dict) -> float:
    """
    Derive the minimum NIST security level (1.0–5.0) required for this device.

    Factors
    -------
    - QRI score          → base level (0–100 mapped to 0–5)
    - data_lifetime_yrs  → HNDL bump: >10yrs +1, >20yrs another +1
    - adversary          → nation_state +1.5, medium +0.5
    """
    level = qri / 20.0  # 0–100 → 0–5

    lifetime = device.get("data_lifetime_yrs", 0)
    if lifetime > 20:
        level += 2.0
        logger.debug("HNDL +2.0 (lifetime=%d yrs)", lifetime)
    elif lifetime > 10:
        level += 1.0
        logger.debug("HNDL +1.0 (lifetime=%d yrs)", lifetime)

    adversary = device.get("adversary", "medium")
    if adversary == "nation_state":
        level += 1.5
        logger.debug("Adversary bump +1.5 (nation_state)")
    elif adversary == "medium":
        level += 0.5

    return round(min(level, 5.0), 2)


# ── Constraint check ──────────────────────────────────────────────────────────

def _check_constraints(spec: AlgorithmSpec, hardware: dict) -> tuple[bool, str]:
    """Return (feasible, rejection_reason)."""
    ram = hardware.get("ram_kb", 0)
    if ram < spec.min_ram_kb:
        return False, (
            f"Insufficient RAM: device has {ram:,} KB, "
            f"{spec.label} requires ≥ {spec.min_ram_kb:,} KB"
        )
    if spec.requires_fpu and not hardware.get("has_fpu", False):
        return False, f"{spec.label} requires an FPU but device has none"
    return True, ""


# ── Per-algorithm scoring ─────────────────────────────────────────────────────

def _bandwidth_fit(spec: AlgorithmSpec, hardware: dict) -> float:
    bw = hardware.get("bandwidth_kbps", 1000)
    cost = spec.network_cost
    if bw < 100:     capacity = 1
    elif bw < 1_000: capacity = 3
    else:            capacity = 5
    return max(0.0, 1.0 - abs(cost - capacity) / 5.0)


def _score_algorithm(
    spec: AlgorithmSpec,
    qri: float,
    hardware: dict,
    device: dict,
    required_level: float,
) -> AlgorithmScore:
    """Compute a composite [0, 1] score for one algorithm candidate."""
    ram_req  = max(spec.min_ram_kb, 1)
    ram_fit  = min(hardware.get("ram_kb", 0) / ram_req, 1.0)

    sec_fit  = max(0.0, 1.0 - abs(spec.nist_level - required_level) / 5.0)
    bw_fit   = _bandwidth_fit(spec, hardware)

    # Hard penalty if algorithm is UNDER the required security level
    penalty = 0.3 if spec.nist_level < required_level else 1.0

    final_score = penalty * (0.6 * sec_fit + 0.25 * ram_fit + 0.15 * bw_fit)

    reason = (
        f"NIST L{spec.nist_level} vs required L{required_level:.1f}; "
        f"security_fit={sec_fit:.3f}, ram_fit={ram_fit:.3f}, "
        f"bandwidth_fit={bw_fit:.3f}, penalty={penalty:.1f}"
    )

    return AlgorithmScore(
        spec=spec,
        security_fit=round(sec_fit, 3),
        ram_fit=round(ram_fit, 3),
        bandwidth_fit=round(bw_fit, 3),
        penalty=penalty,
        final_score=round(final_score, 4),
        required_level=required_level,
        reason=reason,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def compute_capability_from_hardware(hardware: dict) -> float:
    """
    Derive a 0–10 device capability score from hardwars.

    Used by risk_engine and the migration simulator.
    """
    ram_score = min(hardware.get("ram_kb", 0) / 1_024.0, 10.0)

    cpu = hardware.get("cpu", "").lower()
    if "x86" in cpu:           cpu_score = 3.0
    elif "cortex-a" in cpu:    cpu_score = 2.5
    elif "m4" in cpu:          cpu_score = 2.0
    else:                      cpu_score = 1.0  # low-end MCU / MIPS

    fpu_score = 2.0 if hardware.get("has_fpu", False) else 0.0
    return round(min(ram_score + cpu_score + fpu_score, 10.0), 2)


def select_algorithm_scored(
    qri: float,
    hardware: dict,
    device: dict,
) -> DecisionResult:
    """
    Select the optimal PQC algorithm for a device.

    Parameters
    ----------
    qri      : Quantum Risk Index (0–100) from risk_engine.
    hardware : Hardware profile dict (ram_kb, cpu, has_fpu, bandwidth_kbps).
    device   : Full device dict (includes data_lifetime_yrs, adversary, name…).

    Returns
    -------
    DecisionResult  fully-typed object with selection + full explainability.
    """
    t0 = time.perf_counter()
    device_name = device.get("name", "<unnamed>")
    logger.info("Running decision engine for: %s (QRI=%.1f)", device_name, qri)

    required_level = _required_security_level(qri, device)
    logger.debug("Required NIST level: %.2f", required_level)

    scored: list[AlgorithmScore] = []
    rejected: list[dict] = []

    for key, spec in ALGORITHM_CATALOGUE.items():
        feasible, reason = _check_constraints(spec, hardware)
        if not feasible:
            logger.debug("Rejected '%s': %s", key, reason)
            rejected.append({"algorithm": key, "label": spec.label, "reason": reason})
            continue

        ascore = _score_algorithm(spec, qri, hardware, device, required_level)
        scored.append(ascore)
        logger.debug("Scored '%s': %.4f", key, ascore.final_score)

    if not scored:
        logger.error("No feasible algorithm found for device '%s'", device_name)
        elapsed = (time.perf_counter() - t0) * 1000
        return DecisionResult(
            algorithm_key="none",
            algorithm_info={},
            score=0.0,
            required_level=required_level,
            achieved_level=0,
            security_gap=required_level,
            warning="No feasible algorithm found given hardware constraints.",
            reason="All algorithms were rejected by hardware constraint filtering.",
            breakdown={
                "security_fit":   0.0,
                "ram_fit":        0.0,
                "bandwidth_fit":  0.0,
                "penalty":        0.0,
                "final_score":    0.0,
                "required_level": required_level,
            },
            alternatives=[],
            rejected=rejected,
            processing_time_ms=round(elapsed, 3),
        )

    scored.sort(key=lambda x: x.final_score, reverse=True)
    best = scored[0]

    # Security gap
    gap = max(0.0, round(required_level - best.spec.nist_level, 2))
    warning = (
        f"Security gap: required NIST L{required_level:.1f} but best achievable is "
        f"L{best.spec.nist_level} ({best.spec.label})"
    ) if gap > 0 else ""

    # Human-readable selection reason
    reason = _build_reason(best, device, required_level)

    elapsed = round((time.perf_counter() - t0) * 1000, 3)
    logger.info(
        "Selected '%s' (score=%.4f, level=%d) for '%s' in %.2f ms",
        best.spec.key, best.final_score, best.spec.nist_level, device_name, elapsed,
    )

    return DecisionResult(
        algorithm_key=best.spec.key,
        algorithm_info={
            "label":          best.spec.label,
            "mode":           best.spec.mode,
            "kem":            best.spec.kem,
            "signature":      best.spec.signature,
            "security_level": best.spec.security_level,
            "key_sizes":      best.spec.key_sizes,
            "latency_class":  best.spec.latency_class,
        },
        score=best.final_score,
        required_level=required_level,
        achieved_level=best.spec.nist_level,
        security_gap=gap,
        warning=warning,
        reason=reason,
        breakdown={
            "security_fit":   best.security_fit,
            "ram_fit":        best.ram_fit,
            "bandwidth_fit":  best.bandwidth_fit,
            "penalty":        best.penalty,
            "final_score":    best.final_score,
            "required_level": required_level,
        },
        alternatives=[
            {
                "key":   s.spec.key,
                "label": s.spec.label,
                "score": s.final_score,
                "level": s.spec.nist_level,
            }
            for s in scored[1:3]
        ],
        rejected=rejected,
        processing_time_ms=elapsed,
    )


def _build_reason(best: AlgorithmScore, device: dict, required_level: float) -> str:
    """Construct a human-readable natural-language rationale."""
    parts = []
    name    = device.get("name", "this device")
    adv     = device.get("adversary", "medium")
    lt      = device.get("data_lifetime_yrs", 0)
    spec    = best.spec

    parts.append(
        f"'{name}' requires NIST L{required_level:.1f} "
        f"(QRI-driven + {adv} adversary"
        + (f" + {lt}-year data lifetime" if lt > 0 else "")
        + ")."
    )
    parts.append(
        f"'{spec.label}' achieves NIST L{spec.nist_level} "
        f"with a composite score of {best.final_score:.4f}."
    )
    if best.penalty < 1.0:
        parts.append(
            "Note: a security-level penalty was applied — "
            "no fully-compliant algorithm fits the hardware constraints."
        )
    return " ".join(parts)
