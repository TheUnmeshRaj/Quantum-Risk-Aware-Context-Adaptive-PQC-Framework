"""
simulation/evaluator.py
=======================
Batch device evaluation engine.

Responsibilities
----------------
  - Run the full QRI + decision pipeline on a list of devices
  - Compute fleet-level aggregate metrics
  - Report per-device latency
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from backend.core.risk_engine import compute_qri, normalize_lifetime
from backend.core.decision_engine import select_algorithm_scored, compute_capability_from_hardware
from backend.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DeviceEvalResult:
    name:               str
    qri:                float
    qri_tier:           str
    selected_algorithm: str
    achieved_level:     int
    required_level:     float
    security_gap:       float
    processing_ms:      float


def evaluate_fleet(devices: list[dict]) -> tuple[list[DeviceEvalResult], dict]:
    """
    Evaluate a list of device profiles end-to-end.

    Returns
    -------
    (results, fleet_metrics)
    """
    logger.info("Starting fleet evaluation: %d devices", len(devices))
    results = []
    t_fleet_start = time.perf_counter()

    for dev in devices:
        hw = dev.get("hardware", {})
        cap = compute_capability_from_hardware(hw)

        qri_out = compute_qri(
            data_sensitivity  = dev["data_sensitivity"],
            exposure_level    = dev["exposure_level"],
            data_lifetime     = normalize_lifetime(dev["data_lifetime_yrs"]),
            threat_window     = dev["threat_window"],
            device_capability = cap,
        )

        decision = select_algorithm_scored(
            qri      = qri_out["qri"],
            hardware = {
                "ram_kb":         hw.get("ram_kb", 64),
                "cpu":            hw.get("cpu", ""),
                "has_fpu":        hw.get("has_fpu", False),
                "bandwidth_kbps": hw.get("bandwidth_kbps", 100),
            },
            device = dev,
        )

        results.append(DeviceEvalResult(
            name               = dev.get("name", "unnamed"),
            qri                = qri_out["qri"],
            qri_tier           = qri_out["qri_tier"],
            selected_algorithm = decision.algorithm_key,
            achieved_level     = decision.achieved_level,
            required_level     = decision.required_level,
            security_gap       = decision.security_gap,
            processing_ms      = decision.processing_time_ms,
        ))

    total_ms = round((time.perf_counter() - t_fleet_start) * 1000, 2)
    qri_values = [r.qri for r in results]

    tier_map = {"LOW": 0, "MODERATE": 1, "ELEVATED": 2, "HIGH": 3, "CRITICAL": 4}
    fleet_metrics = {
        "device_count":         len(results),
        "avg_qri":              round(sum(qri_values) / len(qri_values), 1),
        "max_qri":              round(max(qri_values), 1),
        "min_qri":              round(min(qri_values), 1),
        "critical_count":       sum(1 for r in results if r.qri_tier == "CRITICAL"),
        "high_count":           sum(1 for r in results if r.qri_tier == "HIGH"),
        "avg_compliance_score": round(
            sum(r.achieved_level / 5.0 * 100 for r in results) / len(results), 1
        ),
        "total_processing_ms":  total_ms,
    }

    logger.info(
        "Fleet evaluation complete: avg_qri=%.1f, critical=%d, total_ms=%.1f",
        fleet_metrics["avg_qri"], fleet_metrics["critical_count"], total_ms,
    )
    return results, fleet_metrics
