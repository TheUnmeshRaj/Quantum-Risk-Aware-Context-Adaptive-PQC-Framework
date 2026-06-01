"""
models/schemas.py
=================
Pydantic request and response schemas for the Unysis PQC Framework API.

All API inputs and outputs pass through these models — guaranteeing
consistent, validated, self-documenting data at every boundary.
"""

from __future__ import annotations

from typing import Any, Optional
import time

from pydantic import BaseModel, Field, field_validator


# ═══════════════════════════════════════════════════════════
# REQUEST SCHEMAS
# ═══════════════════════════════════════════════════════════

class HardwareProfile(BaseModel):
    """Physical hardware constraints of the target device."""
    ram_kb:          int   = Field(..., gt=0,   description="Available RAM in kilobytes")
    cpu:             str   = Field(..., min_length=1, description="CPU model / family string")
    has_fpu:         bool  = Field(..., description="True if device has a hardware floating-point unit")
    bandwidth_kbps:  float = Field(..., gt=0,   description="Available network bandwidth in kbps")


class DeviceProfileRequest(BaseModel):
    """
    Full device profile used for QRI computation and algorithm selection.

    Example
    -------
    ```json
    {
      "name": "Hospital Patient Records DB",
      "data_sensitivity": 9.5,
      "exposure_level": 5.0,
      "data_lifetime_yrs": 25,
      "threat_window": 9.5,
      "adversary": "nation_state",
      "hardware": {
        "ram_kb": 128000000,
        "cpu": "x86-64 server",
        "has_fpu": true,
        "bandwidth_kbps": 10000000
      }
    }
    ```
    """
    name:               str           = Field("unnamed-device", description="Human-readable device label")
    description:        Optional[str] = Field(None, description="Optional context about the device's role")
    data_sensitivity:   float         = Field(..., ge=0.0, le=10.0, description="0=public, 10=top-secret")
    exposure_level:     float         = Field(..., ge=0.0, le=10.0, description="0=air-gapped, 10=fully internet-facing")
    data_lifetime_yrs:  float         = Field(..., ge=0,             description="Years data must remain confidential")
    threat_window:      float         = Field(..., ge=0.0, le=10.0,  description="0=hours, 10=30+ year confidentiality")
    adversary:          str           = Field(..., description="Threat actor: 'low' | 'medium' | 'nation_state'")
    hardware:           HardwareProfile

    @field_validator("adversary")
    @classmethod
    def _validate_adversary(cls, v: str) -> str:
        allowed = {"low", "medium", "nation_state"}
        if v not in allowed:
            raise ValueError(f"adversary must be one of {sorted(allowed)}, got '{v}'")
        return v


class SimulateRequest(BaseModel):
    """Batch simulation request — list of up to 50 device profiles."""
    devices: list[DeviceProfileRequest] = Field(..., min_length=1, max_length=50)


# ═══════════════════════════════════════════════════════════
# RESPONSE SCHEMAS
# ═══════════════════════════════════════════════════════════

class FactorScores(BaseModel):
    """Weighted contribution of each QRI factor (0–10 scale)."""
    data_sensitivity:  float
    data_lifetime:     float
    threat_window:     float
    exposure_level:    float
    device_capability: float


class QRIResult(BaseModel):
    """Quantum Risk Index computation output."""
    qri:           float = Field(..., description="Final risk score 0–100")
    qri_tier:      str   = Field(..., description="LOW | MODERATE | ELEVATED | HIGH | CRITICAL")
    raw_score:     float = Field(..., description="Pre-amplification score")
    amplified:     bool  = Field(..., description="True if HNDL amplifier fired")
    factor_scores: FactorScores


class ScoreBreakdown(BaseModel):
    """Multi-factor scoring breakdown for the selected algorithm."""
    security_fit:   float
    ram_fit:        float
    bandwidth_fit:  float
    penalty:        float
    final_score:    float
    required_level: float


class AlgorithmAlternative(BaseModel):
    key:   str
    label: str
    score: float
    level: int


class RejectedAlgorithm(BaseModel):
    algorithm: str
    label:     str
    reason:    str


class ConstraintsSummary(BaseModel):
    """Hardware constraints passed to the decision engine."""
    ram_kb:           int
    has_fpu:          bool
    bandwidth_kbps:   float
    capability_score: float


class AnalyzeResponse(BaseModel):
    """
    Unified response for POST /analyze and each item in POST /simulate.

    This is the canonical output schema — all other endpoints reuse subsets.
    """
    device:             str
    qri:                float
    qri_tier:           str
    selected_algorithm: str
    mode:               str
    security_level:     str
    score:              float
    required_nist_level: float
    achieved_nist_level: int
    security_gap:        float
    warning:             str
    reason:              str
    alternatives:        list[AlgorithmAlternative]
    rejected:            list[RejectedAlgorithm]
    constraints:         ConstraintsSummary
    breakdown:           ScoreBreakdown
    processing_time_ms:  float
    timestamp:           float = Field(default_factory=time.time)


class FleetMetrics(BaseModel):
    """Aggregate metrics for a batch /simulate run."""
    device_count:           int
    avg_qri:                float
    max_qri:                float
    min_qri:                float
    critical_count:         int
    high_count:             int
    avg_compliance_score:   float   # mean achieved NIST level as % of L5
    total_processing_ms:    float


class SimulateResponse(BaseModel):
    """Response for POST /simulate — per-device results + fleet-level metrics."""
    results:      list[AnalyzeResponse]
    fleet_metrics: FleetMetrics


class ExplainResponse(BaseModel):
    """Response for GET /explain — step-by-step decision walkthrough."""
    device:          str
    qri:             float
    required_level:  float
    step_by_step:    list[str]
    selected:        str
    selected_reason: str
    alternatives:    list[AlgorithmAlternative]
    rejected:        list[RejectedAlgorithm]
    timestamp:       float = Field(default_factory=time.time)


class HealthResponse(BaseModel):
    """GET /health response."""
    status:     str
    service:    str
    version:    str
    uptime_sec: float


# ═══════════════════════════════════════════════════════════
# DISCOVERY SCHEMAS
# ═══════════════════════════════════════════════════════════

class DiscoverRequest(BaseModel):
    """POST /discover request body."""
    subnets: Optional[str] = Field("192.168.1.0/24", description="IP subnets to scan")
    speed:   Optional[str] = Field("standard", description="standard | turbo")


class DiscoveredDevice(BaseModel):
    """Discovered host details and full QRI analysis response."""
    ip:       str
    mac:      str
    analysis: AnalyzeResponse


class DiscoverResponse(BaseModel):
    """POST /discover response containing all active network hosts."""
    devices: list[DiscoveredDevice]

