"""
utils/validation.py
===================
Input validation layer for the UNISYS PQC Framework.

All functions raise ``fastapi.HTTPException`` (400) so callers
don't need to catch or re-wrap errors.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Field bounds ──────────────────────────────────────────────────────────────
_SCORE_FIELDS = {
    "data_sensitivity":  (0.0, 10.0),
    "exposure_level":    (0.0, 10.0),
    "threat_window":     (0.0, 10.0),
}
_ADVERSARY_VALUES = {"low", "medium", "nation_state"}
_REQUIRED_HW_FIELDS = {"ram_kb", "cpu", "has_fpu", "bandwidth_kbps"}


def validate_device_input(device: dict[str, Any]) -> None:
    """
    Validate a raw device profile dict.

    Raises
    ------
    HTTPException(400)  if any field is missing, out of range, or wrong type.
    """
    name = device.get("name", "<unnamed>")
    logger.debug("Validating device input: %s", name)

    # ── Required top-level fields ──
    required = {"data_sensitivity", "exposure_level", "data_lifetime_yrs",
                "threat_window", "adversary", "hardware"}
    missing = required - device.keys()
    if missing:
        msg = f"Device '{name}' is missing required fields: {sorted(missing)}"
        logger.warning(msg)
        raise HTTPException(status_code=400, detail=msg)

    # ── Score range validation ──
    for field, (lo, hi) in _SCORE_FIELDS.items():
        val = device[field]
        if not isinstance(val, (int, float)):
            raise HTTPException(
                status_code=400,
                detail=f"Field '{field}' must be numeric, got {type(val).__name__}"
            )
        if not (lo <= val <= hi):
            raise HTTPException(
                status_code=400,
                detail=f"Field '{field}' = {val} is out of range [{lo}, {hi}]"
            )

    # ── Lifetime ──
    lt = device["data_lifetime_yrs"]
    if not isinstance(lt, (int, float)) or lt < 0:
        raise HTTPException(
            status_code=400,
            detail=f"'data_lifetime_yrs' must be a non-negative number, got {lt!r}"
        )

    # ── Adversary ──
    adv = device["adversary"]
    if adv not in _ADVERSARY_VALUES:
        raise HTTPException(
            status_code=400,
            detail=f"'adversary' must be one of {sorted(_ADVERSARY_VALUES)}, got {adv!r}"
        )

    # ── Hardware sub-dict ──
    hw = device["hardware"]
    if not isinstance(hw, dict):
        raise HTTPException(status_code=400, detail="'hardware' must be an object")

    hw_missing = _REQUIRED_HW_FIELDS - hw.keys()
    if hw_missing:
        raise HTTPException(
            status_code=400,
            detail=f"'hardware' is missing fields: {sorted(hw_missing)}"
        )

    if not isinstance(hw["ram_kb"], int) or hw["ram_kb"] < 1:
        raise HTTPException(status_code=400, detail="'hardware.ram_kb' must be a positive integer")

    if not isinstance(hw["has_fpu"], bool):
        raise HTTPException(status_code=400, detail="'hardware.has_fpu' must be a boolean")

    if not isinstance(hw["bandwidth_kbps"], (int, float)) or hw["bandwidth_kbps"] <= 0:
        raise HTTPException(status_code=400, detail="'hardware.bandwidth_kbps' must be a positive number")

    logger.debug("Validation passed for device: %s", name)


def validate_batch_input(devices: list[dict[str, Any]]) -> None:
    """Validate a list of device profiles for the /simulate endpoint."""
    if not devices:
        raise HTTPException(status_code=400, detail="Device list must not be empty")
    if len(devices) > 50:
        raise HTTPException(status_code=400, detail="Batch size must not exceed 50 devices")
    for i, dev in enumerate(devices):
        try:
            validate_device_input(dev)
        except HTTPException as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Device[{i}] ({dev.get('name','?')}): {exc.detail}"
            ) from exc
