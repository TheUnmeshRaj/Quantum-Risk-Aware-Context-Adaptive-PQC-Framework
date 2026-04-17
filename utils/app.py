from fastapi import FastAPI
from pydantic import BaseModel

from decision_engine import (
    select_algorithm_scored,
    compute_capability_from_hardware
)
from risk_engine import compute_qri

app = FastAPI(title="PQC Decision Engine")


# -------------------------------
# Request Model
# -------------------------------

class DeviceInput(BaseModel):
    data_sensitivity: float
    exposure_level: float
    data_lifetime_yrs: float
    threat_window: float
    adversary: str

    # hardware
    ram_kb: int
    cpu: str
    has_fpu: bool
    bandwidth_kbps: int


# -------------------------------
# API Endpoint
# -------------------------------

@app.post("/analyze")
def analyze_device(device: DeviceInput):

    hardware = {
        "ram_kb": device.ram_kb,
        "cpu": device.cpu,
        "has_fpu": device.has_fpu,
        "bandwidth_kbps": device.bandwidth_kbps
    }

    capability = compute_capability_from_hardware(hardware)

    risk = compute_qri(
        device.data_sensitivity,
        device.exposure_level,
        device.data_lifetime_yrs,
        device.threat_window,
        capability
    )

    result = select_algorithm_scored(
        risk["qri"],
        hardware,
        device.dict()
    )

    return {
        "risk": risk,
        "decision": result
    }