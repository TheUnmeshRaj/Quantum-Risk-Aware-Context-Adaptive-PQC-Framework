import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI
from pydantic import BaseModel

from utils.decision_engine import (
    select_algorithm_scored,
    compute_capability_from_hardware
)
from utils.risk_engine import compute_qri
from simulators.quantum_attack import run_simulation as run_qa_simulation
from simulators.evaluate_framework import run_evaluation

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


# -------------------------------
# Simulation Endpoints
# -------------------------------

@app.get("/simulate/quantum_attack")
def simulate_quantum_attack():
    return run_qa_simulation(2048)


@app.get("/simulate/migration")
def simulate_migration():
    return run_evaluation()