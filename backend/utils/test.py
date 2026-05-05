from backend.utils.devices import DEVICE_PROFILES
from backend.utils.risk_engine import compute_qri
from backend.utils.decision_engine import select_algorithm_scored, compute_capability_from_hardware

device = DEVICE_PROFILES[0]
capability = compute_capability_from_hardware(device["hardware"])
risk = compute_qri(
    device["data_sensitivity"],
    device["exposure_level"],
    device["data_lifetime_yrs"],
    device["threat_window"],
    capability,
)

result = select_algorithm_scored(
    risk["qri"],
    device["hardware"],
    device   # NEW
)
print(result)