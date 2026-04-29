import requests, json

base = "http://127.0.0.1:8001"
hospital = {
    "name": "Hospital Patient Records DB",
    "data_sensitivity": 9.5, "exposure_level": 5.0,
    "data_lifetime_yrs": 25, "threat_window": 9.5,
    "adversary": "nation_state",
    "hardware": {"ram_kb": 128000000, "cpu": "x86-64 server", "has_fpu": True, "bandwidth_kbps": 10000000}
}
iot = {
    "name": "IoT Temperature Sensor",
    "data_sensitivity": 3.0, "exposure_level": 7.0,
    "data_lifetime_yrs": 10, "threat_window": 5.0,
    "adversary": "medium",
    "hardware": {"ram_kb": 64, "cpu": "ARM Cortex-M0+", "has_fpu": False, "bandwidth_kbps": 50}
}

print("=== /health ===")
r = requests.get(f"{base}/health")
print(json.dumps(r.json(), indent=2))

print("\n=== /analyze (Hospital) ===")
r = requests.post(f"{base}/analyze", json=hospital)
d = r.json()
print(f"  QRI       : {d['qri']} ({d['qri_tier']})")
print(f"  Selected  : {d['selected_algorithm']}")
print(f"  Required L: {d['required_nist_level']}  Achieved L: {d['achieved_nist_level']}")
print(f"  Gap       : {d['security_gap']}")
print(f"  Reason    : {d['reason']}")
print(f"  Rejected  : {[x['algorithm'] for x in d['rejected']]}")
print(f"  Breakdown : {d['breakdown']}")

print("\n=== /simulate (batch) ===")
r = requests.post(f"{base}/simulate", json={"devices": [hospital, iot]})
d = r.json()
print(json.dumps(d["fleet_metrics"], indent=2))

print("\n=== /explain (IoT) ===")
r = requests.post(f"{base}/explain", json=iot)
d = r.json()
for step in d["step_by_step"]:
    print(" ", step)
