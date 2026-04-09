"""
devices.py
==========
Device Profile Registry

Each profile represents a real-world device type in a smart digital ecosystem.
Parameter values are chosen to reflect realistic deployment characteristics.

Field Descriptions
------------------
name              : Human-readable device label
description       : Brief context about the device's role
data_sensitivity  : 0–10. How damaging is exposure of this device's data?
exposure_level    : 0–10. How reachable is this device to an external adversary?
data_lifetime_yrs : How many years must this data remain confidential?
threat_window     : 0–10. How long does the data need protection?
device_capability : 0–10. Compute/memory capability (0=extremely constrained).
notes             : Human-readable rationale for parameter choices.
"""

from utils.risk_engine import normalize_lifetime

DEVICE_PROFILES = [
    {
        "name": "IoT Temperature Sensor",
        "description": (
            "Low-power sensor deployed on a smart campus. Transmits ambient "
            "temperature and occupancy data over MQTT. Battery-powered, "
            "ARM Cortex-M0+, 64KB RAM. 10-year deployment lifecycle."
        ),
        # Temperature readings are not individually sensitive, but
        # occupancy patterns could reveal behavioral data
        "data_sensitivity":  3.0,
        # Publishes to an internet-connected MQTT broker
        "exposure_level":    7.0,
        # Device will be in the field for ~10 years
        "data_lifetime_yrs": 10,
        # Data patterns need ~5 years of protection (building security intel)
        "threat_window":     5.0,
        # Severely constrained: MCU, no FPU, 64KB RAM
        "device_capability": 2.0,
        "notes": (
            "Long lifetime + constrained hardware = migration urgency despite "
            "low data sensitivity. Algorithm must fit in <32KB stack."
        ),
    },
    {
        "name": "Developer Workstation",
        "description": (
            "Enterprise laptop used by software engineers. Stores source code, "
            "credentials, and internal API keys. Full x86-64 CPU, 32GB RAM, "
            "typically replaced every 3–4 years."
        ),
        # Source code, API keys, and internal credentials are highly sensitive
        "data_sensitivity":  7.0,
        # Connected to corporate VPN; partially internet-exposed
        "exposure_level":    6.0,
        # Workstation lifecycle ~3 years; data retention ~5 years
        "data_lifetime_yrs": 5,
        # IP and credentials need ~7 years of protection post-theft
        "threat_window":     7.0,
        # High-end laptop: capable of running any PQC scheme
        "device_capability": 8.0,
        "notes": (
            "High sensitivity and long threat window push this into elevated "
            "risk despite short device lifetime. Capable hardware means "
            "strongest algorithm is feasible."
        ),
    },
    {
        "name": "Public API Server",
        "description": (
            "Cloud-hosted REST API gateway serving mobile and web clients. "
            "Handles authentication tokens and some PII (names, emails). "
            "Auto-scaled VMs, replaced on rolling basis."
        ),
        # Handles PII and auth tokens — moderate sensitivity
        "data_sensitivity":  6.0,
        # Fully internet-facing, high traffic, actively scanned
        "exposure_level":    9.5,
        # Session tokens are short-lived; PII retention ~2 years
        "data_lifetime_yrs": 2,
        # Auth tokens need only days; PII needs ~3 years
        "threat_window":     3.0,
        # Cloud VM with modern multi-core CPU: highly capable
        "device_capability": 9.0,
        "notes": (
            "Very high exposure drives the score up despite moderate data "
            "sensitivity. Short data lifetime reduces HNDL risk. High "
            "capability allows strong PQC without performance concern."
        ),
    },
    {
        "name": "Hospital Patient Records DB",
        "description": (
            "On-premise PostgreSQL database storing electronic health records "
            "(EHR). Contains diagnoses, medications, lab results. Legally "
            "required to retain records for 20+ years (HIPAA). Dedicated "
            "server, 128GB RAM, isolated network segment."
        ),
        # Medical records: maximum sensitivity — HIPAA-protected PII + PHI
        "data_sensitivity":  9.5,
        # Internal hospital network, partially internet-adjacent via EMR portal
        "exposure_level":    5.0,
        # HIPAA mandates 20-year record retention minimum
        "data_lifetime_yrs": 25,
        # PHI must remain confidential for patient lifetimes (~30 years)
        "threat_window":     9.5,
        # Dedicated database server: high capability
        "device_capability": 8.5,
        "notes": (
            "Classic HNDL scenario: data encrypted today must stay private "
            "until 2055. Sensitivity × threat_window triggers the non-linear "
            "amplifier. Immediate migration to strongest PQC required."
        ),
    },
    {
        "name": "Industrial PLC Controller",
        "description": (
            "Programmable Logic Controller managing a water treatment facility. "
            "Sends control commands and receives sensor readings. "
            "Embedded RTOS, MIPS processor, 512KB RAM, 15-year lifespan. "
            "Air-gapped but communicates via historian over isolated SCADA."
        ),
        # Control commands for critical infrastructure — very high sensitivity
        "data_sensitivity":  8.5,
        # SCADA historian is isolated but not fully air-gapped
        "exposure_level":    3.0,
        # Infrastructure device: 15+ year operational life
        "data_lifetime_yrs": 15,
        # Safety-critical commands need protection for full device lifetime
        "threat_window":     8.0,
        # Constrained RTOS: limited RAM, no hardware crypto acceleration
        "device_capability": 3.5,
        "notes": (
            "High sensitivity + long lifetime + constrained hardware = complex "
            "tradeoff. Low exposure moderates overall risk. Algorithm selection "
            "must respect strict memory and latency budgets."
        ),
    },
    {
        "name": "Smart Home Hub",
        "description": (
            "Consumer IoT gateway (e.g., Google Nest Hub type device). Manages "
            "smart locks, cameras, thermostats. ARM Cortex-A53, 1GB RAM. "
            "Always internet-connected. Expected lifespan 5–7 years."
        ),
        # Smart lock + camera access patterns: moderately sensitive
        "data_sensitivity":  5.0,
        # Directly internet-connected, frequently targeted by botnets
        "exposure_level":    8.5,
        # Consumer device: ~5 year lifecycle
        "data_lifetime_yrs": 5,
        # Home security data needs ~5 years confidentiality
        "threat_window":     5.0,
        # ARM A53: capable enough for Kyber-512/768 comfortably
        "device_capability": 5.5,
        "notes": (
            "High exposure on a consumer device with moderate capability. "
            "Typical target for mass-scale HNDL attacks on home networks."
        ),
    },
]
