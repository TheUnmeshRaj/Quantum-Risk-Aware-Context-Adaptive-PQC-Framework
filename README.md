
# Quantum Risk-Aware Context-Adaptive Post-Quantum Cryptographic Framework

## Overview

This project presents an intelligent framework for transitioning modern digital systems to **post-quantum cryptography (PQC)**.

With the rapid advancement of quantum computing, traditional cryptographic schemes such as RSA and ECC are expected to become insecure. Rather than simply replacing these algorithms, this framework focuses on **how to deploy PQC efficiently across diverse, real-world systems**.

It introduces a **risk-driven, context-aware approach** that dynamically selects cryptographic configurations based on system requirements, constraints, and threat exposure.

---

## Problem Statement

Most PQC research focuses on algorithm design, but there is limited guidance on:

* How to deploy PQC in heterogeneous environments
* How to balance **security vs performance vs resource constraints**

Applying uniform security across all systems leads to:

* Unnecessary computational overhead
* Performance degradation
* Inefficient resource utilization

This project addresses that gap through **adaptive cryptographic deployment**.

---

## Objectives

* Design a **risk-driven framework** for PQC adoption
* Develop a **Quantum Risk Index (QRI)** to quantify vulnerability
* Enable **context-aware cryptographic selection**
* Support **hybrid classical + PQC migration**
* Simulate real-world heterogeneous systems

---

## System Architecture

The framework consists of two core layers:

### 1. Quantum Risk Evaluation Engine (`risk_engine.py`)

Computes a **Quantum Risk Index (QRI)** from 0–100 using weighted factors:

| Factor            | Weight | Description                     |
| ----------------- | ------ | ------------------------------- |
| Data Sensitivity  | 30%    | Impact of compromise            |
| Data Lifetime     | 25%    | Required protection duration    |
| Threat Window     | 20%    | Time available for attackers    |
| Exposure Level    | 15%    | Accessibility of system         |
| Device Capability | 10%    | Hardware constraints (inverted) |

A **non-linear amplifier** boosts risk in “harvest now, decrypt later” scenarios.

---

### 2. Context-Aware Cryptographic Decision Engine (`decision_engine.py`)

Uses QRI + device capability to select optimal configurations:

* PQC algorithms (Kyber, Dilithium, Falcon, SPHINCS+, Classic McEliece)
* Hybrid classical + PQC modes
* Adaptive security levels

#### Decision Mapping (Simplified)

| QRI Range | Capability | Configuration                       |
| --------- | ---------- | ----------------------------------- |
| < 30      | Any        | Hybrid RSA-2048 + Kyber-512         |
| 30–50     | Low        | Kyber-512 + Falcon                  |
| 30–50     | High       | Kyber-768 + Dilithium               |
| 50–70     | Mid        | Kyber-768 + Falcon                  |
| 70–85     | High       | Kyber-1024 + Dilithium-5            |
| ≥ 85      | High       | Kyber-1024 + Dilithium-5 + SPHINCS+ |

---

## How It Works

1. Input system parameters (sensitivity, exposure, constraints)
2. Compute **Quantum Risk Index (QRI)**
3. Map QRI → cryptographic configuration
4. Apply PQC or hybrid scheme
5. Evaluate performance (latency, overhead, scalability)

---

## Implementation

### Project Structure

```
pqc_framework/
├── risk_engine.py
├── decision_engine.py
├── devices.py
├── pqc_simulator.py
├── main.py
└── README.md
```

---

### Key Components

#### `devices.py`

Defines 6 real-world system profiles:

* IoT Sensor (low power)
* Workstation
* Public API Server
* Hospital Database (critical)
* Industrial Controller
* Smart Home Hub

---

#### `pqc_simulator.py`

* Simulates PQC operations with:

  * Correct NIST key sizes (FIPS 203/204/205)
  * Real RSA-2048 (via `cryptography`)
  * Realistic timing behavior
* Supports easy upgrade to real PQC libraries

---

## How to Run

### Install dependency

```bash
pip install cryptography
```

### Full simulation

```bash
python main.py
```

### Fast mode (no crypto)

```bash
python main.py --no-crypto
```

### Run specific device

```bash
python main.py --device "Hospital"
```

---

## Upgrading to Real PQC

Install Open Quantum Safe bindings:

```bash
pip install oqs
```

Replace simulated functions in `pqc_simulator.py`:

```python
import oqs

with oqs.KeyEncapsulation("Kyber768") as kem:
    public_key = kem.generate_keypair()

with oqs.Signature("Dilithium3") as sig:
    public_key = sig.generate_keypair()
    signature = sig.sign(b"message")
```

---

## Example Output

```
DEVICE: Hospital Patient Records DB

QRI Score: 97.8 / 100  → CRITICAL

Selected Configuration:
Kyber-1024 + Dilithium-5 + SPHINCS+-256s

Mode: Pure PQC — Maximum Assurance
Security: NIST Level 5
```

---

## Architecture Flow

```
Device Profile
    │
    ▼
risk_engine.py ──► QRI Score ──► decision_engine.py
    │                                 │
    ▼                                 ▼
Weighted Risk Model            Algorithm Selection
                                         │
                                         ▼
                                pqc_simulator.py
                                         │
                                         ▼
                             Key sizes, timing, crypto ops
```

---

## Novelty

* Introduces a **quantified quantum risk model (QRI)**
* Enables **adaptive cryptographic deployment**
* Bridges **PQC research ↔ real-world systems**
* Focuses on **deployment strategy**, not just algorithms

---

## Impact

Helps organizations:

* Prioritize systems based on quantum risk
* Optimize performance vs security trade-offs
* Enable gradual PQC migration
* Build **quantum-resilient infrastructure**

### Applicable Domains

* Smart cities
* Healthcare
* Finance
* Industrial systems

---

## Tech Stack

* Python
* `cryptography` (RSA)
* Optional:

  * oqs-python
  * pqcrypto

---

## Future Work

* Machine learning-based adaptive risk scoring
* Real-time network risk monitoring
* Deployment on distributed systems
* Enterprise security integration

---

## Extending the Framework

* Add device → `devices.py`
* Adjust weights → `risk_engine.py`
* Add algorithms → `decision_engine.py`
* Modify thresholds → `select_algorithm()`

---