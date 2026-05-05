"""
core/constants.py
=================
Single source of truth for all algorithm definitions.

Separating the catalogue from the decision logic means:
  - New algorithms require exactly ONE edit (here).
  - Decision engine, API schemas, and docs stay in sync automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── NIST key + ciphertext sizes (bytes) from FIPS 203/204/205 ────────────────
NIST_SIZES: dict[str, dict[str, int]] = {
    "Kyber512":   {"pk": 800,  "ct": 768,   "ss": 32},
    "Kyber768":   {"pk": 1184, "ct": 1088,  "ss": 32},
    "Kyber1024":  {"pk": 1568, "ct": 1568,  "ss": 32},
    "Dilithium2": {"pk": 1312, "sig": 2420},
    "Dilithium3": {"pk": 1952, "sig": 3293},
    "Dilithium5": {"pk": 2592, "sig": 4595},
    "FALCON512":  {"pk": 897,  "sig": 690},
    "SPHINCS256": {"pk": 64,   "sig": 29792},
}


@dataclass(frozen=True)
class AlgorithmSpec:
    """Immutable specification for one PQC algorithm configuration."""
    key:            str
    label:          str
    mode:           str
    kem:            str
    signature:      str
    security_level: str   # e.g. "NIST Level 3"
    nist_level:     int   # 1, 3, or 5
    network_cost:   int   # 1 (low) → 5 (high)
    min_ram_kb:     int
    requires_fpu:   bool
    latency_class:  str   # "ultra-low" | "low" | "medium" | "high"
    key_sizes:      dict  = field(default_factory=dict)


ALGORITHM_CATALOGUE: dict[str, AlgorithmSpec] = {
    "kyber512_constrained": AlgorithmSpec(
        key="kyber512_constrained",
        label="Kyber-512 + Dilithium-2 (Constrained)",
        mode="Constrained Device",
        kem="Kyber-512",
        signature="Dilithium-2",
        security_level="NIST Level 1",
        nist_level=1,
        network_cost=1,
        min_ram_kb=32,
        requires_fpu=False,
        latency_class="ultra-low",
        key_sizes={"kem_pk": 800, "kem_ct": 768, "sig_pk": 1312, "sig": 2420},
    ),
    "hybrid_kyber512": AlgorithmSpec(
        key="hybrid_kyber512",
        label="Hybrid RSA-2048 + Kyber-512",
        mode="Hybrid",
        kem="Kyber-512",
        signature="RSA-2048 (classical)",
        security_level="NIST Level 1",
        nist_level=1,
        network_cost=3,
        min_ram_kb=64,
        requires_fpu=False,
        latency_class="low",
        key_sizes={"kem_pk": 800, "rsa_ct": 256, "kem_ct": 768},
    ),
    "kyber768_dilithium3": AlgorithmSpec(
        key="kyber768_dilithium3",
        label="Kyber-768 + Dilithium-3",
        mode="Pure PQC",
        kem="Kyber-768",
        signature="Dilithium-3",
        security_level="NIST Level 3",
        nist_level=3,
        network_cost=3,
        min_ram_kb=128,
        requires_fpu=False,
        latency_class="low",
        key_sizes={"kem_pk": 1184, "kem_ct": 1088, "sig_pk": 1952, "sig": 3293},
    ),
    "kyber768_falcon512": AlgorithmSpec(
        key="kyber768_falcon512",
        label="Kyber-768 + FALCON-512",
        mode="Pure PQC (compact signature)",
        kem="Kyber-768",
        signature="FALCON-512",
        security_level="NIST Level 3",
        nist_level=3,
        network_cost=1,
        min_ram_kb=256,
        requires_fpu=True,
        latency_class="medium",
        key_sizes={"kem_pk": 1184, "kem_ct": 1088, "sig_pk": 897, "sig": 690},
    ),
    "kyber1024_dilithium5": AlgorithmSpec(
        key="kyber1024_dilithium5",
        label="Kyber-1024 + Dilithium-5",
        mode="High Assurance",
        kem="Kyber-1024",
        signature="Dilithium-5",
        security_level="NIST Level 5",
        nist_level=5,
        network_cost=2,
        min_ram_kb=256,
        requires_fpu=False,
        latency_class="medium",
        key_sizes={"kem_pk": 1568, "kem_ct": 1568, "sig_pk": 2592, "sig": 4595},
    ),
    "kyber1024_dilithium5_sphincs": AlgorithmSpec(
        key="kyber1024_dilithium5_sphincs",
        label="Kyber-1024 + Dilithium-5 + SPHINCS+",
        mode="Maximum Assurance",
        kem="Kyber-1024",
        signature="Dilithium-5 + SPHINCS+",
        security_level="NIST Level 5",
        nist_level=5,
        network_cost=5,
        min_ram_kb=512,
        requires_fpu=False,
        latency_class="high",
        key_sizes={"kem_pk": 1568, "kem_ct": 1568, "sig_pk": 2592, "sig": 4595, "sphincs_sig": 29792},
    ),
}
