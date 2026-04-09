"""
decision_engine.py
==================
Context-Aware Post-Quantum Cryptographic Decision Layer

Takes a QRI score and device capability profile and selects the most
appropriate cryptographic configuration from the NIST-standardized
post-quantum algorithm suite (FIPS 203, 204, 205).

Decision Logic
--------------
The mapping is not just QRI-based — device capability acts as a constraint
that can downgrade the selected algorithm if the device cannot support the
preferred choice.

Algorithm Reference (NIST FIPS Standards)
------------------------------------------
  CRYSTALS-Kyber   (FIPS 203)  — Key Encapsulation Mechanism (KEM)
                                  Variants: Kyber-512 (L1), Kyber-768 (L3),
                                            Kyber-1024 (L5)
  CRYSTALS-Dilithium (FIPS 204)— Digital Signature (lattice-based)
                                  Variants: Dilithium-2 (L2), Dilithium-3 (L3),
                                            Dilithium-5 (L5)
  FALCON (FIPS 204 alt)        — Digital Signature (NTRU lattice)
                                  Compact signatures; key gen needs FPU
  SPHINCS+ (FIPS 205)          — Hash-Based Signature (stateless, conservative)
                                  Large signatures; use for root CA / firmware
  Classic McEliece             — Code-based KEM; enormous keys (~1MB)
                                  Highest confidence; low-frequency key exchange only

Hybrid Mode
-----------
A hybrid configuration runs both a classical algorithm (RSA-2048) AND a
PQC algorithm in parallel. The session key is derived from BOTH via a KDF,
so the session is safe even if one algorithm is broken. This supports backward
compatibility during the transition period.
"""

# ---------------------------------------------------------------------------
# Algorithm Catalogue
# Each entry describes one cryptographic configuration option.
# ---------------------------------------------------------------------------

ALGORITHM_CATALOGUE = {
    "hybrid_kyber512": {
        "label":           "Hybrid RSA-2048 + Kyber-512",
        "mode":            "Hybrid",
        "kem":             "Kyber-512",
        "signature":       "RSA-2048 (classical)",
        "security_level":  "NIST Level 1 (128-bit quantum equivalent)",
        "key_sizes":       "RSA pub: 256B | Kyber-512 pub: 800B | KEM ct: 768B",
        "latency_class":   "Very Fast",
        "min_capability":  1,    # works on anything
        "description": (
            "Hybrid mode runs RSA-2048 alongside Kyber-512. Session key is derived "
            "from both via HKDF. Backward-compatible with legacy TLS stacks. "
            "Appropriate for transitional deployments or low-risk systems."
        ),
    },
    "kyber768_dilithium3": {
        "label":           "Kyber-768 + Dilithium-3",
        "mode":            "Pure PQC",
        "kem":             "Kyber-768",
        "signature":       "Dilithium-3",
        "security_level":  "NIST Level 3 (192-bit quantum equivalent)",
        "key_sizes":       "Kyber-768 pub: 1.2KB | KEM ct: 1.1KB | Dil-3 sig: 3.3KB",
        "latency_class":   "Fast",
        "min_capability":  4,    # needs mid-tier embedded or better
        "description": (
            "Balanced configuration for the majority of enterprise systems. "
            "Kyber-768 provides strong key encapsulation; Dilithium-3 provides "
            "reliable digital signatures. Good performance on modern hardware."
        ),
    },
    "kyber768_falcon512": {
        "label":           "Kyber-768 + FALCON-512",
        "mode":            "Pure PQC (bandwidth-optimised)",
        "kem":             "Kyber-768",
        "signature":       "FALCON-512",
        "security_level":  "NIST Level 1–3",
        "key_sizes":       "Kyber-768 pub: 1.2KB | FALCON-512 sig: ~690B (compact)",
        "latency_class":   "Fast (signing), Slow (key gen)",
        "min_capability":  4,
        "description": (
            "Bandwidth-optimised variant using FALCON's compact signatures. "
            "Preferred for TLS certificates or high-frequency signing where "
            "network overhead matters. Requires hardware FPU for safe key gen."
        ),
    },
    "kyber1024_dilithium5": {
        "label":           "Kyber-1024 + Dilithium-5",
        "mode":            "Pure PQC — High Assurance",
        "kem":             "Kyber-1024",
        "signature":       "Dilithium-5",
        "security_level":  "NIST Level 5 (256-bit quantum equivalent)",
        "key_sizes":       "Kyber-1024 pub: 1.6KB | Dil-5 sig: 4.6KB",
        "latency_class":   "Fast (on capable hardware)",
        "min_capability":  6,
        "description": (
            "Maximum lattice-based security. Required for critical/sensitive "
            "data with long confidentiality windows. Suitable for servers, "
            "cloud infrastructure, and healthcare systems."
        ),
    },
    "kyber1024_dilithium5_sphincs": {
        "label":           "Kyber-1024 + Dilithium-5 + SPHINCS+-256s",
        "mode":            "Pure PQC — Maximum Assurance",
        "kem":             "Kyber-1024",
        "signature":       "Dilithium-5 (operational) + SPHINCS+-256s (root/archive)",
        "security_level":  "NIST Level 5, dual-algorithm signing",
        "key_sizes":       "Kyber-1024 pub: 1.6KB | SPHINCS sig: ~30KB (archive)",
        "latency_class":   "Fast (Kyber/Dil), Slow (SPHINCS for archive ops)",
        "min_capability":  7,
        "description": (
            "Dual-signature strategy: Dilithium-5 for high-frequency operational "
            "signing; SPHINCS+ for archive documents, root CAs, and long-term "
            "records. SPHINCS+ relies only on hash function security — provides "
            "defense-in-depth if lattice assumptions are ever challenged."
        ),
    },
    "kyber512_constrained": {
        "label":           "Kyber-512 + FALCON-512 (constrained profile)",
        "mode":            "Pure PQC — Constrained Device",
        "kem":             "Kyber-512",
        "signature":       "FALCON-512",
        "security_level":  "NIST Level 1 (128-bit quantum equivalent)",
        "key_sizes":       "Kyber-512 pub: 800B | FALCON-512 sig: ~690B",
        "latency_class":   "Fast — minimal memory footprint",
        "min_capability":  2,
        "description": (
            "Optimised for resource-constrained devices. Minimum memory profile: "
            "Kyber-512 stack < 2KB, FALCON-512 requires FPU. If no FPU: "
            "substitute Dilithium-2. For MCUs below Cortex-M4: use Kyber-512 only "
            "with pre-shared key refresh."
        ),
    },
}


# ---------------------------------------------------------------------------
# Decision Rules
# ---------------------------------------------------------------------------

def select_algorithm(qri: float, device_capability: float, device_name: str = "") -> dict:
    """
    Select the optimal PQC configuration for a device given its QRI score
    and hardware capability.

    Parameters
    ----------
    qri               : float, 0–100. Quantum Risk Index from risk_engine.
    device_capability : float, 0–10. Device compute/memory capability.
    device_name       : str, optional. Used in justification strings.

    Returns
    -------
    dict with:
        algorithm_key   — key into ALGORITHM_CATALOGUE
        algorithm_info  — full algorithm config dict
        justification   — human-readable decision rationale
        risk_tier       — label string
        capability_note — note if capability constrained the selection
    """
    name_str = f"'{device_name}'" if device_name else "this device"
    capability_note = ""

    # -----------------------------------------------------------------------
    # Primary selection based on QRI tier
    # -----------------------------------------------------------------------
    if qri < 30:
        # LOW risk — hybrid mode provides forward secrecy and backward compat
        preferred_key = "hybrid_kyber512"
        justification = (
            f"QRI {qri:.1f} (LOW): {name_str} carries minimal quantum risk. "
            "Data sensitivity and/or threat window are low enough that a "
            "hybrid RSA+Kyber-512 configuration provides adequate protection "
            "while maintaining full backward compatibility with classical systems."
        )

    elif qri < 50:
        # MODERATE risk — move to pure PQC but at Level 1/3
        if device_capability <= 3:
            preferred_key = "kyber512_constrained"
            justification = (
                f"QRI {qri:.1f} (MODERATE): {name_str} has moderate quantum risk "
                "but is hardware-constrained. Kyber-512 + FALCON-512 provides "
                "NIST Level 1 protection within tight memory budgets."
            )
        else:
            preferred_key = "kyber768_dilithium3"
            justification = (
                f"QRI {qri:.1f} (MODERATE): {name_str} has growing quantum risk "
                "warranting pure PQC. Kyber-768 + Dilithium-3 at NIST Level 3 "
                "balances strong protection with practical performance."
            )

    elif qri < 70:
        # ELEVATED risk — strong PQC required
        if device_capability <= 3:
            preferred_key = "kyber512_constrained"
            capability_note = (
                "NOTE: QRI warrants Kyber-768 but device capability is too low. "
                "Deployed at Kyber-512 with scheduled hardware upgrade recommended."
            )
            justification = (
                f"QRI {qri:.1f} (ELEVATED): {name_str} requires strong PQC but "
                "hardware capability limits algorithm choice. Using Kyber-512 "
                "constrained profile — hardware refresh should be prioritised."
            )
        elif device_capability <= 5:
            preferred_key = "kyber768_falcon512"
            justification = (
                f"QRI {qri:.1f} (ELEVATED): {name_str} has significant quantum risk. "
                "Kyber-768 + FALCON-512 provides strong protection with compact "
                "signatures suited to this device's moderate capability tier."
            )
        else:
            preferred_key = "kyber768_dilithium3"
            justification = (
                f"QRI {qri:.1f} (ELEVATED): {name_str} has significant quantum risk. "
                "Kyber-768 + Dilithium-3 at NIST Level 3 provides robust protection. "
                "Capable hardware allows full PQC without performance constraints."
            )

    elif qri < 85:
        # HIGH risk — Level 5 required
        if device_capability <= 3:
            preferred_key = "kyber512_constrained"
            capability_note = (
                "URGENT: QRI demands Kyber-1024 but device is hardware-constrained. "
                "Deployed at Kyber-512 as interim measure. IMMEDIATE hardware "
                "upgrade or device replacement is strongly recommended."
            )
            justification = (
                f"QRI {qri:.1f} (HIGH): {name_str} is at high quantum risk but "
                "hardware prevents deployment of the required security level. "
                "This is a critical gap — escalate for hardware review immediately."
            )
        elif device_capability <= 6:
            preferred_key = "kyber768_dilithium3"
            capability_note = (
                "NOTE: QRI warrants Kyber-1024 but device capability limits to "
                "Kyber-768. Plan hardware upgrade to reach target security level."
            )
            justification = (
                f"QRI {qri:.1f} (HIGH): {name_str} has high quantum risk. "
                "Device capability constrains selection to Kyber-768 + Dilithium-3. "
                "This is an acceptable interim measure pending hardware upgrade."
            )
        else:
            preferred_key = "kyber1024_dilithium5"
            justification = (
                f"QRI {qri:.1f} (HIGH): {name_str} has high quantum risk requiring "
                "maximum lattice-based security. Kyber-1024 + Dilithium-5 at "
                "NIST Level 5 provides 256-bit quantum-equivalent protection."
            )

    else:
        # CRITICAL risk — maximum assurance, dual-algorithm strategy
        if device_capability <= 3:
            preferred_key = "kyber512_constrained"
            capability_note = (
                "CRITICAL GAP: QRI demands maximum assurance configuration but device "
                "cannot support it. This device presents an unacceptable security risk. "
                "Immediate replacement or air-gap isolation is required."
            )
            justification = (
                f"QRI {qri:.1f} (CRITICAL): {name_str} represents a CRITICAL quantum "
                "risk but hardware cannot support adequate protection. "
                "Escalate for emergency remediation — device should be isolated "
                "from sensitive data paths until hardware is replaced."
            )
        elif device_capability <= 7:
            preferred_key = "kyber1024_dilithium5"
            capability_note = (
                "NOTE: Maximum assurance profile (SPHINCS+ archive tier) requires "
                "higher capability. Using Kyber-1024 + Dilithium-5 as primary config. "
                "Add SPHINCS+ for archive operations if a secondary system is available."
            )
            justification = (
                f"QRI {qri:.1f} (CRITICAL): {name_str} has critical quantum risk. "
                "Kyber-1024 + Dilithium-5 provides NIST Level 5 protection. "
                "Consider offloading archive signing to a dedicated SPHINCS+ system."
            )
        else:
            preferred_key = "kyber1024_dilithium5_sphincs"
            justification = (
                f"QRI {qri:.1f} (CRITICAL): {name_str} has critical quantum risk "
                "requiring maximum assurance. Dual-algorithm strategy: Kyber-1024 + "
                "Dilithium-5 for operational use, SPHINCS+-256s for archive/root "
                "signing. Defense-in-depth across two distinct mathematical foundations."
            )

    algo_info = ALGORITHM_CATALOGUE[preferred_key]
    risk_tier = _qri_to_tier(qri)

    return {
        "algorithm_key":   preferred_key,
        "algorithm_info":  algo_info,
        "justification":   justification,
        "risk_tier":       risk_tier,
        "capability_note": capability_note,
    }


def _qri_to_tier(qri: float) -> str:
    if qri < 30:   return "LOW"
    elif qri < 50: return "MODERATE"
    elif qri < 70: return "ELEVATED"
    elif qri < 85: return "HIGH"
    else:          return "CRITICAL"
