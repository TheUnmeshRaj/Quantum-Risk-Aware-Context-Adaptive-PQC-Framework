# QRI Weight Justification — Evidence & Citations

## The Hard Truth First

> [!CAUTION]
> **No standards body publishes exact numerical weights like 0.30/0.25/0.20/0.15/0.10 for a "Quantum Risk Index."** These specific numbers are a **design decision** made for your framework, not something you can cite from a single authoritative source. What you *can* cite is that the **choice of factors**, their **relative ordering**, and the **rationale for each** are strongly grounded in published standards and academic literature.

NIST SP 800-30 Rev. 1 explicitly states that organizations must define their own risk scales and weighting — there is no mandated universal formula. Your job is to justify **why these factors matter** and **why this ordering is defensible**.

---

## Factor-by-Factor Justification

### 1. `data_sensitivity` — 0.30 (Highest Weight)

**Why it's the top factor — backed by standards:**

| Source | What it says |
|--------|-------------|
| **FIPS 199** (Standards for Security Categorization of Federal Information and Information Systems) | The *entire* federal security categorization system begins with classifying the **sensitivity of information** (Confidentiality, Integrity, Availability impact levels). The security category of a system is determined by the sensitivity of the data it processes. This is the foundation — everything else follows from it. |
| **NIST SP 800-30 Rev. 1**, §2.3 | Risk is defined as `f(likelihood, impact)`. **Impact** is determined by the adverse effect on organizational operations, assets, and individuals — which is directly a function of data sensitivity. High-sensitivity data → high impact → high risk contribution. |
| **NIST CSWP 48** (Mappings of Migration to PQC Project Capabilities) | Explicitly states: *"Organizations are urged to identify and prioritize the protection of their high-value, long-lived sensitive data."* Data sensitivity is the **primary triage criterion** for PQC migration. |
| **NSA CNSA 2.0** | Migration timeline is prioritized by data classification. National Security Systems (NSS) handling the most sensitive data are migrated **first** (2025-2027), while lower-sensitivity systems get later deadlines (2030-2033). |

**The logic:** If data is public or disposable (sensitivity ≈ 0), quantum risk is near-zero regardless of all other factors. A quantum computer breaking the encryption on public data has zero impact. This makes sensitivity the **necessary condition** for quantum risk to exist at all — hence the highest weight.

> **Citation:** NIST, *FIPS Publication 199: Standards for Security Categorization of Federal Information and Information Systems*, February 2004.  
> **Citation:** NIST, *SP 800-30 Rev. 1: Guide for Conducting Risk Assessments*, September 2012, §2.3.  
> **Citation:** NIST, *CSWP 48: Mappings of NCCoE Migration to PQC Project Capabilities*, 2024.

---

### 2. `data_lifetime` — 0.25 (Second Highest)

**Why it's #2 — this is the "Harvest Now, Decrypt Later" (HNDL) factor:**

| Source | What it says |
|--------|-------------|
| **Mosca's Inequality** (Michele Mosca, 2018) | The foundational quantum risk timeline formula: **X + Y > Z**, where **X = security shelf life of data** (how long it must remain confidential), Y = migration time, Z = time until a CRQC exists. **X (data lifetime) is the first and most prominent variable.** If X is small, the inequality is easily satisfied and risk is low. |
| **ETSI GR QSC 004** (Quantum-Safe Threat Assessment, 2017) | Extends Mosca's formula to **X + Y + T > Z** (adding T = trust development time). Again, **X (security shelf life)** is the leading variable. The document explicitly frames data lifetime as the primary determinant of whether "harvest now, decrypt later" applies. |
| **NIST PQC Migration Guidance** | Repeatedly emphasizes: *"Information with long-term secrecy requirements is at the highest risk from Harvest Now, Decrypt Later (HNDL) attacks."* Data that must stay secret for 5+ years is already at risk *today*, even before a quantum computer exists. |

**The logic:** Data with a 1-year lifetime is almost certainly safe — even optimistic Q-Day estimates are 10+ years out. Data with a 25-year lifetime (medical records, classified intelligence, infrastructure designs) is *already being harvested* by adversaries banking on future quantum capability. Data lifetime is the **temporal multiplier** on all other risk.

> **Citation:** M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?," *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, Sep./Oct. 2018. doi: 10.1109/MSP.2018.3761723  
> **Citation:** ETSI, *GR QSC 004 V1.1.1: Quantum-Safe Cryptography; Quantum-Safe Threat Assessment*, March 2017.

---

### 3. `threat_window` — 0.20 (Third)

**Why it matters — the confidentiality duration requirement:**

| Source | What it says |
|--------|-------------|
| **ETSI GR QSC 004** | The threat assessment explicitly models the *required confidentiality period* as a core risk variable. Systems that need confidentiality for 30+ years face fundamentally different risk profiles than systems needing it for 30 days. |
| **NSA CNSA 2.0 Timeline** | The phased migration (2025→2035) is structured around how long systems must remain secure. Long-window systems (national security, critical infrastructure) get earlier deadlines; short-window systems (session keys, ephemeral auth) are lower priority. |
| **NIST SP 800-57 Part 1** (Key Management) | Defines cryptoperiods — the time span during which a specific key is authorized for use. Longer cryptoperiods = longer threat windows = higher risk exposure. Different data types have different recommended cryptoperiods. |

**The logic:** `threat_window` is related to but distinct from `data_lifetime`. Lifetime is *how long the data exists*; threat window is *how long it must remain confidential*. Some data has a long lifetime but short confidentiality needs (e.g., archived public records). The threat window determines the overlap with realistic Q-Day timelines.

> **Citation:** NIST, *SP 800-57 Part 1 Rev. 5: Recommendation for Key Management*, May 2020.  
> **Citation:** NSA, *CNSA 2.0 — Commercial National Security Algorithm Suite 2.0*, September 2022.

---

### 4. `exposure_level` — 0.15 (Fourth)

**Why it's important but lower — the attack surface factor:**

| Source | What it says |
|--------|-------------|
| **NIST SP 800-30 Rev. 1**, §2.2 | Likelihood of exploitation depends on *"the difficulty of exploiting the weakness"* and the *"capability, intent, and targeting of the threat source."* Exposure (internet-facing vs. air-gapped) directly modulates likelihood. |
| **ETSI GR QSC 004**, Threat Assessment Factors | Assesses **"Opportunity"** — the access an attacker has to intercept the target data. Public-facing TLS endpoints are high-opportunity; air-gapped SCADA systems are low-opportunity. |
| **NIST SP 800-53 Rev. 5**, SC-7 (Boundary Protection) | Network exposure is a primary control category. The entire boundary protection family exists because exposure modulates risk — fewer exposed surfaces = lower interception opportunity. |

**Why it's 0.15, not higher:** In the quantum threat model, the **primary attack** is passive interception ("harvest now"). Unlike active exploitation, passive collection doesn't require sophisticated access — even encrypted traffic on public links is collectible. An air-gapped system is safer, but an internet-facing system with short-lived, non-sensitive data still has low quantum risk. Exposure is a **modifier**, not a primary driver.

> **Citation:** NIST, *SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations*, September 2020.

---

### 5. `device_capability` — 0.10 (Lowest, Inverted)

**Why it's included and why it's inverted:**

| Source | What it says |
|--------|-------------|
| **NIST PQC Standardization** (FIPS 203/204/205) | The entire multi-year standardization process included specific evaluation criteria for performance on **constrained devices**. NIST explicitly acknowledged that some selected algorithms have larger key sizes and higher computational costs that may be prohibitive for IoT/embedded devices. |
| **NIST SP 800-232** (Lightweight Cryptography) | NIST created an entirely separate standardization track (Ascon family) specifically because standard PQC algorithms are too heavy for extremely constrained devices. The existence of this separate track proves that device capability is a real constraint. |
| **IoT/Embedded PQC Research** (IEEE/ACM literature) | Extensive research demonstrates that ML-KEM (Kyber) and ML-DSA (Dilithium) require significantly more RAM, CPU cycles, and bandwidth than ECC equivalents. Devices with <64KB RAM may not be able to run standard PQC at all. |

**Why it's inverted (`10 - capability`):** A high-capability server (score 10) can run any PQC algorithm → capability contributes 0 risk. A severely constrained sensor (score 1) has few or no viable PQC options → capability contributes 9 units of risk. The inversion captures **migration difficulty** — weaker devices are harder to protect.

**Why it's only 0.10:** Device capability is an **operational constraint**, not a threat factor. A constrained device processing non-sensitive, short-lived data still has low quantum risk regardless of its hardware limitations. Capability only matters when the other factors (sensitivity, lifetime, threat window) are already significant.

> **Citation:** NIST, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.  
> **Citation:** NIST, *SP 800-232: NIST Lightweight Encryption Standard (Ascon)*, 2024.

---

## The Non-Linear Amplifier (`_amplify`)

### What it does

```python
def _amplify(qri_raw, sensitivity, threat_window):
    if sensitivity * threat_window > 40:
        return min(qri_raw * 1.20, 100.0)
    return qri_raw
```

When **both** `data_sensitivity` and `threat_window` are high (both ≥ ~6.3, since 6.3 × 6.3 ≈ 40), the raw QRI score is amplified by 20%, capped at 100. This represents the **HNDL critical quadrant**.

### Why it exists — the interaction effect

| Source | What it says |
|--------|-------------|
| **Mosca's Inequality** | The risk isn't just that data is sensitive OR that the threat window is long — it's that **both conditions together** create a qualitatively different threat scenario. Data that is both highly sensitive AND must remain confidential for decades is **already under active harvest attack**. This is a well-documented compound risk. |
| **NIST Risk Assessment Guidance (SP 800-30)** | Risk matrices are inherently non-linear: High Likelihood × High Impact doesn't just produce "High" risk — it produces **"Very High"** or **"Critical"** risk. The jump from Moderate-High to Critical is disproportionate, not linear. |
| **Compound/Systemic Risk Literature** | Risk management literature extensively documents that **interacting risk factors produce multiplicative, not additive, effects**. When two risk drivers are simultaneously at their peaks, the combined exposure exceeds the sum of parts (synergistic risk amplification). |

### Why the threshold is 40

- Both factors are on a 0–10 scale
- `sensitivity × threat_window > 40` means both must be roughly above **6.3** simultaneously
- This is the **"definitely high on both axes"** region — it avoids false amplification when only one factor is high
- The 20% amplification (1.20×) is deliberately conservative — it bumps a score from the 70s into the 80s (HIGH → CRITICAL) but won't radically distort a moderate score

### Visual intuition

```
threat_window
     10 ┤ ▒▒▒▒▒▒ █████████
        │ ▒▒▒▒▒▒ █████████   █ = AMPLIFIED zone
      7 ┤ ▒▒▒▒▒▒ █████████       (both ≥ ~6.3)
        │ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
      4 ┤ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ▒ = linear scoring
        │ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒       (no amplification)
      0 ┼─────────────────
        0    4    7    10
              data_sensitivity
```

---

## Summary: What You Can Defend

| Claim | Defensible? | How |
|-------|-------------|-----|
| These 5 factors are the right ones | ✅ **Yes** | Every factor maps to a specific NIST/ETSI/NSA concept |
| Data sensitivity should be the highest weight | ✅ **Yes** | FIPS 199, NIST CSWP 48, CNSA 2.0 all put data sensitivity as the primary triage criterion |
| Data lifetime should be second | ✅ **Yes** | Mosca's Inequality and ETSI GR QSC 004 both place security shelf life as the leading variable |
| The relative ordering (sensitivity > lifetime > window > exposure > capability) | ✅ **Yes** | Follows the logical flow: impact (sensitivity) → temporal risk (lifetime/window) → likelihood modifier (exposure) → operational constraint (capability) |
| The exact numbers 0.30/0.25/0.20/0.15/0.10 | ⚠️ **Partially** | The ordering is grounded; the exact values are a calibrated design choice. You should state this explicitly |
| The non-linear amplifier | ✅ **Yes** | Directly models the HNDL compound threat (Mosca + ETSI). The interaction of high sensitivity × high threat window is a qualitatively distinct threat class |

---

## Complete Citation List

1. **NIST, FIPS 199** — *Standards for Security Categorization of Federal Information and Information Systems*, February 2004. https://csrc.nist.gov/pubs/fips/199/final
2. **NIST, SP 800-30 Rev. 1** — *Guide for Conducting Risk Assessments*, September 2012. https://csrc.nist.gov/pubs/sp/800/30/r1/final
3. **NIST, SP 800-53 Rev. 5** — *Security and Privacy Controls for Information Systems and Organizations*, September 2020. https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
4. **NIST, SP 800-57 Part 1 Rev. 5** — *Recommendation for Key Management: Part 1 – General*, May 2020. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
5. **NIST, CSWP 48** — *Mappings of NCCoE Migration to PQC Project Capabilities to Risk Framework Documents*, 2024. https://csrc.nist.gov/pubs/cswp/48/final
6. **NIST, FIPS 203** — *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*, August 2024. https://csrc.nist.gov/pubs/fips/203/final
7. **NIST, SP 800-232** — *NIST Lightweight Encryption Standard*, 2024.
8. **M. Mosca** — "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?," *IEEE Security & Privacy*, vol. 16, no. 5, pp. 38–41, Sep./Oct. 2018. doi: 10.1109/MSP.2018.3761723
9. **ETSI, GR QSC 004 V1.1.1** — *Quantum-Safe Cryptography; Quantum-Safe Threat Assessment*, March 2017. https://www.etsi.org/deliver/etsi_gr/QSC/001_099/004/01.01.01_60/gr_QSC004v010101p.pdf
10. **NSA** — *Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)*, September 2022. https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
11. **NIST, SP 800-131A Rev. 2** — *Transitioning the Use of Cryptographic Algorithms and Key Lengths*, March 2024. https://csrc.nist.gov/pubs/sp/800/131a/r2/final

---

## Recommended Docstring Update

If you want to be academically honest in your code, replace the current docstring header with something like:

```python
"""
Weight Justification
--------------------
The five input factors and their relative ordering are derived from the
quantum-risk prioritization frameworks in:

  - NIST SP 800-30 Rev. 1 (risk = f(impact, likelihood))
  - FIPS 199 (data sensitivity as primary impact determinant)
  - Mosca's Inequality (data lifetime as leading HNDL variable)
  - ETSI GR QSC 004 (X+Y+T>Z threat assessment formula)
  - NSA CNSA 2.0 (sensitivity-first migration prioritization)

The specific numerical weights (0.30, 0.25, ...) are calibrated to
reflect the relative ordering established by these frameworks. The
ordering (sensitivity > lifetime > threat_window > exposure > capability)
is standards-grounded; the exact magnitudes are a design choice within
that ordering.
"""
```
