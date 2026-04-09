"""
main.py
=======
Quantum Risk-Aware Context-Adaptive PQC Framework
Demonstration Script

Runs the full framework pipeline across all device profiles:
  1. Load device profile
  2. Compute Quantum Risk Index (QRI)
  3. Select optimal PQC algorithm configuration
  4. Execute (simulated) cryptographic operations
  5. Print formatted results

Usage
-----
    python main.py              # full demo with crypto operations
    python main.py --no-crypto  # QRI + decision only (faster)
    python main.py --device "Hospital Patient Records DB"  # single device
"""

import sys

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
    
import textwrap
import time

from utils.decision_engine import select_algorithm
from utils.devices import DEVICE_PROFILES
from utils.pqc import run_crypto
from utils.risk_engine import compute_qri, normalize_lifetime

USE_COLOR = sys.stdout.isatty()
# ---------------------------------------------------------------------------
# Terminal colour helpers (works on macOS, Linux, and Windows 10+)
# ---------------------------------------------------------------------------


class C:
    RESET  = "\033[0m" if USE_COLOR else ""
    BOLD   = "\033[1m" if USE_COLOR else ""
    DIM    = "\033[2m" if USE_COLOR else ""
    RED    = "\033[91m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    GREEN  = "\033[92m" if USE_COLOR else ""
    CYAN   = "\033[96m" if USE_COLOR else ""
    BLUE   = "\033[94m" if USE_COLOR else ""
    MAGENTA= "\033[95m" if USE_COLOR else ""
    WHITE  = "\033[97m" if USE_COLOR else ""

TIER_COLOURS = {
    "LOW":      C.GREEN,
    "MODERATE": C.CYAN,
    "ELEVATED": C.YELLOW,
    "HIGH":     C.MAGENTA,
    "CRITICAL": C.RED,
}

TIER_BARS = {
    "LOW":      ("█" * 2 + "░" * 8),
    "MODERATE": ("█" * 4 + "░" * 6),
    "ELEVATED": ("█" * 6 + "░" * 4),
    "HIGH":     ("█" * 8 + "░" * 2),
    "CRITICAL": ("█" * 10),
}


def qri_bar(qri: float) -> str:
    filled = int(round(qri / 10))
    bar = "█" * filled + "░" * (10 - filled)
    return bar


def tier_colour(tier: str) -> str:
    return TIER_COLOURS.get(tier, C.WHITE)


def wrap(text: str, width: int = 72, indent: str = "    ") -> str:
    return textwrap.fill(text, width=width, subsequent_indent=indent)


def print_header():
    print()
    print(C.BOLD + C.BLUE + "=" * 72 + C.RESET)
    print(C.BOLD + C.BLUE +
          "  Quantum Risk-Aware Context-Adaptive PQC Framework" + C.RESET)
    print(C.BOLD + C.BLUE + "  Prototype Demo — v1.0" + C.RESET)
    print(C.BOLD + C.BLUE + "=" * 72 + C.RESET)
    print(C.DIM + "  NIST FIPS 203/204/205 | Hybrid + Pure PQC modes" + C.RESET)
    print()


def print_device_result(profile: dict, qri_result: dict, decision: dict, crypto_result: dict = None):
    """Print a formatted result block for one device."""
    qri = qri_result["qri"]
    tier = qri_result["qri_tier"]
    tc = tier_colour(tier)
    algo = decision["algorithm_info"]

    # ── Device header ──────────────────────────────────────────────────────
    print(C.BOLD + "─" * 72 + C.RESET)
    print(C.BOLD + f"  DEVICE: {profile['name']}" + C.RESET)
    print(C.DIM + f"  {profile['description'][:80]}..." + C.RESET)
    print()

    # ── QRI Score ─────────────────────────────────────────────────────────
    bar = qri_bar(qri)
    amplified_str = " ✦ amplified" if qri_result["amplified"] else ""
    print(f"  {C.BOLD}Quantum Risk Index (QRI){C.RESET}")
    print(f"  Score  : {tc}{C.BOLD}{qri:5.1f} / 100{C.RESET}  [{tc}{bar}{C.RESET}]  "
          f"{tc}{C.BOLD}{tier}{C.RESET}{C.DIM}{amplified_str}{C.RESET}")
    print()

    # ── Factor breakdown ───────────────────────────────────────────────────
    print(f"  {C.DIM}Factor contributions (weighted):{C.RESET}")
    factors = qri_result["factor_scores"]
    inputs  = qri_result["inputs"]
    factor_labels = {
        "data_sensitivity":  f"Data sensitivity    (raw={inputs['data_sensitivity']:.1f})",
        "exposure_level":    f"Exposure level      (raw={inputs['exposure_level']:.1f})",
        "data_lifetime":     f"Data lifetime       (raw={inputs['data_lifetime']:.1f})",
        "threat_window":     f"Threat window       (raw={inputs['threat_window']:.1f})",
        "device_capability": f"Device capability¹  (inv={10 - inputs['device_capability']:.1f})",
    }
    for key, label in factor_labels.items():
        contrib = factors[key]
        mini_bar = "▪" * int(round(contrib / 3)) + "·" * (10 - int(round(contrib / 3)))
        print(f"    {label:42s}  {contrib:4.2f}  {C.DIM}{mini_bar}{C.RESET}")
    print(C.DIM + "    ¹ device_capability is inverted: weaker device = higher risk contribution" + C.RESET)
    print()

    # ── Decision output ────────────────────────────────────────────────────
    print(f"  {C.BOLD}Selected Configuration{C.RESET}")
    print(f"  Algorithm : {C.BOLD}{C.CYAN}{algo['label']}{C.RESET}")
    print(f"  Mode      : {algo['mode']}")
    print(f"  Security  : {algo['security_level']}")
    print(f"  Key sizes : {C.DIM}{algo['key_sizes']}{C.RESET}")
    print(f"  Latency   : {algo['latency_class']}")
    print()
    print(f"  {C.BOLD}Rationale{C.RESET}")
    print(wrap(decision["justification"], indent="    "))
    print()

    if decision["capability_note"]:
        print(f"  {C.YELLOW}{C.BOLD}⚠  Capability Constraint{C.RESET}")
        print(wrap(decision["capability_note"], indent="    "))
        print()

    # ── Crypto operations ─────────────────────────────────────────────────
    if crypto_result:
        print(f"  {C.BOLD}Cryptographic Operations{C.RESET}")
        for op in crypto_result["operations"]:
            ms_str = f"{op['ms']:.3f} ms" if op.get("ms") is not None else "combined"
            size_kb = op["size_bytes"] / 1024
            print(f"    {op['op']:40s}  {size_kb:6.2f} KB   {ms_str}")
        if "note" in crypto_result:
            print(f"  {C.DIM}  Note: {crypto_result['note']}{C.RESET}")
        print()

    print()


def print_summary_table(results: list):
    """Print a compact summary table of all devices."""
    print(C.BOLD + "─" * 72 + C.RESET)
    print(C.BOLD + "  SUMMARY TABLE" + C.RESET)
    print(C.BOLD + "─" * 72 + C.RESET)
    print(C.DIM + f"  {'Device':<30}  {'QRI':>6}  {'Tier':<10}  Algorithm" + C.RESET)
    print(C.DIM + "  " + "─" * 68 + C.RESET)

    for r in results:
        qri   = r["qri_result"]["qri"]
        tier  = r["qri_result"]["qri_tier"]
        algo  = r["decision"]["algorithm_info"]["label"]
        tc    = tier_colour(tier)
        short_algo = algo[:32] + "…" if len(algo) > 32 else algo
        print(f"  {r['name']:<30}  {tc}{qri:>6.1f}{C.RESET}  {tc}{tier:<10}{C.RESET}  {short_algo}")

    print()


def main():
    # Parse simple CLI flags
    run_crypto = "--no-crypto" not in sys.argv
    filter_device = None
    if "--device" in sys.argv:
        idx = sys.argv.index("--device")
        if idx + 1 < len(sys.argv):
            filter_device = sys.argv[idx + 1]

    print_header()

    if not run_crypto:
        print(C.DIM + "  [--no-crypto flag set: skipping cryptographic operations]\n" + C.RESET)

    profiles_to_run = DEVICE_PROFILES
    if filter_device:
        profiles_to_run = [p for p in DEVICE_PROFILES if filter_device.lower() in p["name"].lower()]
        if not profiles_to_run:
            print(f"  {C.RED}No device matching '{filter_device}' found.{C.RESET}")
            sys.exit(1)

    all_results = []

    for profile in profiles_to_run:
        # ── Step 1: Compute QRI ────────────────────────────────────────────
        qri_result = compute_qri(
            data_sensitivity  = profile["data_sensitivity"],
            exposure_level    = profile["exposure_level"],
            data_lifetime     = normalize_lifetime(profile["data_lifetime_yrs"]),
            threat_window     = profile["threat_window"],
            device_capability = profile["device_capability"],
        )

        # ── Step 2: Decision layer ─────────────────────────────────────────
        decision = select_algorithm(
            qri               = qri_result["qri"],
            device_capability = profile["device_capability"],
            device_name       = profile["name"],
        )

        # ── Step 3: Crypto demo ────────────────────────────────────────────
        crypto_result = None
        if run_crypto:
            try:
                crypto_result = run_crypto(
                    algorithm_key = decision["algorithm_key"],
                    device_name   = profile["name"],
                )
            except Exception as ex:
                crypto_result = {"operations": [], "note": f"Crypto error: {ex}"}

        # ── Step 4: Print ──────────────────────────────────────────────────
        print_device_result(profile, qri_result, decision, crypto_result)

        all_results.append({
            "name":        profile["name"],
            "qri_result":  qri_result,
            "decision":    decision,
        })

    # ── Summary ────────────────────────────────────────────────────────────
    print_summary_table(all_results)

    print(C.BOLD + "─" * 72 + C.RESET)
    print(C.DIM + "  Framework: risk_engine → QRI score → decision_engine → algorithm config" + C.RESET)
    print(C.DIM + "  Crypto: pqc_simulator (swap in oqs-python for real PQC operations)" + C.RESET)
    print(C.BOLD + "─" * 72 + C.RESET)
    print()


if __name__ == "__main__":
    main()
