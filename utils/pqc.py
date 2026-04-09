"""
pqc_simulator.py
================
Post-Quantum Cryptography Simulation Layer

This module provides a faithful SIMULATION of PQC algorithm operations.
It models real-world key sizes, ciphertext sizes, and relative timing
characteristics of NIST-standardised algorithms.

The simulation below uses the real `cryptography` library for RSA (hybrid mode)
and simulates PQC operations with correct byte sizes and realistic timing.

Reference sizes from NIST FIPS 203/204/205 specifications:
    Kyber-512:   pubkey=800B,  ciphertext=768B,   shared_secret=32B
    Kyber-768:   pubkey=1184B, ciphertext=1088B,  shared_secret=32B
    Kyber-1024:  pubkey=1568B, ciphertext=1568B,  shared_secret=32B
    Dilithium-2: pubkey=1312B, signature=2420B
    Dilithium-3: pubkey=1952B, signature=3293B
    Dilithium-5: pubkey=2592B, signature=4595B
    FALCON-512:  pubkey=897B,  signature=~690B
    SPHINCS+-256s: pubkey=64B, signature=~29792B
"""

import hashlib
import os
import time

import oqs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Utility timing wrapper
# ---------------------------------------------------------------------------

def _timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = (time.perf_counter() - t0) * 1000
    return result, round(elapsed, 3)


# ---------------------------------------------------------------------------
# Kyber (KEM)
# ---------------------------------------------------------------------------

def kyber_keygen(variant="Kyber512"):
    def _gen():
        with oqs.KeyEncapsulation(variant) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key

    (pub, sec), elapsed = _timed(_gen)

    return {
        "variant": variant,
        "public_key": pub,
        "secret_key": sec,
        "pub_key_size": len(pub),
        "elapsed_ms": elapsed
    }


def kyber_encapsulate(public_key, variant="Kyber512"):
    def _enc():
        with oqs.KeyEncapsulation(variant) as kem:
            ct, ss = kem.encap_secret(public_key)
            return ct, ss

    (ct, ss), elapsed = _timed(_enc)

    return {
        "ciphertext": ct,
        "shared_secret": ss,
        "ciphertext_size": len(ct),
        "elapsed_ms": elapsed
    }


# ---------------------------------------------------------------------------
# Dilithium (Signature)
# ---------------------------------------------------------------------------

def dilithium_keygen(variant="Dilithium3"):
    def _gen():
        with oqs.Signature(variant) as sig:
            pub = sig.generate_keypair()
            sec = sig.export_secret_key()
            return pub, sec

    (pub, sec), elapsed = _timed(_gen)

    return {
        "variant": variant,
        "public_key": pub,
        "secret_key": sec,
        "pub_key_size": len(pub),
        "elapsed_ms": elapsed
    }


def dilithium_sign(message, secret_key, variant="Dilithium3"):
    def _sign():
        with oqs.Signature(variant) as sig:
            sig.secret_key = secret_key
            signature = sig.sign(message)
            return signature

    signature, elapsed = _timed(_sign)

    return {
        "signature": signature,
        "signature_size": len(signature),
        "elapsed_ms": elapsed
    }


# ---------------------------------------------------------------------------
# SPHINCS+
# ---------------------------------------------------------------------------

def sphincs_sign(message, variant="SPHINCS+-SHA2-256s"):
    def _sign():
        with oqs.Signature(variant) as sig:
            pub = sig.generate_keypair()
            sec = sig.export_secret_key()
            sig.secret_key = sec
            signature = sig.sign(message)
            return signature

    signature, elapsed = _timed(_sign)

    return {
        "signature": signature,
        "signature_size": len(signature),
        "elapsed_ms": elapsed
    }


# ---------------------------------------------------------------------------
# RSA (Real)
# ---------------------------------------------------------------------------

def rsa_keygen(key_size=2048):
    def _gen():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    (priv, pub), elapsed = _timed(_gen)

    pub_bytes = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "private_key": priv,
        "public_key": pub,
        "pub_key_size": len(pub_bytes),
        "elapsed_ms": elapsed
    }


# ---------------------------------------------------------------------------
# Hybrid RSA + Kyber
# ---------------------------------------------------------------------------

def hybrid_encapsulate(rsa_public_key, kyber_public_key):
    # RSA seed
    rsa_seed = os.urandom(32)

    rsa_ciphertext = rsa_public_key.encrypt(
        rsa_seed,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    kyber = kyber_encapsulate(kyber_public_key)

    combined = hashlib.sha256(
        rsa_seed + kyber["shared_secret"] + b"hybrid"
    ).digest()

    return {
        "rsa_ciphertext_size": len(rsa_ciphertext),
        "kyber_ciphertext_size": kyber["ciphertext_size"],
        "session_key": combined,
        "session_key_size": len(combined)
    }


# ---------------------------------------------------------------------------
# MAIN DEMO
# ---------------------------------------------------------------------------

def run_crypto(algorithm_key, device_name):
    msg = f"{device_name}-{int(time.time())}".encode()

    results = {
        "device": device_name,
        "algorithm": algorithm_key,
        "operations": []
    }

    if algorithm_key == "hybrid_kyber512":
        rsa_keys = rsa_keygen()
        kyber_keys = kyber_keygen("Kyber512")

        encap = hybrid_encapsulate(
            rsa_keys["public_key"],
            kyber_keys["public_key"]
        )

        results["operations"] = [
            {"op": "RSA keygen", "ms": rsa_keys["elapsed_ms"]},
            {"op": "Kyber keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Hybrid encapsulation", "size": encap["session_key_size"]}
        ]

    elif algorithm_key == "kyber768_dilithium3":
        kyber_keys = kyber_keygen("Kyber768")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium3")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium3")

        results["operations"] = [
            {"op": "Kyber keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encapsulation", "ms": encap["elapsed_ms"]},
            {"op": "Sign", "ms": sig["elapsed_ms"]}
        ]

    elif algorithm_key == "kyber512_constrained":
        kyber_keys = kyber_keygen("Kyber512")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium2")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium2")

        results["operations"] = [
            {"op": "Light keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encap", "ms": encap["elapsed_ms"]},
            {"op": "Light sign", "ms": sig["elapsed_ms"]}
        ]

    else:
        kyber_keys = kyber_keygen("Kyber1024")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium5")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium5")

        results["operations"] = [
            {"op": "High keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encap", "ms": encap["elapsed_ms"]},
            {"op": "Strong sign", "ms": sig["elapsed_ms"]}
        ]

    return results