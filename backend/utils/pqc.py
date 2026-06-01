"""
pqc.py
================
Post-Quantum Cryptography Simulation Layer

This module provides a faithful SIMULATION of PQC algorithm operations.
It models key sizes, ciphertext sizes, shared secrets, signing, and a full
plaintext-to-ciphertext walkthrough that can be shown in the UI.

The implementation intentionally avoids hard runtime dependencies so the demo
still works when native PQC packages are unavailable in the environment.

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

from backend.core.constants import NIST_SIZES

KEM_VARIANTS = {
    "Kyber512": "Kyber512",
    "Kyber768": "Kyber768",
    "Kyber1024": "Kyber1024",
}

SIGNATURE_VARIANTS = {
    "Dilithium2": ("Dilithium2", "sig"),
    "Dilithium3": ("Dilithium3", "sig"),
    "Dilithium5": ("Dilithium5", "sig"),
    "Falcon512": ("FALCON512", "sig"),
    "SPHINCS+-SHA2-256s": ("SPHINCS256", "sig"),
}


def _timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = (time.perf_counter() - t0) * 1000
    return result, round(elapsed, 3)


def _normalize_variant_name(variant):
    return variant.replace("-", "").replace("_", "").replace("+", "").lower()


def _size_lookup(name, field):
    record = NIST_SIZES.get(name)
    if not record:
        raise ValueError(f"Unknown PQC size profile: {name}")
    return record[field]


def _expand_bytes(seed, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _random_seed(label):
    return hashlib.sha256(f"{label}:{os.urandom(32).hex()}".encode()).digest()


def _variant_to_record(variant, category):
    normalized = _normalize_variant_name(variant)

    if category == "kem":
        for canonical in KEM_VARIANTS:
            if _normalize_variant_name(canonical) == normalized:
                return KEM_VARIANTS[canonical]
    else:
        for canonical in SIGNATURE_VARIANTS:
            if _normalize_variant_name(canonical) == normalized:
                return SIGNATURE_VARIANTS[canonical][0]

    raise ValueError(f"Unsupported PQC variant: {variant}")


def _simulate_keypair(label, public_size, secret_size):
    seed = _random_seed(label)
    public_key = _expand_bytes(seed + b":pub", public_size)
    secret_key = _expand_bytes(seed + b":sec", secret_size)

    return {
        "seed": seed,
        "public_key": public_key,
        "secret_key": secret_key,
        "pub_key_size": len(public_key),
        "sec_key_size": len(secret_key),
    }


def _simulate_signature(message, secret_key, label, signature_size):
    payload = message if isinstance(message, bytes) else str(message).encode()
    signature_seed = hashlib.sha256(secret_key + payload + label.encode()).digest()
    signature = _expand_bytes(signature_seed, signature_size)
    return signature


def _derive_session_key(shared_secret, label):
    return hashlib.sha256(shared_secret + label.encode()).digest()


def _stream_cipher(payload, key_material):
    keystream_seed = hashlib.sha256(key_material).digest()
    keystream = _expand_bytes(keystream_seed, len(payload))
    return bytes(left ^ right for left, right in zip(payload, keystream))


def _standard_kem_sizes(name):
    return {
        "public": _size_lookup(name, "pk"),
        "ciphertext": _size_lookup(name, "ct"),
        "shared_secret": _size_lookup(name, "ss"),
    }


def _standard_sig_sizes(name):
    return {
        "public": _size_lookup(name, "pk"),
        "signature": _size_lookup(name, "sig"),
    }


def _variant_sizes(variant):
    normalized = _normalize_variant_name(variant)

    if normalized == _normalize_variant_name("Falcon512"):
        return _standard_sig_sizes("FALCON512")
    if normalized == _normalize_variant_name("SPHINCS+-SHA2-256s"):
        return _standard_sig_sizes("SPHINCS256")

    for canonical in ("Dilithium2", "Dilithium3", "Dilithium5"):
        if _normalize_variant_name(canonical) == normalized:
            return _standard_sig_sizes(canonical)

    for canonical in ("Kyber512", "Kyber768", "Kyber1024"):
        if _normalize_variant_name(canonical) == normalized:
            return _standard_kem_sizes(canonical)

    raise ValueError(f"Unsupported PQC variant: {variant}")


def _demo_text(device_name, algorithm_key, plaintext=None):
    if plaintext is not None:
        return plaintext.encode() if isinstance(plaintext, str) else bytes(plaintext)
    return f"Plain text for {device_name} using {algorithm_key}".encode()


def _build_exchange_demo(device_name, algorithm_key, kem_variant, sig_variant=None, plaintext=None):
    text = _demo_text(device_name, algorithm_key, plaintext)
    kem_sizes = _standard_kem_sizes(kem_variant)

    kem_keys = _simulate_keypair(
        f"kem:{device_name}:{kem_variant}",
        kem_sizes["public"],
        kem_sizes["shared_secret"],
    )

    encapsulated_shared_secret = hashlib.sha256(
        kem_keys["seed"] + kem_variant.encode() + b":shared"
    ).digest()[:kem_sizes["shared_secret"]]
    ciphertext_seed = hashlib.sha256(
        kem_keys["public_key"] + encapsulated_shared_secret + kem_variant.encode()
    ).digest()
    kem_ciphertext = _expand_bytes(ciphertext_seed, kem_sizes["ciphertext"])

    session_key = _derive_session_key(encapsulated_shared_secret, algorithm_key)
    ciphertext = _stream_cipher(text, session_key)
    decrypted = _stream_cipher(ciphertext, session_key)

    signature_block = None
    if sig_variant:
        sig_name = _variant_to_record(sig_variant, "sig")
        sig_sizes = _standard_sig_sizes(sig_name)
        sig_keys = _simulate_keypair(
            f"sig:{device_name}:{sig_name}",
            sig_sizes["public"],
            sig_sizes["signature"],
        )
        signature = _simulate_signature(text, sig_keys["secret_key"], sig_name, sig_sizes["signature"])
        signature_block = {
            "algorithm": sig_name,
            "public_key_size": sig_keys["pub_key_size"],
            "signature_size": len(signature),
            "signature_hex": signature.hex(),
        }

    return {
        "plaintext": text.decode("utf-8", errors="replace"),
        "plaintext_size": len(text),
        "kem": {
            "variant": kem_variant,
            "public_key_size": kem_keys["pub_key_size"],
            "ciphertext_size": len(kem_ciphertext),
            "shared_secret_size": len(encapsulated_shared_secret),
            "shared_secret_hex": encapsulated_shared_secret.hex(),
        },
        "session_key_hex": session_key.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_size": len(ciphertext),
        "decrypted_text": decrypted.decode("utf-8", errors="replace"),
        "steps": [
            {
                "step": 1,
                "title": "Generate public/private keys",
                "detail": f"{kem_variant} creates a public key for the sender and a private key for the receiver.",
            },
            {
                "step": 2,
                "title": "Encapsulate a shared secret",
                "detail": "The sender uses the public key to derive a shared secret and produces a ciphertext blob.",
            },
            {
                "step": 3,
                "title": "Derive a session key",
                "detail": "Both sides derive the same session key from the shared secret.",
            },
            {
                "step": 4,
                "title": "Encrypt the plaintext",
                "detail": "The plaintext is turned into ciphertext using the derived session key.",
            },
            {
                "step": 5,
                "title": "Decrypt the ciphertext",
                "detail": "The receiver uses the same session key to recover the original plaintext.",
            },
        ],
        "signature": signature_block,
    }


# ---------------------------------------------------------------------------
# Kyber (KEM)
# ---------------------------------------------------------------------------

def kyber_keygen(variant="Kyber512"):
    record = _variant_to_record(variant, "kem")
    sizes = _standard_kem_sizes(record)

    def _gen():
        return _simulate_keypair(f"kem:{record}", sizes["public"], sizes["shared_secret"])

    keys, elapsed = _timed(_gen)

    return {
        "variant": record,
        "public_key": keys["public_key"],
        "secret_key": keys["secret_key"],
        "pub_key_size": keys["pub_key_size"],
        "elapsed_ms": elapsed,
    }


def kyber_encapsulate(public_key, variant="Kyber512"):
    record = _variant_to_record(variant, "kem")
    sizes = _standard_kem_sizes(record)

    def _enc():
        shared_secret = hashlib.sha256(public_key + record.encode() + b":shared").digest()[:sizes["shared_secret"]]
        ciphertext_seed = hashlib.sha256(public_key + shared_secret + record.encode()).digest()
        ciphertext = _expand_bytes(ciphertext_seed, sizes["ciphertext"])
        return ciphertext, shared_secret

    (ct, ss), elapsed = _timed(_enc)

    return {
        "ciphertext": ct,
        "shared_secret": ss,
        "ciphertext_size": len(ct),
        "shared_secret_size": len(ss),
        "elapsed_ms": elapsed,
    }


# ---------------------------------------------------------------------------
# Dilithium / Falcon / SPHINCS+ (Signature)
# ---------------------------------------------------------------------------

def dilithium_keygen(variant="Dilithium3"):
    record = _variant_to_record(variant, "sig")
    sizes = _standard_sig_sizes(record)

    def _gen():
        return _simulate_keypair(f"sig:{record}", sizes["public"], sizes["signature"])

    keys, elapsed = _timed(_gen)

    return {
        "variant": record,
        "public_key": keys["public_key"],
        "secret_key": keys["secret_key"],
        "pub_key_size": keys["pub_key_size"],
        "elapsed_ms": elapsed,
    }


def falcon_keygen(variant="Falcon512"):
    record = _variant_to_record(variant, "sig")
    sizes = _standard_sig_sizes(record)

    def _gen():
        return _simulate_keypair(f"sig:{record}", sizes["public"], sizes["signature"])

    keys, elapsed = _timed(_gen)

    return {
        "variant": record,
        "public_key": keys["public_key"],
        "secret_key": keys["secret_key"],
        "pub_key_size": keys["pub_key_size"],
        "elapsed_ms": elapsed,
    }


def _sign_with_variant(message, secret_key, variant):
    record = _variant_to_record(variant, "sig")
    sizes = _standard_sig_sizes(record)

    def _sign():
        return _simulate_signature(message, secret_key, record, sizes["signature"])

    signature, elapsed = _timed(_sign)

    return {
        "signature": signature,
        "signature_size": len(signature),
        "elapsed_ms": elapsed,
    }


def dilithium_sign(message, secret_key, variant="Dilithium3"):
    return _sign_with_variant(message, secret_key, variant)


def falcon_sign(message, secret_key, variant="Falcon512"):
    return _sign_with_variant(message, secret_key, variant)


def sphincs_sign(message, variant="SPHINCS+-SHA2-256s"):
    record = _variant_to_record(variant, "sig")
    sizes = _standard_sig_sizes(record)

    def _sign():
        keypair = _simulate_keypair(f"sig:{record}", sizes["public"], sizes["signature"])
        return _simulate_signature(message, keypair["secret_key"], record, sizes["signature"])

    signature, elapsed = _timed(_sign)

    return {
        "signature": signature,
        "signature_size": len(signature),
        "elapsed_ms": elapsed,
    }


# ---------------------------------------------------------------------------
# RSA (simulated for demo parity)
# ---------------------------------------------------------------------------

def rsa_keygen(key_size=2048):
    public_size = key_size // 8
    secret_size = key_size // 4

    def _gen():
        return _simulate_keypair(f"rsa:{key_size}", public_size, secret_size)

    keys, elapsed = _timed(_gen)

    return {
        "private_key": keys["secret_key"],
        "public_key": keys["public_key"],
        "pub_key_size": keys["pub_key_size"],
        "elapsed_ms": elapsed,
    }


# ---------------------------------------------------------------------------
# Hybrid RSA + Kyber
# ---------------------------------------------------------------------------

def hybrid_encapsulate(rsa_public_key, kyber_public_key):
    rsa_seed = hashlib.sha256(rsa_public_key + b":rsa-seed").digest()
    rsa_ciphertext = _expand_bytes(hashlib.sha256(rsa_seed + rsa_public_key).digest(), 256)

    kyber = kyber_encapsulate(kyber_public_key)

    combined = hashlib.sha256(rsa_seed + kyber["shared_secret"] + b"hybrid").digest()

    return {
        "rsa_ciphertext_size": len(rsa_ciphertext),
        "kyber_ciphertext_size": kyber["ciphertext_size"],
        "session_key": combined,
        "session_key_size": len(combined),
        "shared_secret_hex": kyber["shared_secret"].hex(),
    }


def build_crypto_demo(algorithm_key, device_name, plaintext=None):
    if algorithm_key == "hybrid_kyber512":
        return _build_exchange_demo(device_name, algorithm_key, "Kyber512", "Dilithium2", plaintext)
    if algorithm_key == "kyber512_constrained":
        return _build_exchange_demo(device_name, algorithm_key, "Kyber512", "Dilithium2", plaintext)
    if algorithm_key == "kyber768_dilithium3":
        return _build_exchange_demo(device_name, algorithm_key, "Kyber768", "Dilithium3", plaintext)
    if algorithm_key == "kyber768_falcon512":
        return _build_exchange_demo(device_name, algorithm_key, "Kyber768", "Falcon512", plaintext)
    if algorithm_key == "kyber1024_dilithium5_sphincs":
        return _build_exchange_demo(device_name, algorithm_key, "Kyber1024", "Dilithium5", plaintext)
    return _build_exchange_demo(device_name, algorithm_key, "Kyber1024", "Dilithium5", plaintext)


def build_all_crypto_demos(device_name, plaintext=None):
    """Return every supported demo so the UI or CLI can show all PQC flows at once."""
    algorithms = [
        "hybrid_kyber512",
        "kyber512_constrained",
        "kyber768_dilithium3",
        "kyber768_falcon512",
        "kyber1024_dilithium5",
        "kyber1024_dilithium5_sphincs",
    ]

    return {
        algorithm_key: build_crypto_demo(algorithm_key, device_name, plaintext)
        for algorithm_key in algorithms
    }


# ---------------------------------------------------------------------------
# MAIN DEMO
# ---------------------------------------------------------------------------

def run_crypto(algorithm_key, device_name):
    msg = f"{device_name}-{int(time.time())}".encode()

    results = {
        "device": device_name,
        "algorithm": algorithm_key,
        "operations": [],
        "demo": build_crypto_demo(algorithm_key, device_name, msg),
    }

    if algorithm_key == "hybrid_kyber512":
        rsa_keys = rsa_keygen()
        kyber_keys = kyber_keygen("Kyber512")

        encap = hybrid_encapsulate(
            rsa_keys["public_key"],
            kyber_keys["public_key"],
        )

        results["operations"] = [
            {"op": "RSA keygen", "ms": rsa_keys["elapsed_ms"]},
            {"op": "Kyber keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Hybrid encapsulation", "size": encap["session_key_size"]},
        ]

    elif algorithm_key == "kyber768_dilithium3":
        kyber_keys = kyber_keygen("Kyber768")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium3")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium3")

        results["operations"] = [
            {"op": "Kyber keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encapsulation", "ms": encap["elapsed_ms"]},
            {"op": "Sign", "ms": sig["elapsed_ms"]},
        ]

    elif algorithm_key == "kyber768_falcon512":
        kyber_keys = kyber_keygen("Kyber768")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        falcon_keys = falcon_keygen("Falcon512")
        sig = falcon_sign(msg, falcon_keys["secret_key"], "Falcon512")

        results["operations"] = [
            {"op": "Kyber keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encapsulation", "ms": encap["elapsed_ms"]},
            {"op": "Falcon sign", "ms": sig["elapsed_ms"]},
        ]

    elif algorithm_key == "kyber512_constrained":
        kyber_keys = kyber_keygen("Kyber512")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium2")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium2")

        results["operations"] = [
            {"op": "Light keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encap", "ms": encap["elapsed_ms"]},
            {"op": "Light sign", "ms": sig["elapsed_ms"]},
        ]

    elif algorithm_key == "kyber1024_dilithium5_sphincs":
        kyber_keys = kyber_keygen("Kyber1024")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium5")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium5")

        results["operations"] = [
            {"op": "High keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encap", "ms": encap["elapsed_ms"]},
            {"op": "Strong sign", "ms": sig["elapsed_ms"]},
        ]

    else:
        kyber_keys = kyber_keygen("Kyber1024")
        encap = kyber_encapsulate(kyber_keys["public_key"])

        dil_keys = dilithium_keygen("Dilithium5")
        sig = dilithium_sign(msg, dil_keys["secret_key"], "Dilithium5")

        results["operations"] = [
            {"op": "High keygen", "ms": kyber_keys["elapsed_ms"]},
            {"op": "Encap", "ms": encap["elapsed_ms"]},
            {"op": "Strong sign", "ms": sig["elapsed_ms"]},
        ]

    return results