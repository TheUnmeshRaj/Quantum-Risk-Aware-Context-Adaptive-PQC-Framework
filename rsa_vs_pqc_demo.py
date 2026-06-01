from __future__ import annotations

import argparse
import hashlib
import math
import secrets
import textwrap
from typing import Dict, Tuple


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor_stream(data: bytes, key_material: bytes) -> bytes:
    """Small stream-cipher-style helper for demo encryption."""

    output = bytearray()
    counter = 0

    while len(output) < len(data):
        block = sha256(key_material + counter.to_bytes(4, "big"))
        remaining = len(data) - len(output)
        output.extend(block[:remaining])
        counter += 1

    return bytes(left ^ right for left, right in zip(data, output))


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if length is None:
        return raw
    return raw.rjust(length, b"\x00")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def is_probable_prime(candidate: int, rounds: int = 8) -> bool:
    if candidate < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        witness = secrets.randbelow(candidate - 3) + 2
        x = pow(witness, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime with the requested bit length."""

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # force the top bit
        candidate |= 1  # force odd
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 256) -> Dict[str, int]:
    """Generate a small educational RSA keypair.

    The modulus is intentionally modest so the demo runs quickly.
    It is not secure and should never be used outside a teaching example.
    """

    public_exponent = 65537

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue

        modulus = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(public_exponent, phi) != 1:
            continue

        private_exponent = pow(public_exponent, -1, phi)
        return {
            "p": p,
            "q": q,
            "n": modulus,
            "e": public_exponent,
            "d": private_exponent,
        }


def rsa_encrypt_key(session_key: bytes, public_key: Dict[str, int]) -> Tuple[int, bytes]:
    key_int = bytes_to_int(session_key)
    if key_int >= public_key["n"]:
        raise ValueError("Session key is too large for this RSA modulus.")

    ciphertext_int = pow(key_int, public_key["e"], public_key["n"])
    return ciphertext_int, int_to_bytes(ciphertext_int, (public_key["n"].bit_length() + 7) // 8)


def rsa_decrypt_key(ciphertext_int: int, private_key: Dict[str, int], key_length: int) -> bytes:
    key_int = pow(ciphertext_int, private_key["d"], private_key["n"])
    return int_to_bytes(key_int, key_length)


def classical_symmetric_demo(message: bytes) -> Dict[str, bytes]:
    shared_key = secrets.token_bytes(32)
    ciphertext = xor_stream(message, shared_key)
    plaintext = xor_stream(ciphertext, shared_key)
    return {
        "shared_key": shared_key,
        "ciphertext": ciphertext,
        "plaintext": plaintext,
    }


def toy_pqc_keypair() -> Dict[str, bytes]:
    """Create a toy PQC-style KEM keypair.

    In a real PQC KEM, the sender uses the public key to encapsulate a shared secret
    and the receiver uses the private key to decapsulate it. This toy version keeps
    the same structure while remaining dependency-free.
    """

    secret_seed = secrets.token_bytes(32)
    public_key = sha256(secret_seed + b":public")
    return {
        "public_key": public_key,
        "secret_seed": secret_seed,
    }


def toy_pqc_encapsulate(public_key: bytes) -> Dict[str, bytes]:
    nonce = secrets.token_bytes(32)
    shared_secret = sha256(public_key + nonce + b":shared")
    session_key = sha256(shared_secret + b":session")
    ciphertext = nonce
    return {
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
        "session_key": session_key,
    }


def toy_pqc_decapsulate(secret_seed: bytes, ciphertext: bytes) -> bytes:
    public_key = sha256(secret_seed + b":public")
    shared_secret = sha256(public_key + ciphertext + b":shared")
    return sha256(shared_secret + b":session")


def format_bytes(data: bytes, limit: int = 24) -> str:
    preview = data.hex()
    if len(preview) > limit * 2:
        return preview[: limit * 2] + "..."
    return preview


def print_section(title: str) -> None:
    print("\n" + title)
    print("-" * len(title))


def print_comparison_table(rsa_public: Dict[str, int], rsa_ciphertext: bytes, pqc_ciphertext: bytes) -> None:
    print("\nQuick comparison")
    print("-----------------")
    print(f"RSA public key      : {rsa_public['n'].bit_length()}-bit modulus, public exponent {rsa_public['e']}")
    print(f"RSA key transport   : encrypts the session key directly with the public key")
    print(f"RSA ciphertext size : {len(rsa_ciphertext)} bytes")
    print(f"PQC KEM ciphertext  : {len(pqc_ciphertext)} bytes (toy encapsulation blob)")
    print("PQC KEM model       : sender encapsulates a shared secret, then both sides derive a session key")


def run_demo(message: str) -> None:
    payload = message.encode("utf-8")

    print_section("1) Classical symmetric cryptography")
    symmetric = classical_symmetric_demo(payload)
    print("Both sides already know the same secret key.")
    print(f"Shared key preview   : {format_bytes(symmetric['shared_key'])}")
    print(f"Ciphertext preview   : {format_bytes(symmetric['ciphertext'])}")
    print(f"Recovered plaintext  : {symmetric['plaintext'].decode('utf-8')}")

    print_section("2) RSA key encryption (key transport)")
    rsa_keypair = generate_rsa_keypair(bits=256)
    session_key = secrets.token_bytes(16)
    rsa_ciphertext_int, rsa_ciphertext = rsa_encrypt_key(session_key, rsa_keypair)
    recovered_session_key = rsa_decrypt_key(rsa_ciphertext_int, rsa_keypair, len(session_key))
    rsa_payload_ciphertext = xor_stream(payload, recovered_session_key)
    rsa_payload_plaintext = xor_stream(rsa_payload_ciphertext, recovered_session_key)

    print("RSA sends a random session key to the recipient by encrypting it with the public key.")
    print(f"RSA public modulus   : {rsa_keypair['n'].bit_length()} bits")
    print(f"Session key          : {format_bytes(session_key)}")
    print(f"Encrypted key blob   : {format_bytes(rsa_ciphertext)}")
    print(f"Key round-trip OK    : {recovered_session_key == session_key}")
    print(f"Payload ciphertext   : {format_bytes(rsa_payload_ciphertext)}")
    print(f"Payload recovered    : {rsa_payload_plaintext.decode('utf-8')}")

    print_section("3) PQC-style KEM (toy post-quantum flow)")
    pqc_keypair = toy_pqc_keypair()
    encapsulation = toy_pqc_encapsulate(pqc_keypair["public_key"])
    pqc_session_key = toy_pqc_decapsulate(pqc_keypair["secret_seed"], encapsulation["ciphertext"])
    pqc_payload_ciphertext = xor_stream(payload, pqc_session_key)
    pqc_payload_plaintext = xor_stream(pqc_payload_ciphertext, pqc_session_key)

    print("PQC does not have to encrypt the key with RSA-style modular arithmetic.")
    print("Instead, a KEM encapsulates a shared secret and the receiver decapsulates it.")
    print(f"Public key preview   : {format_bytes(pqc_keypair['public_key'])}")
    print(f"Ciphertext / nonce   : {format_bytes(encapsulation['ciphertext'])}")
    print(f"Shared secret preview: {format_bytes(encapsulation['shared_secret'])}")
    print(f"Session key roundtrip : {pqc_session_key == encapsulation['session_key']}")
    print(f"Payload ciphertext   : {format_bytes(pqc_payload_ciphertext)}")
    print(f"Payload recovered    : {pqc_payload_plaintext.decode('utf-8')}")

    print_comparison_table(rsa_keypair, rsa_ciphertext, encapsulation["ciphertext"])

    print("\nTakeaway")
    print("--------")
    print(
        textwrap.fill(
            "RSA protects a randomly generated key by encrypting it with the recipient's public key. "
            "A PQC KEM protects a shared secret by encapsulating it to the recipient's public key and "
            "then deriving a session key from that shared secret. In both cases, the actual payload is "
            "usually encrypted symmetrically after the key exchange step.",
            width=88,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Show RSA key transport vs a PQC-style KEM demo.")
    parser.add_argument(
        "--message",
        default="This message is protected after a key-exchange step.",
        help="Message to encrypt and recover in the demo.",
    )
    args = parser.parse_args()
    run_demo(args.message)


if __name__ == "__main__":
    main()