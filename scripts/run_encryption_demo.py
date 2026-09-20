#!/usr/bin/env python3
"""Display plaintext, the complete ciphertext, and recovered plaintext.

This is the presentation-oriented encryption/decryption demo requested for the
artifact.  It uses small functional parameters and must not be reported as a
paper-scale benchmark.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from postrbe import PostRBE, PostRBEStar, RBEParams
from postrbe.serialization import serialize_ciphertext


MESSAGE = b"PostRBE demo message: 0123456789"


def parameters(scheme_class):
    return RBEParams(
        N=4,
        n=2,
        m=3,
        r=2,
        t=6 if scheme_class is PostRBE else 4,
        q=2_147_483_647,
        q_bits=64,
        sigma_inf=1,
        keep_bits=8,
        message_bits=256,
        seed=2027,
    )


def display_ciphertext(ciphertext) -> None:
    """Print every transmitted ciphertext field in a readable representation."""
    component_view = {
        "scheme": ciphertext.scheme,
        "instance_id": ciphertext.instance_id,
        "identity": ciphertext.identity,
        "block": ciphertext.block,
        "position": ciphertext.position,
        "state_version": ciphertext.state_version,
        "c1": ciphertext.c1.tolist(),
        "c2": ciphertext.c2.tolist(),
        "reconciliation_hint": ciphertext.reconciliation_hint.tolist(),
        "nonce_hex": ciphertext.nonce.hex(),
        "c3_hex": ciphertext.c3.hex(),
    }
    print("Complete ciphertext components:")
    print(json.dumps(component_view, indent=2, ensure_ascii=False))

    # This is the exact versioned byte representation used for transmission or
    # storage.  The local-only correctness audit value is intentionally absent.
    serialized = serialize_ciphertext(ciphertext)
    print("Complete serialized ciphertext:")
    print(json.dumps(json.loads(serialized.decode("ascii")), indent=2, ensure_ascii=False))
    print(f"Serialized ciphertext bytes: {len(serialized)}")


def exercise(scheme_class) -> bool:
    scheme = scheme_class(parameters(scheme_class), instance_id=f"encryption-demo-{scheme_class.__name__}")
    scheme.setup()
    secret_key, user = scheme.keygen(1)
    scheme.register(1, user)
    proof = scheme.update(1)

    ciphertext = scheme.encrypt(1, MESSAGE)
    recovered = scheme.decrypt(secret_key, proof, ciphertext)

    print("=" * 78)
    print(f"Scheme: {scheme.name}")
    print(f"Original plaintext (UTF-8): {MESSAGE.decode('ascii')}")
    print(f"Original plaintext (hex): {MESSAGE.hex()}")
    print(f"Plaintext bytes: {len(MESSAGE)} (256 bits)")
    display_ciphertext(ciphertext)
    print(f"Decrypted plaintext (UTF-8): {recovered.decode('ascii')}")
    print(f"Decrypted plaintext (hex): {recovered.hex()}")
    equal = recovered == MESSAGE
    print(f"Original plaintext == Decrypted plaintext: {equal}")
    return equal


def main() -> int:
    print("profile=functional_demo_not_paper_result")
    print("This output displays the full ciphertext; it is not a paper-scale timing result.")
    results = [exercise(PostRBE), exercise(PostRBEStar)]
    if all(results):
        print("=" * 78)
        print("ENCRYPTION/DECRYPTION DEMO PASS: both schemes recovered the exact plaintext.")
        return 0
    print("ENCRYPTION/DECRYPTION DEMO FAIL", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
