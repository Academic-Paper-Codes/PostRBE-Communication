#!/usr/bin/env python3
"""Fast evaluator smoke test covering both schemes and every public operation."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from postrbe import PostRBE, PostRBEStar, RBEParams, SystemManager


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


def exercise(scheme_class) -> None:
    scheme = scheme_class(parameters(scheme_class), instance_id=f"smoke-{scheme_class.__name__}")
    setup_audit = scheme.setup()
    assert setup_audit["trapdoor_exported"] is False
    assert scheme.verify_nonmembership(1, scheme.update(1))

    sk, partial = scheme.keygen(1, include_upload=False)
    complete = scheme.add_registration_upload(sk, partial)
    scheme.register(1, complete)
    proof = scheme.update(1)
    assert scheme.verify_membership(1, complete.pk, proof)
    assert not scheme.verify_nonmembership(1, proof)

    message = bytes(range(32))
    ciphertext = scheme.encrypt(1, message)
    assert scheme.decrypt(sk, proof, ciphertext) == message
    audit = scheme.correctness_audit(sk, proof, ciphertext)
    assert audit.noise_infinity_norm > 0
    assert audit.within_bound and audit.reconciliation_matches

    scheme.revoke(1)
    assert scheme.verify_nonmembership(1, scheme.update(1))
    print(
        f"PASS {scheme.name}: Setup KeyGen Register Update Encrypt Decrypt "
        f"Membership NonMembership Revoke; noise={audit.noise_infinity_norm} "
        f"threshold={audit.allowed_threshold:.1f}"
    )


def exercise_scaling() -> None:
    manager = SystemManager("PostRBE*", parameters(PostRBEStar))
    for global_identity in range(1, 6):
        manager.register_global(global_identity)
    assert len(manager.instances) == 2
    assert manager.instances[0].instance_id != manager.instances[1].instance_id
    print("PASS scaling: capacity 4 -> 2 independent instances")


def main() -> int:
    print("profile=functional_demo_not_paper_result arithmetic=python_bigint symmetric=AES-256-GCM")
    try:
        exercise(PostRBE)
        exercise(PostRBEStar)
        exercise_scaling()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("SMOKE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
