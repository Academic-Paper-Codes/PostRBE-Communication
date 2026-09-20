"""Compatibility wrappers for historical experiment scripts.

New functional code uses :mod:`postrbe.arithmetic` and
:mod:`postrbe.extraction` directly.  The matrix operations exported here are
overflow-safe; only ``legacy_numpy_matmul_mod`` retains the old benchmark path.
"""
from __future__ import annotations

import hashlib

import numpy as np

from .arithmetic import (
    Array,
    add_mod,
    canonical_mod as mod_q,
    identity_left_matrix,
    legacy_numpy_matmul_mod,
    matmul_mod,
    pad_preimage_n_to_m,
    rand_small,
    rand_uniform,
    zeros,
)


def high_bits(x: Array, q: int, keep_bits: int = 10) -> bytes:
    """Historical raw extractor; do not use for noisy correctness claims."""
    if keep_bits <= 0 or keep_bits >= q.bit_length():
        raise ValueError("invalid keep_bits")
    values = mod_q(x, q)
    levels = 1 << keep_bits
    width = (keep_bits + 7) // 8
    return b"".join(((int(v) * levels) // q).to_bytes(width, "little") for v in values.flat)


def kdf(data: bytes, length: int = 32) -> bytes:
    if not 1 <= length <= 32:
        raise ValueError("SHA-256 KDF output length must be in [1,32]")
    return hashlib.sha256(data).digest()[:length]


def xor_stream(key: bytes, plaintext: bytes) -> bytes:
    """Legacy benchmark helper, retained only for reproducing historical timing."""
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        out.extend(hashlib.sha256(key + counter.to_bytes(8, "little")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[: len(plaintext)]))


def nbytes_array(x: Array) -> int:
    return int(np.asarray(x).nbytes)
