"""Small matrix utilities for prototype PostRBE experiments.

This module intentionally keeps arithmetic simple: integer matrices modulo q.
It is for benchmarking and reproducibility, not for production cryptography.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

import numpy as np

Array = np.ndarray


def mod_q(x: Array, q: int) -> Array:
    """Reduce an integer array modulo q into int64."""
    return np.remainder(x, q).astype(np.int64, copy=False)


def matmul_mod(a: Array, b: Array, q: int) -> Array:
    """Matrix product modulo q.

    q is the runtime modulus of the prototype. The paper's size accounting uses
    q_bits=64 separately.
    """
    return mod_q(a @ b, q)


def add_mod(a: Array, b: Array, q: int) -> Array:
    return mod_q(a + b, q)


def zeros(shape: Tuple[int, int]) -> Array:
    return np.zeros(shape, dtype=np.int64)


def rand_uniform(rng: np.random.Generator, shape: Tuple[int, int], q: int) -> Array:
    return rng.integers(0, q, size=shape, dtype=np.int64)


def rand_small(rng: np.random.Generator, shape: Tuple[int, int], bound: int = 2) -> Array:
    """Sample short entries with infinity norm <= bound.

    For sigma_inf=2, entries are in {-2,-1,0,1,2}.
    """
    return rng.integers(-bound, bound + 1, size=shape, dtype=np.int64)


def identity_left_matrix(n: int, m: int) -> Array:
    """Return A=[I_n | 0] in Z_q^{n x m}, requiring m >= n."""
    if m < n:
        raise ValueError(f"m must be >= n, got n={n}, m={m}")
    A = np.zeros((n, m), dtype=np.int64)
    A[:, :n] = np.eye(n, dtype=np.int64)
    return A


def pad_preimage_n_to_m(y: Array, m: int) -> Array:
    """Given y in Z_q^{n x k}, return T in Z_q^{m x k} with [I|0]T=y."""
    n, k = y.shape
    if m < n:
        raise ValueError("m must be >= number of rows of y")
    out = np.zeros((m, k), dtype=np.int64)
    out[:n, :] = y
    return out


def high_bits(x: Array, q: int, keep_bits: int = 10) -> bytes:
    """Toy high-bit extractor F[·] for executable timing tests."""
    if keep_bits <= 0 or keep_bits > 63:
        raise ValueError("keep_bits should be in [1, 63] for this prototype")
    z = mod_q(x, q).astype(np.uint64, copy=False)
    shift = max(int(np.ceil(np.log2(q))) - keep_bits, 0)
    hb = (z >> shift).astype(np.uint16, copy=False)
    return hb.tobytes()


def kdf(data: bytes, length: int = 32) -> bytes:
    return hashlib.sha256(data).digest()[:length]


def xor_stream(key: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hashlib.sha256(key + counter.to_bytes(8, "little")).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[: len(plaintext)]))


def nbytes_array(x: Array) -> int:
    return int(x.size * x.dtype.itemsize)
