"""Overflow-safe modular arithmetic used by the functional artifact."""
from __future__ import annotations

from typing import Iterable, Tuple

import numpy as np

Array = np.ndarray


def _as_integral_array(value: Array | Iterable[int]) -> Array:
    array = np.asarray(value)
    if array.dtype.kind not in "iuO":
        raise TypeError("modular arithmetic accepts integral arrays only")
    return array


def canonical_mod(value: Array | Iterable[int], q: int) -> Array:
    """Return canonical representatives in ``[0,q)`` without int64 overflow."""
    array = _as_integral_array(value)
    reduced = np.remainder(array.astype(object), int(q))
    return np.asarray(reduced, dtype=np.int64)


def centered(value: Array | Iterable[int], q: int) -> Array:
    """Return centered representatives as a Python-integer object array."""
    canonical = canonical_mod(value, q).astype(object)
    half = q // 2
    return np.where(canonical > half, canonical - q, canonical)


def matmul_mod_reference(a: Array, b: Array, q: int) -> Array:
    """Straightforward Python-bigint reference multiplication."""
    left = _as_integral_array(a)
    right = _as_integral_array(b)
    if left.ndim != 2 or right.ndim != 2 or left.shape[1] != right.shape[0]:
        raise ValueError(f"incompatible matrix shapes: {left.shape} and {right.shape}")
    product = left.astype(object) @ right.astype(object)
    return canonical_mod(product, q)


def matmul_mod(a: Array, b: Array, q: int, backend: str = "python_bigint") -> Array:
    if backend != "python_bigint":
        raise ValueError(f"unsupported safe arithmetic backend: {backend}")
    return matmul_mod_reference(a, b, q)


def legacy_numpy_matmul_mod(a: Array, b: Array, q: int) -> Array:
    """Historical benchmark-only path; unsafe when signed int64 overflows."""
    return np.remainder(np.asarray(a, dtype=np.int64) @ np.asarray(b, dtype=np.int64), q).astype(np.int64)


def add_mod(a: Array, b: Array, q: int) -> Array:
    if np.shape(a) != np.shape(b):
        raise ValueError(f"shape mismatch: {np.shape(a)} and {np.shape(b)}")
    return canonical_mod(np.asarray(a).astype(object) + np.asarray(b).astype(object), q)


def sub_mod(a: Array, b: Array, q: int) -> Array:
    if np.shape(a) != np.shape(b):
        raise ValueError(f"shape mismatch: {np.shape(a)} and {np.shape(b)}")
    return canonical_mod(np.asarray(a).astype(object) - np.asarray(b).astype(object), q)


def zeros(shape: Tuple[int, ...]) -> Array:
    return np.zeros(shape, dtype=np.int64)


def rand_uniform(rng: np.random.Generator, shape: Tuple[int, ...], q: int) -> Array:
    return rng.integers(0, q, size=shape, dtype=np.int64)


def rand_small(rng: np.random.Generator, shape: Tuple[int, ...], bound: int = 2, *, nonzero: bool = False) -> Array:
    if bound <= 0:
        raise ValueError("short-sampling bound must be positive")
    out = rng.integers(-bound, bound + 1, size=shape, dtype=np.int64)
    if nonzero and out.size and not np.any(out):
        out.flat[0] = 1
    return out


def identity_left_matrix(n: int, m: int) -> Array:
    if m < n:
        raise ValueError(f"m must be >= n, got n={n}, m={m}")
    out = np.zeros((n, m), dtype=np.int64)
    out[:, :n] = np.eye(n, dtype=np.int64)
    return out


def pad_preimage_n_to_m(y: Array, m: int) -> Array:
    array = _as_integral_array(y)
    if array.ndim != 2:
        raise ValueError("preimage target must be a matrix")
    n, width = array.shape
    if m < n:
        raise ValueError("m must be >= target row count")
    out = np.zeros((m, width), dtype=np.int64)
    out[:n] = array
    return out


def infinity_norm(value: Array, q: int | None = None) -> int:
    array = centered(value, q) if q is not None else np.asarray(value).astype(object)
    return int(max((abs(int(x)) for x in array.flat), default=0))


def matrix_equal_mod(a: Array, b: Array, q: int) -> bool:
    return bool(np.array_equal(canonical_mod(a, q), canonical_mod(b, q)))
