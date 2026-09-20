"""Reconciliation-assisted stable high-bit extraction.

The paper requires F(x+e)=F(x) whenever ||e||_inf < q/2^(d+1). A raw
right shift cannot provide that guarantee at bin boundaries. This module uses
a public low-part reconciliation hint: encryption moves each value to the
nearest quantization centre and publishes only the signed displacement.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .arithmetic import Array, canonical_mod, centered


@dataclass(frozen=True)
class ReconciliationResult:
    extracted: bytes
    hint: Array


def _nearest_level(value: int, q: int, levels: int) -> int:
    return ((2 * value * levels + q) // (2 * q)) % levels


def _level_center(level: int, q: int, levels: int) -> int:
    return (2 * level * q + levels) // (2 * levels)


def encode_levels(level_values: list[int], keep_bits: int) -> bytes:
    width = (keep_bits + 7) // 8
    return b"".join(int(value).to_bytes(width, "little") for value in level_values)


def prepare_reconciliation(value: Array, q: int, keep_bits: int) -> ReconciliationResult:
    canonical = canonical_mod(value, q)
    levels = 1 << keep_bits
    indices: list[int] = []
    hint = np.empty(canonical.shape, dtype=np.int64)
    for flat_index, raw in enumerate(canonical.flat):
        v = int(raw)
        level = _nearest_level(v, q, levels)
        centre = _level_center(level, q, levels) % q
        indices.append(level)
        hint.flat[flat_index] = int(centered(np.asarray([v - centre]), q)[0])
    return ReconciliationResult(encode_levels(indices, keep_bits), hint)


def reconcile(value: Array, hint: Array, q: int, keep_bits: int) -> bytes:
    canonical = canonical_mod(value, q)
    hint_array = np.asarray(hint)
    if hint_array.shape != canonical.shape:
        raise ValueError("reconciliation hint shape mismatch")
    levels = 1 << keep_bits
    indices: list[int] = []
    for raw, displacement in zip(canonical.flat, hint_array.flat):
        adjusted = (int(raw) - int(displacement)) % q
        indices.append(_nearest_level(adjusted, q, levels))
    return encode_levels(indices, keep_bits)
