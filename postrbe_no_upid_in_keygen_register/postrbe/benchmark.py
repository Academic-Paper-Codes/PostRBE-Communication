"""Benchmark helpers for PostRBE and PostRBE* prototypes."""
from __future__ import annotations

import csv
import gc
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Type

from .params import RBEParams
from .schemes import PostRBE, PostRBEStar


SCHEMES = {
    "PostRBE": PostRBE,
    "PostRBE*": PostRBEStar,
    "PostRBEStar": PostRBEStar,
}


@dataclass
class TimingRow:
    scheme: str
    N: int
    B: int
    n: int
    m: int
    r: int
    t: int
    q_bits: int
    q_runtime: int
    d: int
    sigma_inf: int
    short_min: int
    short_max: int
    message_bits: int
    repeat: int
    setup_ms: float
    keygen_ms: float
    register_ms: float
    update_ms: float
    encrypt_ms: float
    decrypt_ms: float
    decrypt_update_ms: float
    membership_verify_ms: float
    total_ms: float
    correct: bool
    note: str = ""


@dataclass
class SizeRow:
    scheme: str
    N: int
    B: int
    n: int
    m: int
    r: int
    t: int
    q_bits: int
    d: int
    sigma_inf: int
    message_bits: int
    item: str
    bytes: int
    kib: float
    mib: float


def _time_call(fn):
    start = time.perf_counter()
    out = fn()
    end = time.perf_counter()
    return out, (end - start) * 1000.0


def run_one(scheme_name: str, params: RBEParams, repeat: int = 0, message: bytes | None = None) -> TimingRow:
    params = params.with_t_for_scheme("postrbe" if scheme_name == "PostRBE" else "star")
    params.validate()
    cls: Type = SCHEMES[scheme_name]
    scheme = cls(params)
    if message is None:
        message = bytes([0x42]) * params.message_bytes

    _, setup_ms = _time_call(scheme.setup)
    identity = 1
    # Revised convention: KeyGen excludes up_id / registration upload data.
    # Register also excludes up_id generation. We precompute up_id outside timing
    # to simulate the curator receiving (pk, up_id), then measure only the
    # curator-side registration update.
    (sk, up), keygen_ms = _time_call(lambda: scheme.keygen(identity, include_upload=False))
    up_with_upload = scheme.add_registration_upload(sk, up)  # intentionally not timed
    _, register_ms = _time_call(lambda: scheme.register(identity, up_with_upload))
    opening, update_ms = _time_call(lambda: scheme.update(identity))
    ct, encrypt_ms = _time_call(lambda: scheme.encrypt(identity, message))
    recovered, decrypt_ms = _time_call(lambda: scheme.decrypt(sk, opening, ct))
    ok = recovered == message
    verified, membership_ms = _time_call(lambda: scheme.membership_verify(identity, sk, opening))
    ok = bool(ok and verified)

    decrypt_update_ms = decrypt_ms + update_ms
    total = setup_ms + keygen_ms + register_ms + update_ms + encrypt_ms + decrypt_ms + membership_ms
    return TimingRow(
        scheme=scheme_name,
        N=params.N,
        B=params.B,
        n=params.n,
        m=params.m,
        r=params.r,
        t=int(params.t),
        q_bits=params.q_bits,
        q_runtime=params.q,
        d=params.keep_bits,
        sigma_inf=params.sigma_inf,
        short_min=params.short_min,
        short_max=params.short_max,
        message_bits=params.message_bits,
        repeat=repeat,
        setup_ms=setup_ms,
        keygen_ms=keygen_ms,
        register_ms=register_ms,
        update_ms=update_ms,
        encrypt_ms=encrypt_ms,
        decrypt_ms=decrypt_ms,
        decrypt_update_ms=decrypt_update_ms,
        membership_verify_ms=membership_ms,
        total_ms=total,
        correct=ok,
    )


def size_rows_for(scheme_name: str, params: RBEParams) -> List[SizeRow]:
    params = params.with_t_for_scheme("postrbe" if scheme_name == "PostRBE" else "star")
    scheme = SCHEMES[scheme_name](params)
    sizes = scheme.estimated_sizes_bytes()
    return [
        SizeRow(
            scheme=scheme_name,
            N=params.N,
            B=params.B,
            n=params.n,
            m=params.m,
            r=params.r,
            t=int(params.t),
            q_bits=params.q_bits,
            d=params.keep_bits,
            sigma_inf=params.sigma_inf,
            message_bits=params.message_bits,
            item=k,
            bytes=int(v),
            kib=float(v) / 1024,
            mib=float(v) / (1024 * 1024),
        )
        for k, v in sizes.items()
    ]


def write_csv(path: Path, rows: Iterable[object]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def summarize(rows: List[TimingRow]) -> List[Dict[str, object]]:
    groups: Dict[tuple, List[TimingRow]] = {}
    for r in rows:
        key = (r.scheme, r.N, r.B, r.n, r.m, r.r, r.t, r.q_bits, r.d, r.sigma_inf, r.message_bits)
        groups.setdefault(key, []).append(r)
    out = []
    metrics = [
        "setup_ms",
        "keygen_ms",
        "register_ms",
        "update_ms",
        "encrypt_ms",
        "decrypt_ms",
        "decrypt_update_ms",
        "membership_verify_ms",
        "total_ms",
    ]
    for key, vals in groups.items():
        item = {
            "scheme": key[0],
            "N": key[1],
            "B": key[2],
            "n": key[3],
            "m": key[4],
            "r": key[5],
            "t": key[6],
            "q_bits": key[7],
            "d": key[8],
            "sigma_inf": key[9],
            "message_bits": key[10],
            "short_min": -key[9],
            "short_max": key[9],
            "repeats": len(vals),
            "all_correct": all(v.correct for v in vals),
        }
        for metric in metrics:
            xs = [getattr(v, metric) for v in vals]
            item[f"{metric}_mean"] = statistics.mean(xs)
            item[f"{metric}_stdev"] = statistics.stdev(xs) if len(xs) > 1 else 0.0
        out.append(item)
    return out


def write_summary_csv(path: Path, summary_rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not summary_rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        for row in summary_rows:
            writer.writerow(row)
