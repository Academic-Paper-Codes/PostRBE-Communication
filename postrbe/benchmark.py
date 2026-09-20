"""Benchmark helpers for PostRBE and PostRBE* prototypes."""
from __future__ import annotations

import csv
import gc
import platform as platform_module
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
    registration_upload_ms: float
    register_ms: float
    update_ms: float
    encrypt_ms: float
    decrypt_ms: float
    decrypt_update_ms: float
    membership_verify_ms: float
    nonmembership_verify_ms: float
    total_ms: float
    correct: bool
    device: str
    platform: str
    result_type: str
    measured_N: int
    measured_B: int
    arithmetic_backend: str
    source_file: str
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
    result_type: str
    size_representation: str
    source_file: str


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
    up_with_upload, registration_upload_ms = _time_call(lambda: scheme.add_registration_upload(sk, up))
    _, register_ms = _time_call(lambda: scheme.register(identity, up_with_upload))
    proof, update_ms = _time_call(lambda: scheme.update(identity))
    ct, encrypt_ms = _time_call(lambda: scheme.encrypt(identity, message))
    recovered, decrypt_ms = _time_call(lambda: scheme.decrypt(sk, proof, ct))
    ok = recovered == message
    verified, membership_ms = _time_call(lambda: scheme.verify_membership(identity, up_with_upload.pk, proof))
    nonmember, nonmembership_ms = _time_call(lambda: scheme.verify_nonmembership(identity, proof))
    audit = scheme.correctness_audit(sk, proof, ct)
    ok = bool(ok and verified and not nonmember and audit.within_bound and audit.reconciliation_matches)

    decrypt_update_ms = decrypt_ms + update_ms
    total = (
        setup_ms + keygen_ms + registration_upload_ms + register_ms + update_ms
        + encrypt_ms + decrypt_ms + membership_ms + nonmembership_ms
    )
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
        registration_upload_ms=registration_upload_ms,
        register_ms=register_ms,
        update_ms=update_ms,
        encrypt_ms=encrypt_ms,
        decrypt_ms=decrypt_ms,
        decrypt_update_ms=decrypt_update_ms,
        membership_verify_ms=membership_ms,
        nonmembership_verify_ms=nonmembership_ms,
        total_ms=total,
        correct=ok,
        device=platform_module.processor() or "unknown_cpu",
        platform=platform_module.platform(),
        result_type="functional_demo_not_paper_result",
        measured_N=params.N,
        measured_B=params.B,
        arithmetic_backend=params.arithmetic_backend,
        source_file="run_experiments.py",
        note=(
            "functional_demo_not_paper_result; arithmetic=python_bigint; "
            f"noise_inf={audit.noise_infinity_norm}; threshold={audit.allowed_threshold:.3f}"
        ),
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
            result_type="formula_size",
            size_representation=(
                "paper_byte_aligned_formula" if not k.startswith("functional_")
                else "functional_component_byte_aligned"
            ),
            source_file="postrbe/benchmark.py",
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
        "registration_upload_ms",
        "register_ms",
        "update_ms",
        "encrypt_ms",
        "decrypt_ms",
        "decrypt_update_ms",
        "membership_verify_ms",
        "nonmembership_verify_ms",
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
            "q_runtime": vals[0].q_runtime,
            "d": key[8],
            "sigma_inf": key[9],
            "message_bits": key[10],
            "short_min": -key[9],
            "short_max": key[9],
            "repeats": len(vals),
            "all_correct": all(v.correct for v in vals),
            "result_type": vals[0].result_type,
            "arithmetic_backend": vals[0].arithmetic_backend,
            "device": vals[0].device,
            "platform": vals[0].platform,
            "source_file": vals[0].source_file,
            "measured_N": vals[0].measured_N,
            "measured_B": vals[0].measured_B,
        }
        for metric in metrics:
            xs = [getattr(v, metric) for v in vals]
            item[f"{metric}_mean"] = statistics.mean(xs)
            item[f"{metric}_median"] = statistics.median(xs)
            item[f"{metric}_stdev"] = statistics.stdev(xs) if len(xs) > 1 else 0.0
            item[f"{metric}_min"] = min(xs)
            item[f"{metric}_max"] = max(xs)
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
