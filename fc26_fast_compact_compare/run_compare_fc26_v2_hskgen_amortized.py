#!/usr/bin/env python3
"""
Comparison data generator for:
  Fast and Compact Lattice-Based Registration-Based Encryption (ePrint 2026)

This paper contains two RBE schemes:
  1. Base RBE
  2. More Efficient RBE

Goal:
  Produce CSV files compatible with the existing six_plot_data_clean.csv format:
    scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits

Important modelling notes:
  - This is a benchmark/estimation model, not a production cryptographic implementation.
  - The formulas and anchors are derived from the paper's algorithm descriptions and benchmark tables.
  - Common parameters are recorded according to the user's unified experimental setting:
      N = 10^3,10^4,10^5,10^6,10^7
      B = ceil(sqrt(N)) in the clean CSV, for compatibility with PostRBE data
      n=256, m=512, r=128, q_bits=64, d=10, sigma_inf=2, short_range={-2,-1,0,1,2}, message_bits=256
  - The paper's own internal parameters are also kept in operation_counts.csv:
      identity_len_l, ring_degree_nR, table_q_bits, decomposition_base_internal
  - HskGen/update cost supports three models:
      amortized_log: scale the S=1000 anchor by log2(N)/log2(1000) [default]
      worst_linear: old conservative model, scale by N/1000
      constant: keep the S=1000 anchor unchanged
  - In this paper, d=64 in the implementation means d-ary decomposition base, not F[.] high-bit extraction.
    Therefore, it is NOT overwritten by the unified d=10. The clean CSV still records d=10 only to match format.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


TARGET_N = [10**3, 10**4, 10**5, 10**6, 10**7]

# Unified parameters used in previous PostRBE experiments.
UNIFIED_N = 256
UNIFIED_M = 512
UNIFIED_R = 128
UNIFIED_D = 10             # F[.] high-bit extraction parameter in our PostRBE data format.
UNIFIED_Q_BITS = 64
UNIFIED_SIGMA_INF = 2
UNIFIED_SHORT_RANGE = "{-2,-1,0,1,2}"
UNIFIED_MESSAGE_BITS = 256

# Paper benchmark defaults.
# The paper uses q as a 59-bit NTT-friendly prime and implementation base decomposition d=64.
PAPER_TABLE_Q_BITS = 59
PAPER_DECOMP_BASE = 64
PAPER_IDENTITY_LEN = 50
PAPER_RING_DEGREE = 256


@dataclass(frozen=True)
class Anchor:
    setup_ms: float
    reg_ms: float
    enc_ms: float
    hskgen_ms_at_1000: float
    dec_ms: float
    crs_mb: float
    ct_mb: float
    aux_mb_at_1000: float


# Benchmarks from the paper, Table 2 and Table 3, using Rq=Zq[X]/(X^256+1), S=1000.
# Base RBE: Setup 139, Reg 0.0155, Enc 11.3, HskGen 12383, Dec 18.9, crs 17, ct 4.1, aux 1520.5.
# More Efficient RBE: Setup 2.3e6, Reg 0.0145, Enc 1.91, HskGen 12921, Dec 0.956, crs 9.5e3, ct 0.148, aux 394.5.
ANCHORS: Dict[str, Anchor] = {
    "FC26-BaseRBE": Anchor(
        setup_ms=139.0,
        reg_ms=0.0155,
        enc_ms=11.3,
        hskgen_ms_at_1000=12383.0,
        dec_ms=18.9,
        crs_mb=17.0,
        ct_mb=4.1,
        aux_mb_at_1000=1520.5,
    ),
    "FC26-MoreEfficientRBE": Anchor(
        setup_ms=2.3e6,
        reg_ms=0.0145,
        enc_ms=1.91,
        hskgen_ms_at_1000=12921.0,
        dec_ms=0.956,
        crs_mb=9.5e3,
        ct_mb=0.148,
        aux_mb_at_1000=394.5,
    ),
}


def ceil_sqrt(n: int) -> int:
    return math.ceil(math.sqrt(n))


def ceil_log2(n: int) -> int:
    return math.ceil(math.log2(n))


def mb_to_mib(mb: float) -> float:
    """Treat paper MB as decimal MB and convert to MiB for consistency with previous plots."""
    return (mb * 1_000_000.0) / (1024.0 * 1024.0)


def scale_size_for_qbits(size_mib: float, q_bits: int, table_q_bits: int = PAPER_TABLE_Q_BITS) -> float:
    """Scale storage linearly by bits per coefficient.

    The original benchmark table uses q as a 59-bit prime. Our unified comparison uses q_bits=64.
    Since sizes count coefficient representations, we scale by q_bits / 59.
    """
    return size_mib * (q_bits / float(table_q_bits))


def identity_scale(identity_len: int, anchor_identity_len: int = PAPER_IDENTITY_LEN) -> float:
    """Scale identity-length-dependent costs when requested.

    Default identity_len is 50, so this returns 1.0. If the user later wants l=ceil(log2 N),
    this can be used for rough scaling.
    """
    return identity_len / float(anchor_identity_len)


def compute_hskgen_ms(anchor_ms_at_1000: float, N: int, model: str) -> float:
    """Estimate one HskGen/update cost under the selected model.

    The FC26 paper reports HskGen at S=1000 and states that fresh HskGen
    is O(N) in the worst case, while updates/amortized HskGen are O(log N).
    For our decryption-related-operation plot, the amortized update model is
    the intended default; worst_linear is kept only for sensitivity checks.
    """
    if model == "worst_linear":
        return anchor_ms_at_1000 * (N / 1000.0)
    if model == "amortized_log":
        return anchor_ms_at_1000 * (ceil_log2(N) / float(ceil_log2(1000)))
    if model == "constant":
        return anchor_ms_at_1000
    raise ValueError(f"Unsupported hskgen model: {model}")


def compute_for_scheme(
    scheme: str,
    N: int,
    *,
    q_bits: int,
    identity_len: int,
    hskgen_model: str,
    use_log_identity_len: bool = False,
    scale_time_by_identity_len: bool = False,
    scale_sizes_by_qbits: bool = True,
) -> Dict[str, float | int | str]:
    a = ANCHORS[scheme]
    B_clean = ceil_sqrt(N)
    l_internal = ceil_log2(N) if use_log_identity_len else identity_len

    # HskGen/update cost. The old script used a linear N/1000 extrapolation,
    # which corresponds to a worst-case fresh helper-key generation. For the
    # decryption-related operation in the plots, we use amortized_log by default,
    # following the paper's statement that HskGen/update is O(log N) amortized.
    hskgen_ms = compute_hskgen_ms(a.hskgen_ms_at_1000, N, hskgen_model)

    # Setup, Enc, Dec in the benchmark are mostly independent of S but depend on ring degree and identity length.
    # We keep the benchmark identity length by default. Optional identity scaling is provided.
    id_scale = identity_scale(l_internal) if scale_time_by_identity_len else 1.0

    setup_ms = a.setup_ms * id_scale
    keygen_ms = 0.0
    # The paper does not tabulate KeyGen separately. It is lightweight compared with the listed operations.
    # We estimate it from dual-Regev-like key generation as a small constant.
    # This can be changed with --keygen-ms.
    reg_ms = a.reg_ms
    enc_ms = a.enc_ms * id_scale
    dec_ms = a.dec_ms * id_scale
    decrypt_update_ms = hskgen_ms + dec_ms

    ct_mib = mb_to_mib(a.ct_mb)
    crs_mib = mb_to_mib(a.crs_mb)
    aux_mib = mb_to_mib(a.aux_mb_at_1000) * (N / 1000.0)
    if scale_sizes_by_qbits:
        ct_mib = scale_size_for_qbits(ct_mib, q_bits)
        crs_mib = scale_size_for_qbits(crs_mib, q_bits)
        aux_mib = scale_size_for_qbits(aux_mib, q_bits)

    # Work-unit style proxies for transparency. These are not used directly in clean plots.
    # They are derived by normalising ms against the paper anchors only.
    return {
        "scheme": scheme,
        "N": N,
        "B": B_clean,
        "B_logN": ceil_log2(N),
        "identity_len_l": l_internal,
        "ring_degree_nR": PAPER_RING_DEGREE,
        "table_q_bits": PAPER_TABLE_Q_BITS,
        "q_bits": q_bits,
        "decomposition_base_internal": PAPER_DECOMP_BASE,
        "n": UNIFIED_N,
        "m": UNIFIED_M,
        "r": UNIFIED_R,
        "t": "NA",
        "d": UNIFIED_D,
        "sigma_inf": UNIFIED_SIGMA_INF,
        "short_range": UNIFIED_SHORT_RANGE,
        "message_bits": UNIFIED_MESSAGE_BITS,
        "Setup_ms": setup_ms,
        "KeyGen_ms": keygen_ms,
        "Register_ms": reg_ms,
        "Encrypt_ms": enc_ms,
        "HskGen_ms": hskgen_ms,
        "Dec_ms": dec_ms,
        "DecryptUpdate_ms": decrypt_update_ms,
        "HskGen_model": hskgen_model,
        "Ciphertext_mib": ct_mib,
        "CRS_mib": crs_mib,
        "Aux_mib": aux_mib,
        "note": (
            "Estimated from paper benchmark anchors; q_bits unified to 64 for size accounting. "
            f"DecryptUpdate = HskGen + Dec, with HskGen_model={hskgen_model}. "
            "Internal decomposition base remains paper d=64, not F[.] d=10."
        ),
    }


def write_csv(path: str, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    print(f"Wrote: {path}")


def build_rows(args: argparse.Namespace) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for scheme in ["FC26-BaseRBE", "FC26-MoreEfficientRBE"]:
        for N in args.N:
            row = compute_for_scheme(
                scheme,
                int(N),
                q_bits=args.q_bits,
                identity_len=args.identity_len,
                hskgen_model=args.hskgen_model,
                use_log_identity_len=args.use_log_identity_len,
                scale_time_by_identity_len=args.scale_time_by_identity_len,
                scale_sizes_by_qbits=not args.no_scale_sizes_by_qbits,
            )
            if args.keygen_ms is not None:
                row["KeyGen_ms"] = float(args.keygen_ms)
            rows.append(row)
    return rows


def build_six_plot_rows(op_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    metrics = [
        ("Setup", "Setup_ms", "ms"),
        ("KeyGen", "KeyGen_ms", "ms"),
        ("Register", "Register_ms", "ms"),
        ("Encrypt", "Encrypt_ms", "ms"),
        ("DecryptUpdate", "DecryptUpdate_ms", "ms"),
        ("CiphertextSizes", "Ciphertext_mib", "MiB"),
    ]
    clean_rows: List[Dict[str, object]] = []
    for row in op_rows:
        for metric, src, unit in metrics:
            clean_rows.append({
                "scheme": row["scheme"],
                "N": row["N"],
                "B": row["B"],
                "metric": metric,
                "plot_value": row[src],
                "plot_unit": unit,
                "n": row["n"],
                "m": row["m"],
                "r": row["r"],
                "t": row["t"],
                "q_bits": row["q_bits"],
                "d": row["d"],
                "sigma_inf": row["sigma_inf"],
                "short_range": row["short_range"],
                "message_bits": row["message_bits"],
            })
    return clean_rows


def build_sizes_rows(op_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    sizes: List[Dict[str, object]] = []
    for row in op_rows:
        for item, src, unit in [
            ("ciphertext", "Ciphertext_mib", "MiB"),
            ("crs", "CRS_mib", "MiB"),
            ("aux", "Aux_mib", "MiB"),
        ]:
            sizes.append({
                "scheme": row["scheme"],
                "N": row["N"],
                "B": row["B"],
                "B_logN": row["B_logN"],
                "item": item,
                "value": row[src],
                "unit": unit,
                "n": row["n"],
                "m": row["m"],
                "r": row["r"],
                "t": row["t"],
                "q_bits": row["q_bits"],
                "d": row["d"],
                "sigma_inf": row["sigma_inf"],
                "short_range": row["short_range"],
                "message_bits": row["message_bits"],
                "identity_len_l": row["identity_len_l"],
                "ring_degree_nR": row["ring_degree_nR"],
                "decomposition_base_internal": row["decomposition_base_internal"],
            })
    return sizes


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate comparison CSVs for FC26 Base RBE and More Efficient RBE.")
    p.add_argument("--target", action="store_true", help="Use target N = 1e3,1e4,1e5,1e6,1e7.")
    p.add_argument("--N", nargs="*", type=int, default=None, help="Custom N list.")
    p.add_argument("--out", default="results_fc26", help="Output directory.")
    p.add_argument("--q-bits", type=int, default=UNIFIED_Q_BITS, help="Unified q bit length for size accounting.")
    p.add_argument("--identity-len", type=int, default=PAPER_IDENTITY_LEN, help="Internal identity length l. Default uses paper l=50.")
    p.add_argument("--use-log-identity-len", action="store_true", help="Set internal identity length l=ceil(log2(N)). Off by default.")
    p.add_argument("--scale-time-by-identity-len", action="store_true", help="Roughly scale setup/enc/dec by l/50. Off by default.")
    p.add_argument("--no-scale-sizes-by-qbits", action="store_true", help="Do not scale paper size anchors from 59-bit q to q_bits.")
    p.add_argument("--keygen-ms", type=float, default=0.12, help="Estimated KeyGen time in ms. Default 0.12 ms.")
    p.add_argument(
        "--hskgen-model",
        choices=["amortized_log", "worst_linear", "constant"],
        default="amortized_log",
        help=(
            "Model for HskGen/update cost. amortized_log follows the paper's O(log N) "
            "amortized update discussion and is the default. worst_linear reproduces the "
            "old conservative N/1000 extrapolation. constant keeps the S=1000 anchor."
        ),
    )
    args = p.parse_args()
    if args.target or args.N is None:
        args.N = TARGET_N
    return args


def main() -> None:
    args = parse_args()
    op_rows = build_rows(args)
    six_rows = build_six_plot_rows(op_rows)
    size_rows = build_sizes_rows(op_rows)

    op_fields = [
        "scheme", "N", "B", "B_logN", "identity_len_l", "ring_degree_nR", "table_q_bits", "q_bits",
        "decomposition_base_internal", "n", "m", "r", "t", "d", "sigma_inf", "short_range", "message_bits",
        "Setup_ms", "KeyGen_ms", "Register_ms", "Encrypt_ms", "HskGen_ms", "Dec_ms", "DecryptUpdate_ms",
        "HskGen_model", "Ciphertext_mib", "CRS_mib", "Aux_mib", "note",
    ]
    six_fields = [
        "scheme", "N", "B", "metric", "plot_value", "plot_unit",
        "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "short_range", "message_bits",
    ]
    size_fields = [
        "scheme", "N", "B", "B_logN", "item", "value", "unit",
        "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "short_range", "message_bits",
        "identity_len_l", "ring_degree_nR", "decomposition_base_internal",
    ]
    write_csv(os.path.join(args.out, "operation_counts.csv"), op_rows, op_fields)
    write_csv(os.path.join(args.out, "sizes_estimated.csv"), size_rows, size_fields)
    write_csv(os.path.join(args.out, "six_plot_data_clean.csv"), six_rows, six_fields)

    print("Unified clean CSV params: n=256, m=512, r=128, q_bits=64, d=10, sigma_inf=2, short_range={-2,-1,0,1,2}.")
    print("This file contains two schemes: FC26-BaseRBE and FC26-MoreEfficientRBE.")
    print(f"Note: DecryptUpdate = HskGen + Dec, with HskGen model = {args.hskgen_model}.")
    print("      Use --hskgen-model worst_linear to reproduce the old conservative linear extrapolation.")
    print("Note: paper internal decomposition base d=64 is kept as decomposition_base_internal and is not the same as F[.] d=10.")


if __name__ == "__main__":
    main()
