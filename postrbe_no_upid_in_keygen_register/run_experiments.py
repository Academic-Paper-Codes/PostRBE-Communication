#!/usr/bin/env python3
"""Run PostRBE/PostRBE* timing experiments and write CSV files.

Default unified target parameters:
  N = 10^3,10^4,10^5,10^6,10^7
  n=256, m=512, r=128, d=10, q_bits=64, sigma_inf=2
  PostRBE:  t=(B-1)m+n+1
  PostRBE*: t=512

For very large t, especially PostRBE with N>=10^5, direct dense matrices are
impractical. Use --opcounts-only to produce measurement/planning data without
allocating dense matrices.
"""
from __future__ import annotations

import os
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

import argparse
import csv
import gc
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

from postrbe.benchmark import run_one, size_rows_for, summarize, write_csv, write_summary_csv
from postrbe.models import opcount_postrbe, opcount_postrbe_star
from postrbe.params import RBEParams


def parse_nm(items: List[str]) -> List[Tuple[int, int]]:
    out = []
    for x in items:
        a, b = x.split(",")
        out.append((int(a), int(b)))
    return out


def make_params(args, N: int, n: int, m: int, scheme: str, rep_seed_offset: int = 0) -> RBEParams:
    t = None
    if scheme == "PostRBE*" and args.star_t is not None:
        t = args.star_t
    if scheme == "PostRBE" and args.base_t is not None:
        t = args.base_t
    return RBEParams(
        N=N,
        n=n,
        m=m,
        r=args.r,
        t=t,
        q=args.q_runtime,
        q_bits=args.q_bits,
        sigma_inf=args.sigma_inf,
        keep_bits=args.d,
        message_bits=args.message_bits,
        seed=args.seed + rep_seed_offset,
    ).with_t_for_scheme("postrbe" if scheme == "PostRBE" else "star")


def write_six_required_csv(outdir: Path, op_rows: list[dict]) -> None:
    """Write compact rows for the six target figures/tables.

    Computation metrics are represented as operation-count work units. For Setup,
    randomness generation entries are included because setup is dominated by
    matrix generation in this prototype/model.
    """
    rows = []
    for r in op_rows:
        common = {k: r[k] for k in ["scheme", "N", "B", "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "message_bits"]}
        common["short_min"] = r["short_min"]
        common["short_max"] = r["short_max"]
        metrics = [
            ("Setup", int(r["setup_rand_entries"]) + int(r["setup_muladds"]), "work_units"),
            ("KeyGen", int(r["keygen_muladds"]), "muladds"),
            ("Register", int(r["register_muladds"]), "muladds"),
            ("Encrypt", int(r["encrypt_muladds"]), "muladds"),
            ("DecryptUpdate", int(r["decrypt_update_muladds"]), "muladds"),
            ("CiphertextSizes", int(r["ciphertext_bytes"]), "bytes"),
        ]
        for metric, value, unit in metrics:
            item = dict(common)
            item.update({"metric": metric, "value": value, "unit": unit})
            if unit == "bytes":
                item["value_kib"] = value / 1024
                item["value_mib"] = value / (1024 * 1024)
            else:
                item["value_kib"] = ""
                item["value_mib"] = ""
            rows.append(item)
    if rows:
        with (outdir / "six_required_data.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small fast demo parameters")
    ap.add_argument("--target", action="store_true", help="use unified target parameters from the thesis experiment")
    ap.add_argument("--schemes", nargs="+", default=["PostRBE", "PostRBE*"], choices=["PostRBE", "PostRBE*"])
    ap.add_argument("--N", nargs="+", type=int, default=[100])
    ap.add_argument("--nm", nargs="+", default=["16,32"], help="list like 16,32 32,64")
    ap.add_argument("--r", type=int, default=16)
    ap.add_argument("--base-t", type=int, default=None, help="debug override for PostRBE t; normally leave unset")
    ap.add_argument("--star-t", type=int, default=None, help="PostRBE* fixed t; target uses 512")
    ap.add_argument("--q-runtime", type=int, default=2_147_483_647, help="runtime modulus for executable prototype only")
    ap.add_argument("--q-bits", type=int, default=64, help="paper modulus bit length used for size accounting")
    ap.add_argument("--sigma-inf", type=int, default=2, help="infinity norm bound; entries sampled from [-sigma,sigma]")
    ap.add_argument("--d", type=int, default=10, help="number of high bits extracted by F[·]")
    ap.add_argument("--message-bits", type=int, default=256)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--seed", type=int, default=12345)
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("--opcounts-only", action="store_true", help="skip timing, only write operation counts and size estimates")
    args = ap.parse_args()

    if args.quick:
        args.N = [16, 64]
        args.nm = ["8,16", "12,24"]
        args.r = 8
        args.star_t = 16
        args.repeats = 2
        args.message_bits = 256

    if args.target:
        args.N = [1000, 10000, 100000, 1000000, 10000000]
        args.nm = ["256,512"]
        args.r = 128
        args.star_t = 512
        args.q_bits = 64
        args.sigma_inf = 2
        args.d = 10
        args.message_bits = 256

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    timing_rows = []
    size_rows = []
    op_rows = []

    for N in args.N:
        for n, m in parse_nm(args.nm):
            for scheme in args.schemes:
                p = make_params(args, N, n, m, scheme)
                size_rows.extend(size_rows_for(scheme, p))
                op = opcount_postrbe(p) if scheme == "PostRBE" else opcount_postrbe_star(p)
                op_rows.append(asdict(op))
                if args.opcounts_only:
                    continue
                for rep in range(args.repeats):
                    p_rep = make_params(args, N, n, m, scheme, rep_seed_offset=rep)
                    row = run_one(scheme, p_rep, repeat=rep)
                    timing_rows.append(row)
                    print(
                        f"{scheme:8s} N={N:<8d} n={n:<4d} m={m:<4d} r={args.r:<4d} t={p.t:<8d} "
                        f"rep={rep} setup={row.setup_ms:.3f}ms keygen={row.keygen_ms:.3f}ms "
                        f"reg={row.register_ms:.3f}ms enc={row.encrypt_ms:.3f}ms "
                        f"dec+upd={row.decrypt_update_ms:.3f}ms ok={row.correct}"
                    )
                    gc.collect()

    write_csv(outdir / "timings_raw.csv", timing_rows)
    write_summary_csv(outdir / "timings_summary.csv", summarize(timing_rows))
    write_csv(outdir / "sizes_estimated.csv", size_rows)

    if op_rows:
        with (outdir / "operation_counts.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(op_rows[0].keys()))
            writer.writeheader()
            writer.writerows(op_rows)
        write_six_required_csv(outdir, op_rows)

    print(f"\nWrote results to: {outdir.resolve()}", flush=True)


if __name__ == "__main__":
    main()
