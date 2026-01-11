# -*- coding: utf-8 -*-
"""
bench_postrbe_base_v1.py

Real (measured) micro-benchmarks for PostRBE (base) implementation.

Why "micro"?
- In your base scheme, t = B*m + n and B = floor(sqrt(N_max)).
- For N up to 1e6 and (n,m) in (256,512)/(256,1024)/(512,1024), t becomes enormous
  (e.g., B=1000 => t ≈ 512256), which is not feasible to instantiate as dense numpy matrices.
- So this script measures the real runtime at a feasible cap B_cap (default 10),
  and ALSO produces an extrapolated estimate for larger N by scaling the dominant
  linear terms in B and N (you can disable extrapolation).

Outputs:
- CSV files in ./Figure-Exp-Data/ with columns:
  op, n, m, N_target, B_target, B_used, mode(measured/extrapolated), repeats, time_ms_mean, time_ms_std

Usage examples:
  python bench_postrbe_base_v1.py
  python bench_postrbe_base_v1.py --pairs 256,512 256,1024 512,1024 --Ns 1e2 1e4 1e6 --B_cap 10
"""

import argparse
import math
import os
import time
import statistics
from typing import Any, Dict, Tuple, List

import numpy as np

# ---- import your implementation ----
from postrbe_core import setup, keygen, register, encrypt, decrypt, update

# dataclasses (may not be used by your core, but we adapt)
from postrbe_structs import CRS, PublicParams, AuxParams


def _as_crs_pp_aux(crs_obj, pp_obj, aux_obj):
    """
    Accept either dict-based objects or dataclass instances.
    Return: (CRS, PublicParams, AuxParams)
    """
    if isinstance(crs_obj, CRS) and isinstance(pp_obj, PublicParams) and isinstance(aux_obj, AuxParams):
        return crs_obj, pp_obj, aux_obj

    if isinstance(crs_obj, dict):
        crs = CRS(
            N_max=crs_obj["N_max"],
            B=crs_obj["B"],
            q=crs_obj["q"],
            n=crs_obj["n"],
            m=crs_obj["m"],
            t=crs_obj["t"],
            A_list=crs_obj["A_list"],
            U_list=crs_obj["U_list"],
            T_mat=crs_obj["T_mat"],
            hash_name=crs_obj.get("hash_name", "sha256"),
            se_mode=crs_obj.get("se_mode", "AEAD"),
        )
    else:
        raise TypeError(f"Unsupported CRS type: {type(crs_obj)}")

    if isinstance(pp_obj, dict):
        pp = PublicParams(C_list=pp_obj["C_list"])
    else:
        raise TypeError(f"Unsupported PP type: {type(pp_obj)}")

    if isinstance(aux_obj, dict):
        aux = AuxParams(L_mat=aux_obj["L_mat"])
    else:
        raise TypeError(f"Unsupported AUX type: {type(aux_obj)}")

    return crs, pp, aux


def time_op(fn, repeats: int, warmups: int = 2):
    """Return (mean_ms, std_ms) over repeats, after warmups."""
    for _ in range(warmups):
        fn()

    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)

    mean_ms = statistics.mean(times)
    std_ms = statistics.pstdev(times) if len(times) > 1 else 0.0
    return mean_ms, std_ms


def extrapolate_linear_in_B(measured_ms: float, B_used: int, B_target: int) -> float:
    """Simple scaling: time_target ≈ time_measured * (B_target / B_used)."""
    if B_used <= 0:
        return measured_ms
    return measured_ms * (B_target / B_used)


def ensure_outdir() -> str:
    d = os.path.join(os.path.dirname(__file__), "Figure-Exp-Data")
    os.makedirs(d, exist_ok=True)
    return d


def save_rows_csv(path: str, rows: List[Dict[str, Any]]):
    import csv
    if not rows:
        return
    keys = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def bench_one_pair(n: int, m: int, Ns: List[int], B_cap: int, repeats: int, do_extrapolate: bool):
    rows = []

    for N_target in Ns:
        B_target = int(math.isqrt(int(N_target)))
        B_used = min(B_target, B_cap)
        N_used = B_used * B_used

        crs0, pp0, aux0 = setup(security_param=128, N_max=N_used, n=n, m=m)
        crs, pp, aux = _as_crs_pp_aux(crs0, pp0, aux0)

        user_id = min(7, max(0, N_used - 1))

        # KeyGen
        kg_mean, kg_std = time_op(lambda: keygen(user_id, crs), repeats=repeats)

        # Register (includes keygen per repeat)
        def _reg_once():
            user = keygen(user_id, crs)
            register(user, crs, pp, aux)

        reg_mean, reg_std = time_op(_reg_once, repeats=repeats)

        # Fixed user for enc/dec
        msg = b"bench message"
        user_fixed = keygen(user_id, crs)
        register(user_fixed, crs, pp, aux)

        enc_mean, enc_std = time_op(lambda: encrypt(pp, crs, user_id, msg), repeats=repeats)

        ct_fixed = encrypt(pp, crs, user_id, msg)
        dec_mean, dec_std = time_op(lambda: decrypt(user_fixed, crs, aux, ct_fixed), repeats=repeats)

        upd_mean, upd_std = time_op(lambda: update(user_id, crs, aux), repeats=repeats)

        measured = [
            ("KeyGen", kg_mean, kg_std),
            ("Register", reg_mean, reg_std),
            ("Encrypt_P1_R1", enc_mean, enc_std),
            ("Decrypt_single", dec_mean, dec_std),
            ("Update", upd_mean, upd_std),
        ]

        for op, mean_ms, std_ms in measured:
            rows.append({
                "op": op,
                "n": n,
                "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "mode": "measured",
                "repeats": int(repeats),
                "time_ms_mean": float(mean_ms),
                "time_ms_std": float(std_ms),
            })

        if do_extrapolate and B_target > B_used:
            for op, mean_ms, std_ms in measured:
                rows.append({
                    "op": op,
                    "n": n,
                    "m": m,
                    "N_target": int(N_target),
                    "B_target": int(B_target),
                    "B_used": int(B_used),
                    "mode": "extrapolated_linear_B",
                    "repeats": int(repeats),
                    "time_ms_mean": float(extrapolate_linear_in_B(mean_ms, B_used, B_target)),
                    "time_ms_std": float(extrapolate_linear_in_B(std_ms, B_used, B_target)),
                })

    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", nargs="*", default=["256,512", "256,1024", "512,1024"])
    ap.add_argument("--Ns", nargs="*", default=["1e2", "1e4", "1e6"])
    ap.add_argument("--B_cap", type=int, default=10)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--no_extrapolate", action="store_true")
    args = ap.parse_args()

    pairs = []
    for s in args.pairs:
        n, m = s.split(",")
        pairs.append((int(n), int(m)))

    Ns = [int(float(x)) for x in args.Ns]
    outd = ensure_outdir()

    all_rows = []
    for (n, m) in pairs:
        all_rows.extend(
            bench_one_pair(
                n=n, m=m, Ns=Ns, B_cap=args.B_cap,
                repeats=args.repeats,
                do_extrapolate=(not args.no_extrapolate)
            )
        )

    out_path = os.path.join(outd, "postrbe_base_bench_v1.csv")
    save_rows_csv(out_path, all_rows)
    print(f"Done. Wrote: {out_path}")


if __name__ == "__main__":
    main()
