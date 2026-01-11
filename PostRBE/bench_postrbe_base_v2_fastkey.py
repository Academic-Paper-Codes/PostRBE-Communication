# -*- coding: utf-8 -*-
print(">>> SCRIPT LOADED")

"""
bench_postrbe_base_v2_fastkey.py

You got "stuck" because KeyGen in postrbe_core samples a FULL (t×t) matrix X and then
computes X_inv via Gauss elimination mod q (invert_matrix_mod_q). With your experiment
dimensions, even with small B, t = B*m + n is already thousands, so inverting X is
computationally infeasible in Python (and will appear to hang).

This benchmark script keeps your (n,m) = (256,512)/(256,1024)/(512,1024) and N points,
BUT uses a benchmark-safe KeyGen variant:
- X is a random *diagonal* matrix with non-zero diagonal entries in Z_q
- X_inv is the diagonal inverse
This preserves correctness of the algebra (X is invertible mod q), while making KeyGen feasible.

What is measured:
- Setup (optional)
- KeyGen_fastdiag
- Register (using pk/up from fast keygen)
- Encrypt
- Decrypt (single)
- Update

Outputs:
- Figure-Exp-Data/postrbe_base_bench_v2_fastkey.csv

Run:
  python bench_postrbe_base_v2_fastkey.py
  python bench_postrbe_base_v2_fastkey.py --repeats 5 --B_cap 1
"""

import argparse
import math
import os
import time
import statistics
from typing import Any, Dict, List

import numpy as np

from postrbe_core import setup, register, encrypt, decrypt, update, compute_indices
from postrbe_utils import mod_q, sample_short_matrix, inv_mod

# ---------------- timing helper ----------------
def time_op(fn, repeats: int, warmups: int = 1):
    for _ in range(warmups):
        fn()
    ts = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        ts.append((t1 - t0) * 1000.0)
    return float(statistics.mean(ts)), float(statistics.pstdev(ts) if len(ts) > 1 else 0.0)

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
        w.writerows(rows)

# ---------------- fast KeyGen (diagonal X) ----------------
def keygen_fastdiag(user_id: int, crs, bound: int = 3) -> Dict[str, Any]:
    """
    Benchmark-safe KeyGen:
      - Sample diagonal entries d_i in [-bound,bound]\{0} mapped to Z_q
      - X = diag(d)
      - X_inv = diag(inv_mod(d_i,q))
      - pk = U_id' @ X   (n×t) times (t×t diagonal) -> scale columns of U
      - up_i = T_{i,id'} @ X -> scale columns of T
    """
    q, n, m, t, B = crs.q, crs.n, crs.m, crs.t, crs.B
    _, id_prime = compute_indices(user_id, B)

    # sample non-zero short diag (in Z_q)
    # draw from [-bound,bound] excluding 0
    diag_small = np.random.randint(-bound, bound + 1, size=(t,), dtype=np.int64)
    diag_small[diag_small == 0] = 1
    diag = np.mod(diag_small, q)

    inv_diag = np.array([inv_mod(int(x), q) for x in diag], dtype=np.int64)

    # represent X and X_inv as full diagonal matrices ONLY if you need to store them
    X = np.diag(diag)
    X_inv = np.diag(inv_diag)

    # pk = U @ X = scale each column j by diag[j]
    U = crs.U_list[id_prime]  # (n×t)
    pk = mod_q(U * diag.reshape(1, -1), q)

    # up list length B
    up_list = []
    for i in range(B):
        if i == id_prime:
            up_list.append(np.zeros((m, t), dtype=np.int64))
        else:
            T_i = crs.T_mat[i][id_prime]  # (m×t)
            up_list.append(mod_q(T_i * diag.reshape(1, -1), q))

    return {"user_id": user_id, "sk": X, "sk_inv": X_inv, "pk": pk, "up": up_list}

# ---------------- main benchmark ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", nargs="*", default=["256,512", "256,1024", "512,1024"])
    ap.add_argument("--Ns", nargs="*", default=["1e2", "1e4", "1e6"])
    ap.add_argument("--B_cap", type=int, default=1,
                    help="IMPORTANT: even B=10 makes t huge. Use 1 (default) unless you know what you're doing.")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--measure_setup", action="store_true")
    args = ap.parse_args()

    pairs = []
    for s in args.pairs:
        n, m = s.split(",")
        pairs.append((int(n), int(m)))
    Ns = [int(float(x)) for x in args.Ns]

    outd = ensure_outdir()
    rows: List[Dict[str, Any]] = []
    msg = b"bench message"

    for (n, m) in pairs:
        for N_target in Ns:
            B_target = int(math.isqrt(int(N_target)))
            B_used = min(B_target, args.B_cap)
            N_used = B_used * B_used if B_used > 0 else 1

            # Setup
            if args.measure_setup:
                setup_mean, setup_std = time_op(lambda: setup(security_param=128, N_max=N_used, n=n, m=m),
                                                repeats=args.repeats)
                # run once to get objects
                crs, pp, aux = setup(security_param=128, N_max=N_used, n=n, m=m)
                print(">>> setup returned:", type(crs), type(pp), type(aux))
                rows.append({
                    "op": "Setup",
                    "n": n, "m": m,
                    "N_target": int(N_target),
                    "B_target": int(B_target),
                    "B_used": int(B_used),
                    "repeats": int(args.repeats),
                    "time_ms_mean": float(setup_mean),
                    "time_ms_std": float(setup_std),
                })
            else:
                crs, pp, aux = setup(security_param=128, N_max=N_used, n=n, m=m)

            user_id = 0  # with B_used=1, only id 0 is valid

            # KeyGen_fastdiag
            kg_mean, kg_std = time_op(lambda: keygen_fastdiag(user_id, crs), repeats=args.repeats)
            rows.append({
                "op": "KeyGen_fastdiag",
                "n": n, "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "repeats": int(args.repeats),
                "time_ms_mean": float(kg_mean),
                "time_ms_std": float(kg_std),
            })

            # Register
            def _reg():
                user = keygen_fastdiag(user_id, crs)
                register(user, crs, pp, aux)

            reg_mean, reg_std = time_op(_reg, repeats=args.repeats)
            rows.append({
                "op": "Register_fastdiag",
                "n": n, "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "repeats": int(args.repeats),
                "time_ms_mean": float(reg_mean),
                "time_ms_std": float(reg_std),
            })

            # prepare fixed user + registered pp/aux
            user = keygen_fastdiag(user_id, crs)
            pp, aux = register(user, crs, pp, aux)

            # Encrypt
            enc_mean, enc_std = time_op(lambda: encrypt(pp, crs, user_id, msg), repeats=args.repeats)
            rows.append({
                "op": "Encrypt_P1",
                "n": n, "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "repeats": int(args.repeats),
                "time_ms_mean": float(enc_mean),
                "time_ms_std": float(enc_std),
            })

            # Decrypt (single)
            ct = encrypt(pp, crs, user_id, msg)
            dec_mean, dec_std = time_op(lambda: decrypt(user, crs, aux, ct), repeats=args.repeats)
            rows.append({
                "op": "Decrypt_single",
                "n": n, "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "repeats": int(args.repeats),
                "time_ms_mean": float(dec_mean),
                "time_ms_std": float(dec_std),
            })

            # Update
            upd_mean, upd_std = time_op(lambda: update(user_id, crs, aux), repeats=args.repeats)
            rows.append({
                "op": "Update",
                "n": n, "m": m,
                "N_target": int(N_target),
                "B_target": int(B_target),
                "B_used": int(B_used),
                "repeats": int(args.repeats),
                "time_ms_mean": float(upd_mean),
                "time_ms_std": float(upd_std),
            })

    out_path = os.path.join(outd, "postrbe_base_bench_v2_fastkey.csv")
    save_rows_csv(out_path, rows)
    print(f"Done. Wrote: {out_path}")

if __name__ == "__main__":
    print(">>> main() entered")
    main()
