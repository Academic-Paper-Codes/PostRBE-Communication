# -*- coding: utf-8 -*-
"""
bench_postrbe_base_v2_fastkey_debug.py

This is a diagnostic-safe runner:
- prints at import time and when entering main()
- wraps main() in try/except and prints full traceback
- prints the absolute path of the script, Python version, and cwd
- verifies that required modules exist and shows where they are imported from

Run:
  python -u bench_postrbe_base_v2_fastkey_debug.py --B_cap 1 --repeats 3
"""

print(">>> [BENCH DEBUG] script loaded (top-level)")

import argparse
import math
import os
import sys
import time
import statistics
import traceback
from typing import Any, Dict, List

print(f">>> [BENCH DEBUG] __file__ = {os.path.abspath(__file__)}")
print(f">>> [BENCH DEBUG] cwd     = {os.getcwd()}")
print(f">>> [BENCH DEBUG] python  = {sys.executable}")
print(f">>> [BENCH DEBUG] version = {sys.version}")

# --- import dependencies with location prints ---
def _import_with_where(name: str):
    mod = __import__(name)
    where = getattr(mod, "__file__", "<built-in>")
    print(f">>> [BENCH DEBUG] imported {name} from {where}")
    return mod

try:
    np = _import_with_where("numpy")
    postrbe_core = _import_with_where("postrbe_core")
    postrbe_utils = _import_with_where("postrbe_utils")
except Exception as e:
    print("!!! [BENCH DEBUG] import failed:")
    traceback.print_exc()
    raise

# pull functions
setup = postrbe_core.setup
register = postrbe_core.register
encrypt = postrbe_core.encrypt
decrypt = postrbe_core.decrypt
update = postrbe_core.update
compute_indices = postrbe_core.compute_indices

mod_q = postrbe_utils.mod_q
inv_mod = postrbe_utils.inv_mod


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


def keygen_fastdiag(user_id: int, crs, bound: int = 3) -> Dict[str, Any]:
    q, n, m, t, B = crs["q"], crs["n"], crs["m"], crs["t"], crs["B"]
    _, id_prime = compute_indices(user_id, B)

    diag_small = np.random.randint(-bound, bound + 1, size=(t,), dtype=np.int64)
    diag_small[diag_small == 0] = 1
    diag = np.mod(diag_small, q)
    inv_diag = np.array([inv_mod(int(x), q) for x in diag], dtype=np.int64)

    X = np.diag(diag)
    X_inv = np.diag(inv_diag)

    U = crs["U_list"][id_prime]  # (n×t)
    pk = mod_q(U * diag.reshape(1, -1), q)

    up_list = []
    for i in range(B):
        if i == id_prime:
            up_list.append(np.zeros((m, t), dtype=np.int64))
        else:
            T_i = crs["T_mat"][i][id_prime]  # (m×t)
            up_list.append(mod_q(T_i * diag.reshape(1, -1), q))

    return {"user_id": user_id, "sk": X, "sk_inv": X_inv, "pk": pk, "up": up_list}


def main():
    print(">>> [BENCH DEBUG] main() entered")

    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", nargs="*", default=["256,512", "256,1024", "512,1024"])
    ap.add_argument("--Ns", nargs="*", default=["1e2", "1e4", "1e6"])
    ap.add_argument("--B_cap", type=int, default=1)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--measure_setup", action="store_true")
    args = ap.parse_args()

    pairs = []
    for s in args.pairs:
        n, m = s.split(",")
        pairs.append((int(n), int(m)))
    Ns = [int(float(x)) for x in args.Ns]

    outd = ensure_outdir()
    print(f">>> [BENCH DEBUG] outdir = {outd}")

    rows: List[Dict[str, Any]] = []
    msg = b"bench message"

    for (n, m) in pairs:
        for N_target in Ns:
            B_target = int(math.isqrt(int(N_target)))
            B_used = min(B_target, args.B_cap)
            N_used = max(1, B_used * B_used)

            print(f">>> [BENCH DEBUG] (n,m)=({n},{m}), N_target={N_target}, B_used={B_used}, N_used={N_used}")

            # Setup
            crs, pp, aux = setup(security_param=128, N_max=N_used, n=n, m=m)
            print(">>> [BENCH DEBUG] setup ok, types:", type(crs), type(pp), type(aux))

            user_id = 0  # with B_used=1, only id 0 is valid

            kg_mean, kg_std = time_op(lambda: keygen_fastdiag(user_id, crs), repeats=args.repeats)
            rows.append({"op": "KeyGen_fastdiag", "n": n, "m": m, "N_target": int(N_target),
                         "B_target": int(B_target), "B_used": int(B_used), "repeats": int(args.repeats),
                         "time_ms_mean": kg_mean, "time_ms_std": kg_std})

            def _reg():
                user = keygen_fastdiag(user_id, crs)
                return register(user, crs, pp, aux)

            reg_mean, reg_std = time_op(_reg, repeats=args.repeats)
            rows.append({"op": "Register_fastdiag", "n": n, "m": m, "N_target": int(N_target),
                         "B_target": int(B_target), "B_used": int(B_used), "repeats": int(args.repeats),
                         "time_ms_mean": reg_mean, "time_ms_std": reg_std})

            user = keygen_fastdiag(user_id, crs)
            pp2, aux2 = register(user, crs, pp, aux)

            enc_mean, enc_std = time_op(lambda: encrypt(pp2, crs, user_id, msg), repeats=args.repeats)
            rows.append({"op": "Encrypt_P1", "n": n, "m": m, "N_target": int(N_target),
                         "B_target": int(B_target), "B_used": int(B_used), "repeats": int(args.repeats),
                         "time_ms_mean": enc_mean, "time_ms_std": enc_std})

            ct = encrypt(pp2, crs, user_id, msg)
            dec_mean, dec_std = time_op(lambda: decrypt(user, crs, aux2, ct), repeats=args.repeats)
            rows.append({"op": "Decrypt_single", "n": n, "m": m, "N_target": int(N_target),
                         "B_target": int(B_target), "B_used": int(B_used), "repeats": int(args.repeats),
                         "time_ms_mean": dec_mean, "time_ms_std": dec_std})

            upd_mean, upd_std = time_op(lambda: update(user_id, crs, aux2), repeats=args.repeats)
            rows.append({"op": "Update", "n": n, "m": m, "N_target": int(N_target),
                         "B_target": int(B_target), "B_used": int(B_used), "repeats": int(args.repeats),
                         "time_ms_mean": upd_mean, "time_ms_std": upd_std})

    out_path = os.path.join(outd, "postrbe_base_bench_v2_fastkey_debug.csv")
    save_rows_csv(out_path, rows)
    print(f">>> [BENCH DEBUG] Done. Wrote: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("!!! [BENCH DEBUG] Unhandled exception:")
        traceback.print_exc()
        raise
