#!/usr/bin/env python3
"""
SP26 / KLSS26 BLE-to-RBE comparison model with unified experiment parameters.

This is a benchmarking/estimation script, not a production cryptographic implementation.
It models the SP'26 "Scalable Registration-Based Encryption from Lattices" BLE-to-RBE
construction, but records and uses the unified parameters requested for comparison:

  N = 10^3, 10^4, 10^5, 10^6, 10^7
  B = ceil(sqrt(N))                         # common table/block parameter for clean CSV
  n = 256, m = 512, r = 128                 # common matrix parameters when applicable
  d = 10                                    # common high-bit extraction parameter; not used by SP26
  q_bits = 64                               # common modulus/element bit length
  sigma_inf = 2                             # common short bound, short elements {-2,-1,0,1,2}
  message_bits = 256

Important mapping notes:
  - SP26's internal BLE/RBE batch parameter satisfies N <= 2^B_batch, so
    B_batch = ceil(log2(N)). This is not the same as the PostRBE block parameter
    B = ceil(sqrt(N)). We keep B=ceil(sqrt(N)) in six_plot_data_clean.csv for
    format consistency and record B_batch in operation_counts.csv.
  - SP26 is a module/ring-lattice scheme. Its module rank and ring degree do not
    directly equal PostRBE's n=256 and m=512. The formula still uses SP26's native
    structural parameters (phi, module_rank, ell_A, k), while the clean CSV records
    the unified table parameters for fair experiment labelling.
  - SP26's paper uses Gaussian parameters. In unified mode, sigma-like short/noise
    parameters are set to 2 and the short range is recorded as {-2,-1,0,1,2}, to
    match the user's comparison setting. This is an experiment-normalized model.

Outputs:
  - operation_counts.csv
  - sizes_estimated.csv
  - six_plot_data_clean.csv

The clean CSV has the same columns as the previous six_plot_data_clean.csv:
  scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits
"""

from __future__ import annotations

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True)
class UnifiedParams:
    # Unified experiment parameters for the clean CSV.
    n: int = 256
    m: int = 512
    r: int = 128
    d: int = 10
    q_bits: int = 64
    sigma_inf: int = 2
    short_range: str = "{-2,-1,0,1,2}"
    message_bits: int = 256

    # SP26 structural parameters that do not map directly to PostRBE's n,m,r,t.
    # Keep these fixed to the construction's structure; do not overwrite them with
    # PostRBE n=256,m=512 because they are not the same mathematical dimensions.
    phi: int = 256               # ring degree
    module_rank: int = 7         # SP26 module rank n in the paper's implementation
    ell_A: int = 2               # approximate gadget parameter used in the implementation
    tree_arity_k: int = 3        # ternary Merkle tree

    # Unified q and short/noise settings.
    # We do not apply SP26's paper bit-dropping in unified mode, because the common
    # comparison says each Z_q element is represented with 64 bits.
    q_effective_bits: int = 64
    bit_drop_D: int = 0
    stored_coeff_bits: int = 64
    sigma_gaussian: float = 2.0
    sigma_tilde: float = 2.0

    # Paper Table 3 timing constants for SP26 native optimized implementation.
    # We use these as a timing anchor and scale mildly by formulaic work/size terms.
    # This gives estimated ms, not a direct measurement under the unified parameters.
    paper_B_batch: int = 30
    paper_q_effective_bits: int = 48
    paper_bit_drop_D: int = 16
    paper_stored_coeff_bits: int = 32
    paper_setup_ms: float = 9.98
    paper_keygen_ms: float = 0.12
    paper_register_ms: float = 33.24
    paper_encrypt_ms: float = 15.56
    paper_wgen_ms: float = 3.38
    paper_decrypt_ms: float = 10.43


def ceil_sqrt(n: int) -> int:
    return math.ceil(math.sqrt(n))


def ceil_log2(n: int) -> int:
    if n <= 1:
        return 0
    return math.ceil(math.log2(n))


def id_length(message_bits: int, arity: int) -> int:
    # Need k^ell >= 2^message_bits.
    return math.ceil(message_bits / math.log2(arity))


def poly_mul_cost(phi: int, model: str) -> float:
    if model == "ntt":
        return phi * math.log2(phi)
    if model == "schoolbook":
        return phi * phi
    if model == "scalar":
        return 1.0
    raise ValueError(f"unknown poly model: {model}")


def rq_element_bytes(params: UnifiedParams) -> float:
    return params.phi * params.stored_coeff_bits / 8.0


def ciphertext_rq_elements(params: UnifiedParams, B_batch: int) -> int:
    ell_hat = id_length(params.message_bits, params.tree_arity_k)
    # SP26 Section 6.1 formula for ciphertext elements against B sub-registries:
    # (3*ell_A*ell_hat + 1)*n + B, because k=3.
    return (params.tree_arity_k * params.ell_A * ell_hat + 1) * params.module_rank + B_batch


def estimate_for_N(N: int, params: UnifiedParams, poly_model: str) -> Dict[str, object]:
    B_common = ceil_sqrt(N)
    B_batch = ceil_log2(N)
    ell_hat = id_length(params.message_bits, params.tree_arity_k)

    mA = params.module_rank * params.ell_A
    mB = params.module_rank
    kmA = params.tree_arity_k * mA
    pmul = poly_mul_cost(params.phi, poly_model)

    rq_elems = ciphertext_rq_elements(params, B_batch)
    paper_rq_elems = (params.tree_arity_k * params.ell_A * ell_hat + 1) * params.module_rank + params.paper_B_batch
    bytes_per_rq = rq_element_bytes(params)
    ciphertext_bytes = rq_elems * bytes_per_rq

    # Formulaic work units. These are rough operation-count models in terms of ring operations.
    setup_rand_rq_entries = params.module_rank * kmA + params.module_rank * mB + B_batch * params.module_rank
    setup_work_units = setup_rand_rq_entries * params.phi
    keygen_work_units = params.module_rank * mB * pmul
    register_work_units = ell_hat * params.module_rank * kmA * pmul
    encrypt_work_units = (ell_hat * (params.module_rank * kmA + kmA) + params.module_rank * mB + params.module_rank * B_batch) * pmul
    wgen_work_units = ell_hat * kmA * params.phi
    decrypt_work_units = (ell_hat * kmA + mB) * pmul
    decrypt_update_work_units = wgen_work_units + decrypt_work_units

    # Estimated time model.
    # Setup: scale with random/generated Rq entries.
    paper_setup_entries = params.module_rank * kmA + params.module_rank * mB + params.paper_B_batch * params.module_rank
    setup_ms = params.paper_setup_ms * setup_rand_rq_entries / paper_setup_entries

    # KeyGen/Register/WGen/Dec: mostly independent of user scale for fixed identity length.
    # Since q arithmetic remains 64-bit word arithmetic, keep paper timing anchors.
    keygen_ms = params.paper_keygen_ms
    register_ms = params.paper_register_ms
    wgen_ms = params.paper_wgen_ms
    dec_ms = params.paper_decrypt_ms

    # Encrypt: scale by Rq element count and by stored coefficient bits. Since unified mode
    # stores 64-bit coefficients while paper after bit-dropping stores ~32-bit coefficients,
    # this can increase the estimated cost conservatively.
    bit_scale = params.stored_coeff_bits / params.paper_stored_coeff_bits
    encrypt_ms = params.paper_encrypt_ms * (rq_elems / paper_rq_elems) * bit_scale
    decrypt_update_ms = wgen_ms + dec_ms

    return {
        "scheme": "SP26BLE-RBE",
        "N": N,
        "B": B_common,
        "B_batch_logN": B_batch,
        "ell_hat": ell_hat,
        "tree_arity_k": params.tree_arity_k,
        "phi": params.phi,
        "module_rank": params.module_rank,
        "ell_A": params.ell_A,
        "mA": mA,
        "mB": mB,
        "q_bits": params.q_bits,
        "q_effective_bits": params.q_effective_bits,
        "bit_drop_D": params.bit_drop_D,
        "stored_coeff_bits": params.stored_coeff_bits,
        "sigma_inf": params.sigma_inf,
        "sigma_gaussian_used": params.sigma_gaussian,
        "sigma_tilde_used": params.sigma_tilde,
        "short_range": params.short_range,
        "message_bits": params.message_bits,
        "poly_mul_model": poly_model,
        "poly_mul_cost": pmul,
        "setup_rand_rq_entries": setup_rand_rq_entries,
        "Setup_work_units": setup_work_units,
        "KeyGen_work_units": keygen_work_units,
        "Register_work_units": register_work_units,
        "Encrypt_work_units": encrypt_work_units,
        "WGen_work_units": wgen_work_units,
        "Decrypt_work_units": decrypt_work_units,
        "DecryptUpdate_work_units": decrypt_update_work_units,
        "ciphertext_rq_elements": rq_elems,
        "rq_element_bytes": bytes_per_rq,
        "ciphertext_bytes": ciphertext_bytes,
        "ciphertext_kib": ciphertext_bytes / 1024.0,
        "ciphertext_mib": ciphertext_bytes / (1024.0 * 1024.0),
        "Setup_ms": setup_ms,
        "KeyGen_ms": keygen_ms,
        "Register_ms": register_ms,
        "Encrypt_ms": encrypt_ms,
        "DecryptUpdate_ms": decrypt_update_ms,
    }


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("No rows to write")
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_operation_counts(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    fields = [
        "scheme", "N", "B", "B_batch_logN", "ell_hat", "tree_arity_k", "phi",
        "module_rank", "ell_A", "mA", "mB", "q_bits", "q_effective_bits",
        "bit_drop_D", "stored_coeff_bits", "sigma_inf", "sigma_gaussian_used",
        "sigma_tilde_used", "short_range", "message_bits", "poly_mul_model",
        "poly_mul_cost", "setup_rand_rq_entries", "Setup_work_units",
        "KeyGen_work_units", "Register_work_units", "Encrypt_work_units",
        "WGen_work_units", "Decrypt_work_units", "DecryptUpdate_work_units",
        "Setup_ms", "KeyGen_ms", "Register_ms", "Encrypt_ms", "DecryptUpdate_ms",
    ]
    return [{k: row.get(k, "") for k in fields} for row in rows]


def build_sizes(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    for row in rows:
        common = {
            "scheme": row["scheme"],
            "N": row["N"],
            "B": row["B"],
            "B_batch_logN": row["B_batch_logN"],
            "ell_hat": row["ell_hat"],
            "phi": row["phi"],
            "module_rank": row["module_rank"],
            "ell_A": row["ell_A"],
            "q_bits": row["q_bits"],
            "q_effective_bits": row["q_effective_bits"],
            "bit_drop_D": row["bit_drop_D"],
            "stored_coeff_bits": row["stored_coeff_bits"],
            "message_bits": row["message_bits"],
        }
        c_total = row["ciphertext_rq_elements"]
        c_d = row["B_batch_logN"]
        c_vec = c_total - c_d
        items = [
            ("ciphertext_total", c_total, row["ciphertext_bytes"]),
            ("ciphertext_c_vector_part", c_vec, c_vec * row["rq_element_bytes"]),
            ("ciphertext_d_batch_part", c_d, c_d * row["rq_element_bytes"]),
            ("secret_key_x", row["mB"], row["mB"] * row["rq_element_bytes"]),
            ("public_key_y", row["module_rank"], row["module_rank"] * row["rq_element_bytes"]),
            ("state_st", row["B_batch_logN"] * row["module_rank"], row["B_batch_logN"] * row["module_rank"] * row["rq_element_bytes"]),
        ]
        for item, entries, size_bytes in items:
            out.append({
                **common,
                "item": item,
                "rq_elements": entries,
                "bytes": size_bytes,
                "kib": size_bytes / 1024.0,
                "mib": size_bytes / (1024.0 * 1024.0),
            })
    return out


def build_clean(rows: List[Dict[str, object]], params: UnifiedParams) -> List[Dict[str, object]]:
    metrics = [
        ("Setup", "Setup_ms", "ms"),
        ("KeyGen", "KeyGen_ms", "ms"),
        ("Register", "Register_ms", "ms"),
        ("Encrypt", "Encrypt_ms", "ms"),
        ("DecryptUpdate", "DecryptUpdate_ms", "ms"),
        ("CiphertextSizes", "ciphertext_mib", "MiB"),
    ]
    out: List[Dict[str, object]] = []
    for row in rows:
        for metric, col, unit in metrics:
            out.append({
                "scheme": row["scheme"],
                "N": row["N"],
                "B": row["B"],
                "metric": metric,
                "plot_value": row[col],
                "plot_unit": unit,
                "n": params.n,
                "m": params.m,
                "r": params.r,
                "t": "NA",
                "q_bits": params.q_bits,
                "d": params.d,
                "sigma_inf": params.sigma_inf,
                "short_range": params.short_range,
                "message_bits": params.message_bits,
            })
    fields = ["scheme", "N", "B", "metric", "plot_value", "plot_unit", "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "short_range", "message_bits"]
    return [{k: r.get(k, "") for k in fields} for r in out]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SP26 BLE-RBE comparison data using unified parameters.")
    parser.add_argument("--target", action="store_true", help="Use target N values 10^3...10^7.")
    parser.add_argument("--N", nargs="*", type=int, help="Custom N values.")
    parser.add_argument("--out", default="results_sp26_ble_unified", help="Output directory.")
    parser.add_argument("--poly-mul-model", default="ntt", choices=["ntt", "schoolbook", "scalar"], help="Polynomial multiplication model for work units.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.N:
        N_values = args.N
    elif args.target:
        N_values = [10**3, 10**4, 10**5, 10**6, 10**7]
    else:
        N_values = [10**3, 10**4]

    params = UnifiedParams()
    rows = [estimate_for_N(N, params, args.poly_mul_model) for N in N_values]

    out = Path(args.out)
    write_csv(out / "operation_counts.csv", build_operation_counts(rows))
    write_csv(out / "sizes_estimated.csv", build_sizes(rows))
    write_csv(out / "six_plot_data_clean.csv", build_clean(rows, params))

    print(f"Wrote: {out / 'operation_counts.csv'}")
    print(f"Wrote: {out / 'sizes_estimated.csv'}")
    print(f"Wrote: {out / 'six_plot_data_clean.csv'}")
    print("Unified params: q_bits=64, sigma_inf=2, short_range={-2,-1,0,1,2}, d=10.")
    print("Note: clean CSV B=ceil(sqrt(N)); SP26 internal B_batch=ceil(log2(N)) is in operation_counts.csv.")
    print("Note: timings are estimated from paper Table 3 anchors; this is not a direct Rust benchmark under unified params.")


if __name__ == "__main__":
    main()
