#!/usr/bin/env python3
import argparse
import csv
import os
import math
from dkllmr23_compare.params import TARGET_N, UnifiedParams, parse_int_list
from dkllmr23_compare.models import rbe_operation_counts, size_counts, base_row

SCHEME_NAME = "DKLLMR23RBE"


# Paper Table 1 anchor for the underlying Laconic Encryption implementation.
# Source: Eurocrypt 2023 DKLLMR, Section 12, q = 5 * 2^55 + 1 (58-bit), ell = 50.
LE_BENCHMARKS_MS = {
    256: {"Setup": 47.0, "Upd": 1200.0, "Enc": 2.85, "WGen": 0.048, "Dec": 6.00, "ctxt_mib": 49.0},
    512: {"Setup": 85.0, "Upd": 1389.0, "Enc": 8.28, "WGen": 0.051, "Dec": 10.86, "ctxt_mib": 97.0},
    1024: {"Setup": 167.0, "Upd": 1813.0, "Enc": 13.60, "WGen": 0.055, "Dec": 21.49, "ctxt_mib": 194.0},
}


def nearest_benchmark_degree(deg: int) -> int:
    return min(LE_BENCHMARKS_MS.keys(), key=lambda x: abs(x - int(deg)))


def benchmark_rbe_times_ms(p, register_model: str = "worst", benchmark_degree: int = 256,
                           paper_ell: int = 50, commitment_ms: float = 0.0):
    """Estimate DKLLMR23 RBE times from the paper's measured LE benchmarks.

    The old code converted synthetic operation counts with PostRBE calibration coefficients.
    That is not comparable because DKLLMR23 uses ring/NTT polynomial operations and the
    units in models.py are only relative work units. This benchmark model anchors LE.Enc,
    LE.Dec, LE.WGen and LE.Upd directly to the measured Table 1 timings, then applies the
    generic LE->RBE transformation in Fig. 3.

    Fig. 3 RBE encryption contains ell components; each component has two LE encryptions
    plus one commitment. Decryption only uses the matching component and decrypts two
    LE ciphertexts, plus witness generation/update.
    """
    deg = nearest_benchmark_degree(benchmark_degree)
    b = LE_BENCHMARKS_MS[deg]

    # Table 1 uses q = 5*2^55+1, i.e. 58-bit modulus.
    q_scale = float(p.q_bits) / 58.0

    # The measured LE benchmark fixes ell=50. LE.Enc/Dec/WGen/Upd are path-based,
    # so for our target N we scale the LE primitive by ell/50.
    ell_scale = float(p.ell) / float(paper_ell)

    le_setup = b["Setup"] * ell_scale * q_scale
    le_upd = b["Upd"] * ell_scale * q_scale
    le_enc = b["Enc"] * ell_scale * q_scale
    le_wgen = b["WGen"] * ell_scale * q_scale
    le_dec = b["Dec"] * ell_scale * q_scale

    # KeyGen is not reported in Table 1. It is one public-key generation step, modeled
    # conservatively as roughly one LE encryption layer rather than the whole LE.Enc path.
    keygen = (b["Enc"] / float(paper_ell + 1)) * q_scale

    register_model = register_model.lower()
    if register_model == "worst":
        register = p.N * le_upd
    elif register_model == "amortized":
        register = p.ell * le_upd
    elif register_model == "sqrt":
        register = p.B * le_upd
    else:
        raise ValueError("register_model must be worst, amortized, or sqrt")

    commitment = float(commitment_ms) * q_scale
    encrypt = p.ell * (2.0 * le_enc + commitment)
    decrypt_update = le_wgen + 2.0 * le_dec + commitment

    return {
        "Setup": le_setup,
        "KeyGen": keygen,
        "Register": register,
        "Encrypt": encrypt,
        "DecryptUpdate": decrypt_update,
    }


def read_coefficients(path: str):
    """Read optional coefficient file.

    Supported formats:
    1) calibration_coefficients.csv from our previous pipeline with columns metric, coefficient_ms_per_unit_median.
    2) a simple two-column CSV: metric,ms_per_unit.
    3) a global one-row CSV with metric=GLOBAL.
    """
    if not path:
        return {}
    coeff = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            metric = row.get('metric') or row.get('Metric') or row.get('operation') or row.get('Operation')
            val = row.get('coefficient_ms_per_unit_median') or row.get('ms_per_unit') or row.get('coefficient')
            if metric and val:
                try:
                    coeff[metric] = float(val)
                except ValueError:
                    pass
    return coeff


def coeff_for(coeffs, metric, default):
    if metric in coeffs:
        return coeffs[metric]
    if "GLOBAL" in coeffs:
        return coeffs["GLOBAL"]
    return default


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, '') for k in fieldnames})


def main():
    ap = argparse.ArgumentParser(description="Generate target data for the Eurocrypt'23 DKLLMR LE-to-RBE comparison baseline.")
    ap.add_argument('--target', action='store_true', help='Use the unified target N list: 10^3,...,10^7')
    ap.add_argument('--N', nargs='*', default=None, help='User counts. Example: --N 1000 10000')
    ap.add_argument('--n', type=int, default=256)
    ap.add_argument('--m', type=int, default=512)
    ap.add_argument('--r', type=int, default=128, help='Kept for CSV compatibility; not used by this baseline.')
    ap.add_argument('--d', type=int, default=10, help='Kept for CSV compatibility; not used by this baseline.')
    ap.add_argument('--q-bits', type=int, default=64)
    ap.add_argument('--sigma-inf', type=int, default=2)
    ap.add_argument('--message-bits', type=int, default=256)
    ap.add_argument('--ring-degree', type=int, default=128, help='Degree of R_q. Use 1 for pure Z_q scalar model.')
    ap.add_argument('--poly-mul-model', choices=['scalar', 'naive', 'ntt'], default='ntt')
    ap.add_argument('--register-model', choices=['worst', 'amortized', 'sqrt'], default='worst',
                    help='Register cost model. Paper states worst-case O(N); amortized/sqrt are optional alternatives.')
    ap.add_argument('--commit-entries', type=int, default=0, help='Commitment size in R_q elements. 0 means n entries.')
    ap.add_argument('--coefficients', default='', help='Optional CSV mapping metric to ms_per_unit for estimated ms output.')
    ap.add_argument('--default-ms-per-unit', type=float, default=0.0,
                    help='If >0, output computation metrics as ms even without coefficient file. Otherwise output work_units.')
    ap.add_argument('--time-model', choices=['benchmark_anchor', 'opcount_coeff'], default='benchmark_anchor',
                    help='benchmark_anchor uses Eurocrypt23 Table 1 LE timings. opcount_coeff keeps the old operation-count conversion.')
    ap.add_argument('--le-benchmark-degree', type=int, default=256,
                    help='Which Table 1 ring degree anchor to use: 256, 512, or 1024. Default 256 matches the lightest benchmark.')
    ap.add_argument('--paper-ell', type=int, default=50,
                    help='Identity length used by the paper benchmark anchor.')
    ap.add_argument('--commitment-ms', type=float, default=0.0,
                    help='Optional per-component commitment cost in ms. Default 0 because the paper does not benchmark the commitment separately.')
    ap.add_argument('--out', default='results_dkllmr23')
    args = ap.parse_args()

    if args.target or not args.N:
        Ns = TARGET_N
    else:
        Ns = parse_int_list(args.N)

    coeffs = read_coefficients(args.coefficients)
    op_rows = []
    size_rows = []
    clean_rows = []

    for N in Ns:
        p = UnifiedParams(
            N=N,
            n=args.n,
            m=args.m,
            r=args.r,
            d=args.d,
            q_bits=args.q_bits,
            sigma_inf=args.sigma_inf,
            short_min=-args.sigma_inf,
            short_max=args.sigma_inf,
            message_bits=args.message_bits,
            ring_degree=args.ring_degree,
            poly_mul_model=args.poly_mul_model,
            commit_entries=args.commit_entries,
        )
        base = base_row(p, SCHEME_NAME)
        ops = rbe_operation_counts(p, register_model=args.register_model)
        sizes = size_counts(p)

        op_row = dict(base)
        op_row.update({f'{k}_work_units': v for k, v in ops.items()})
        op_row.update(sizes)
        op_row['register_model'] = args.register_model
        op_rows.append(op_row)

        for name, value in sizes.items():
            srow = dict(base)
            srow['item'] = name
            srow['value'] = value
            size_rows.append(srow)

        if args.time_model == 'benchmark_anchor':
            plot_times = benchmark_rbe_times_ms(
                p,
                register_model=args.register_model,
                benchmark_degree=args.le_benchmark_degree,
                paper_ell=args.paper_ell,
                commitment_ms=args.commitment_ms,
            )
            plot_units = {metric: 'ms' for metric in plot_times}
        else:
            plot_times = {}
            plot_units = {}
            for metric in ['Setup', 'KeyGen', 'Register', 'Encrypt', 'DecryptUpdate']:
                units = ops[metric]
                c = coeff_for(coeffs, metric, args.default_ms_per_unit)
                plot_times[metric] = units * c if c and c > 0 else units
                plot_units[metric] = 'ms' if c and c > 0 else 'work_units'

        for metric in ['Setup', 'KeyGen', 'Register', 'Encrypt', 'DecryptUpdate']:
            crow = {
                'scheme': SCHEME_NAME,
                'N': p.N,
                'B': p.B,
                'metric': metric,
                'plot_value': plot_times[metric],
                'plot_unit': plot_units[metric],
                'n': p.n,
                'm': p.m,
                'r': p.r_for_csv,
                't': p.t_for_csv,
                'q_bits': p.q_bits,
                'd': p.d,
                'sigma_inf': p.sigma_inf,
                'short_range': p.short_range,
                'message_bits': p.message_bits,
            }
            clean_rows.append(crow)

        clean_rows.append({
            'scheme': SCHEME_NAME,
            'N': p.N,
            'B': p.B,
            'metric': 'CiphertextSizes',
            'plot_value': sizes['ciphertext_mib'],
            'plot_unit': 'MiB',
            'n': p.n,
            'm': p.m,
            'r': p.r_for_csv,
            't': p.t_for_csv,
            'q_bits': p.q_bits,
            'd': p.d,
            'sigma_inf': p.sigma_inf,
            'short_range': p.short_range,
            'message_bits': p.message_bits,
        })

    op_fields = [
        'scheme','N','B','ell','n','m','r','t','q_bits','d','sigma_inf','short_min','short_max',
        'message_bits','ring_degree','poly_mul_model','register_model',
        'Setup_work_units','KeyGen_work_units','Register_work_units','Encrypt_work_units','DecryptUpdate_work_units',
        'le_ciphertext_entries','rbe_ciphertext_entries','ciphertext_bytes','ciphertext_kib','ciphertext_mib',
        'pk_entries','sk_entries','witness_entries','commit_entries'
    ]
    size_fields = ['scheme','N','B','ell','n','m','r','t','q_bits','d','sigma_inf','short_range','message_bits','ring_degree','poly_mul_model','item','value']
    clean_fields = ['scheme','N','B','metric','plot_value','plot_unit','n','m','r','t','q_bits','d','sigma_inf','short_range','message_bits']

    write_csv(os.path.join(args.out, 'operation_counts.csv'), op_rows, op_fields)
    write_csv(os.path.join(args.out, 'sizes_estimated.csv'), size_rows, size_fields)
    write_csv(os.path.join(args.out, 'six_plot_data_clean.csv'), clean_rows, clean_fields)

    print(f'Wrote: {os.path.join(args.out, "operation_counts.csv")}')
    print(f'Wrote: {os.path.join(args.out, "sizes_estimated.csv")}')
    print(f'Wrote: {os.path.join(args.out, "six_plot_data_clean.csv")}')
    print(f'Time model: {args.time_model}')
    if args.time_model == 'benchmark_anchor':
        print(f'Benchmark anchor: LE Table 1 degree={nearest_benchmark_degree(args.le_benchmark_degree)}, paper_ell={args.paper_ell}, q_anchor_bits=58')


if __name__ == '__main__':
    main()
