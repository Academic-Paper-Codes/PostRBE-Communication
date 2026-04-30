#!/usr/bin/env python3
"""Calibrate operation-count data into estimated milliseconds.

This v2 script can use calibration timing rows even when all_correct=False.
For performance calibration, correctness is not required as long as the run
completed and timing columns were produced.

Example:
  python calibrate_estimate_v2.py `
    --target-opcounts results_target_main/operation_counts.csv `
    --target-six results_target_main/six_required_data.csv `
    --calib-dirs results_calibration_small results_calibration_medium results_calibration_large `
    --out results_estimated

By default, rows with all_correct=False are kept with a warning. Add
--require-correct to restore the strict behavior.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from statistics import median
from typing import Dict, Iterable, List, Tuple

COMPUTE_METRICS = ["Setup", "KeyGen", "Register", "Encrypt", "DecryptUpdate"]

TIMING_COL = {
    "Setup": "setup_ms_mean",
    "KeyGen": "keygen_ms_mean",
    "Register": "register_ms_mean",
    "Encrypt": "encrypt_ms_mean",
    "DecryptUpdate": "decrypt_update_ms_mean",
}

OPCOUNT_EXPR = {
    "Setup": lambda r: int(float(r.get("setup_rand_entries", 0))) + int(float(r.get("setup_muladds", 0))),
    "KeyGen": lambda r: int(float(r.get("keygen_muladds", 0))),
    "Register": lambda r: int(float(r.get("register_muladds", 0))),
    "Encrypt": lambda r: int(float(r.get("encrypt_muladds", 0))),
    "DecryptUpdate": lambda r: int(float(r.get("decrypt_update_muladds", 0))),
}

KEY_COLS = ["scheme", "N", "B", "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "message_bits"]
PARAM_COLS = ["scheme", "N", "B", "n", "m", "r", "t", "q_bits", "d", "sigma_inf", "message_bits", "short_min", "short_max"]


def read_csv(path: Path) -> List[dict]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: Iterable[dict]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: List[str] = []
    for row in rows:
        for k in row.keys():
            if k not in fieldnames:
                fieldnames.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def norm_val(v: object) -> str:
    s = str(v)
    try:
        x = float(s)
        if x.is_integer():
            return str(int(x))
        return str(x)
    except Exception:
        return s


def key(row: dict) -> Tuple[str, ...]:
    return tuple(norm_val(row.get(c, "")) for c in KEY_COLS)


def is_correct(row: dict) -> bool:
    return str(row.get("all_correct", "True")).lower() in ["true", "1", "yes"]


def load_calibration_rows(calib_dirs: List[Path], require_correct: bool = False) -> List[dict]:
    rows: List[dict] = []
    skipped_missing = 0
    skipped_correctness = 0
    used_incorrect = 0

    for d in calib_dirs:
        timing_path = d / "timings_summary.csv"
        op_path = d / "operation_counts.csv"
        if not timing_path.exists() or not op_path.exists():
            print(f"[WARN] Skip {d}: missing timings_summary.csv or operation_counts.csv")
            continue

        timing_rows = read_csv(timing_path)
        op_rows = read_csv(op_path)
        op_by_key = {key(r): r for r in op_rows}

        for tr in timing_rows:
            k = key(tr)
            if k not in op_by_key:
                print(f"[WARN] No opcount match for calibration row {k}")
                skipped_missing += 1
                continue

            correct = is_correct(tr)
            if require_correct and not correct:
                print(f"[WARN] Calibration row not all correct; skipped: {k}")
                skipped_correctness += 1
                continue
            if not correct:
                used_incorrect += 1

            op = op_by_key[k]
            base = {c: tr.get(c, op.get(c, "")) for c in PARAM_COLS}
            base["all_correct"] = str(correct)
            base["calibration_dir"] = str(d)

            for metric in COMPUTE_METRICS:
                if TIMING_COL[metric] not in tr:
                    continue
                try:
                    units = OPCOUNT_EXPR[metric](op)
                    observed_ms = float(tr[TIMING_COL[metric]])
                except Exception:
                    continue
                if units <= 0 or not math.isfinite(observed_ms) or observed_ms <= 0:
                    continue
                item = dict(base)
                item.update({
                    "metric": metric,
                    "observed_ms": observed_ms,
                    "units": units,
                    "ms_per_unit": observed_ms / units,
                })
                rows.append(item)

    if skipped_missing:
        print(f"[INFO] Rows skipped due to missing opcount match: {skipped_missing}")
    if skipped_correctness:
        print(f"[INFO] Rows skipped because all_correct=False: {skipped_correctness}")
    if used_incorrect:
        print(f"[INFO] Used {used_incorrect} timing rows with all_correct=False for performance calibration.")
    return rows


def compute_coefficients(cal_rows: List[dict]) -> List[dict]:
    groups: Dict[Tuple[str, str], List[float]] = {}
    for r in cal_rows:
        groups.setdefault((r["scheme"], r["metric"]), []).append(float(r["ms_per_unit"]))
    coeff_rows = []
    for (scheme, metric), vals in sorted(groups.items()):
        coeff_rows.append({
            "scheme": scheme,
            "metric": metric,
            "calibration_samples": len(vals),
            "coefficient_ms_per_unit_median": median(vals),
            "coefficient_ms_per_unit_min": min(vals),
            "coefficient_ms_per_unit_max": max(vals),
        })
    return coeff_rows


def target_key(row: dict) -> Tuple[str, ...]:
    return tuple(norm_val(row.get(c, "")) for c in KEY_COLS)


def apply_estimates(target_opcounts: List[dict], target_six: List[dict], coeff_rows: List[dict]) -> List[dict]:
    coeff = {(r["scheme"], r["metric"]): float(r["coefficient_ms_per_unit_median"]) for r in coeff_rows}
    target_by_key = {target_key(r): r for r in target_opcounts}

    out = []
    for row in target_six:
        metric = row["metric"]
        new = dict(row)
        if metric == "CiphertextSizes":
            new["estimated_ms"] = ""
            new["estimated_unit"] = row.get("unit", "bytes")
            new["estimated_value"] = row.get("value", "")
            new["note"] = "size metric copied from target data"
        else:
            k = target_key(row)
            op = target_by_key.get(k)
            c = coeff.get((row["scheme"], metric))
            if op is None or c is None:
                new["estimated_ms"] = ""
                new["estimated_unit"] = "ms"
                new["estimated_value"] = ""
                new["note"] = "missing target opcount or calibration coefficient"
            else:
                units = OPCOUNT_EXPR[metric](op)
                est = units * c
                new["estimated_ms"] = est
                new["estimated_unit"] = "ms"
                new["estimated_value"] = est
                new["note"] = f"estimated from {units} work units and calibrated coefficient {c:.6e} ms/unit"
        out.append(new)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-opcounts", required=True, help="target operation_counts.csv")
    ap.add_argument("--target-six", required=True, help="target six_required_data.csv")
    ap.add_argument("--calib-dirs", nargs="+", required=True, help="directories with timings_summary.csv and operation_counts.csv")
    ap.add_argument("--out", default="results_estimated", help="output directory")
    ap.add_argument("--require-correct", action="store_true", help="strictly discard calibration rows where all_correct is false")
    args = ap.parse_args()

    outdir = Path(args.out)
    target_op = read_csv(Path(args.target_opcounts))
    target_six = read_csv(Path(args.target_six))
    cal_rows = load_calibration_rows([Path(x) for x in args.calib_dirs], require_correct=args.require_correct)
    if not cal_rows:
        raise SystemExit("No calibration rows loaded. Check calibration directories or rerun without --require-correct.")

    coeff_rows = compute_coefficients(cal_rows)
    estimated_rows = apply_estimates(target_op, target_six, coeff_rows)

    write_csv(outdir / "calibration_samples.csv", cal_rows)
    write_csv(outdir / "calibration_coefficients.csv", coeff_rows)
    write_csv(outdir / "six_required_data_estimated_time.csv", estimated_rows)

    print(f"Loaded {len(cal_rows)} calibration samples.")
    print(f"Wrote: {outdir / 'calibration_samples.csv'}")
    print(f"Wrote: {outdir / 'calibration_coefficients.csv'}")
    print(f"Wrote: {outdir / 'six_required_data_estimated_time.csv'}")


if __name__ == "__main__":
    main()
