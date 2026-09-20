#!/usr/bin/env python3
"""Generate paper-scale dimensions, operation counts, and size estimates."""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from postrbe.models import opcount_postrbe, opcount_postrbe_star
from postrbe.params import RBEParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results_accounting"))
    parser.add_argument("--q-bits", type=int, default=64, choices=(43, 51, 64))
    parser.add_argument("--N", nargs="+", type=int, default=[1000, 10000, 100000, 1000000])
    args = parser.parse_args()
    rows = []
    for N in args.N:
        base = RBEParams(N=N, n=256, m=512, r=128, q_bits=args.q_bits, sigma_inf=2, keep_bits=10, message_bits=256)
        for result in (opcount_postrbe(base), opcount_postrbe_star(base)):
            row = asdict(result)
            row.update({
                "metric_profile": "paper_scale_accounting",
                "result_type": "operation_count_only",
                "arithmetic_backend": "not_executed_formula",
                "unit_note": "bytes are byte-aligned using ceil(q_bits/8)",
            })
            rows.append(row)
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / "paper_accounting.csv"
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"profile=paper_scale_accounting result_type=operation_count_only q_bits={args.q_bits}")
    print(f"rows={len(rows)} output={target.resolve()}")
    print("ACCOUNTING PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
