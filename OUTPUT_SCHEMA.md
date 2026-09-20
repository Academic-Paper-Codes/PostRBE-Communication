# Output schema

The functional scripts print pass/fail results and do not create manuscript
tables. Their result type is `functional_demo_not_paper_result`.

`scripts/run_accounting.py` writes `paper_accounting.csv`. Every row contains
the complete dimensions, modulus width, noise/extraction settings, operation
counts, byte-aligned size estimates, `metric_profile`, `result_type`,
`arithmetic_backend`, and a unit note. These rows are formulas, not timings.

`run_experiments.py` writes historical direct-demo timing CSVs plus operation
counts. `KeyGen` excludes registration-upload preparation; that preparation is
reported separately. `Register` starts after `(pk, up)` has been received and
includes public validation and the curator-side state update.

Units follow: `KB=1000 B`, `MB=10^6 B`, `KiB=1024 B`, and `MiB=2^20 B`.
NumPy memory allocation is never presented as a network serialization size.
