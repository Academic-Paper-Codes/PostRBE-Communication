# DKLLMR23 / Eurocrypt'23 LE-to-RBE comparison estimator

This is a lightweight experimental estimator for the lattice-based RBE baseline obtained from the Eurocrypt'23 laconic-encryption construction and its generic LE-to-RBE transformation.

It is **not** a production cryptographic implementation. It is a measurement/estimation harness designed to produce the same clean plotting format as the PostRBE experiment:

```text
scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits
```

## Model used

The Eurocrypt'23 paper builds laconic encryption (LE) with algorithms `Setup, KGen, Upd, Enc, WGen, Dec`. The LE ciphertext has components `(c0,...,c_ell,d)`, where each `c_j` for `j<ell` has length `2m`, `c_ell` has length `m`, and `d` has length 1. The RBE construction uses `ell = ceil(log2(N))` states. Each RBE ciphertext component contains two LE ciphertexts and a commitment, so we model:

```text
LE_ct_entries  = (2*ell + 1)*m + 1
RBE_ct_entries = ell * (2*LE_ct_entries + commitment_entries)
```

Default commitment size is `n` elements, modeling a simple SIS-style vector commitment output.

The paper is over a ring `R_q`, so the script supports polynomial multiplication cost models:

- `--poly-mul-model scalar`: one `R_q` multiplication = one scalar muladd; useful to match pure `Z_q` experiments.
- `--poly-mul-model naive`: one `R_q` multiplication = `ring_degree^2` scalar muladds.
- `--poly-mul-model ntt`: one `R_q` multiplication ≈ `ring_degree*log2(ring_degree)` scalar muladds.

Default is `--ring-degree 128 --poly-mul-model ntt`. To force the exact scalar model used by the unified parameter table, use:

```powershell
python run_compare_dkllmr23.py --target --ring-degree 1 --poly-mul-model scalar --out results_dkllmr23_scalar
```

## Target run

Run with the same target parameters as PostRBE:

```powershell
python run_compare_dkllmr23.py --target --out results_dkllmr23
```

This creates:

```text
results_dkllmr23/operation_counts.csv
results_dkllmr23/sizes_estimated.csv
results_dkllmr23/six_plot_data_clean.csv
```

If no timing coefficient is supplied, the first five computation metrics use `plot_unit=work_units`. Ciphertext size uses `plot_unit=MiB`.

## Convert work units to estimated ms

Pass a coefficient file with `metric,ms_per_unit` or the previous `calibration_coefficients.csv` format:

```powershell
python run_compare_dkllmr23.py --target `
  --coefficients path\to\calibration_coefficients.csv `
  --out results_dkllmr23_ms
```

The generated `six_plot_data_clean.csv` will then use `plot_unit=ms` for Setup, KeyGen, Register, Encrypt, and DecryptUpdate.

## Merge with PostRBE data

```powershell
python merge_clean_files.py --inputs path\to\postrbe\six_plot_data_clean.csv results_dkllmr23_ms\six_plot_data_clean.csv --out results_merged\six_plot_data_all.csv
```

## Important notes

- `B=ceil(sqrt(N))` is kept only for compatibility with the PostRBE plot format. This baseline itself uses `ell=ceil(log2(N))`.
- `r` and `t` are kept in the clean CSV for format compatibility. This baseline does not use PostRBE's `r` and `t`; `t` is written as `NA`.
- The default register model is `worst`, matching the weakly-efficient RBE statement that registration can take `O(N)` updates. You can also test `--register-model amortized` or `--register-model sqrt` for alternative trade-offs.
