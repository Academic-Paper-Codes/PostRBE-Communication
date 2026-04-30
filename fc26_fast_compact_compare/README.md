# FC26 Fast and Compact RBE Comparison Generator

This folder generates benchmark/estimation CSVs for the ePrint 2026 paper **Fast and Compact Lattice-Based Registration-Based Encryption**.

The paper contains two schemes:

1. `FC26-BaseRBE` — the Base RBE construction from Section 3.
2. `FC26-MoreEfficientRBE` — the compressed/more efficient RBE construction from Section 4.

The output format matches the previous `six_plot_data_clean.csv` format used for PostRBE / PostRBE*:

```csv
scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits
```

## Run

```powershell
python -S run_compare_fc26.py --target --out results_fc26
```

If normal Python is fine on your machine, this also works:

```powershell
python run_compare_fc26.py --target --out results_fc26
```

## Outputs

```text
results_fc26/operation_counts.csv
results_fc26/sizes_estimated.csv
results_fc26/six_plot_data_clean.csv
```

Use `six_plot_data_clean.csv` for the six figures:

- Setup
- KeyGen
- Register
- Encrypt
- DecryptUpdate
- CiphertextSizes

For this paper, `DecryptUpdate = HskGen + Dec`, because the helper decryption key generation/update is the closest counterpart to the update/witness-generation part used in the other RBE comparisons.

## Unified parameters

The clean CSV records the same unified parameters as the existing PostRBE experiment:

```text
N = 10^3, 10^4, 10^5, 10^6, 10^7
B = ceil(sqrt(N))
n = 256
m = 512
r = 128
q_bits = 64
d = 10
sigma_inf = 2
short_range = {-2,-1,0,1,2}
message_bits = 256
```

Important: the paper also uses `d=64`, but that is **d-ary decomposition base**, not the same as our `F[.]` high-bit extraction parameter `d=10`. Therefore, the script keeps the paper value in `operation_counts.csv` as:

```text
decomposition_base_internal = 64
```

and keeps the clean CSV's `d=10` only for compatibility with the existing plot format.

## Modelling notes

This is not a full cryptographic implementation. It is a benchmark/estimation data generator. It uses benchmark anchors from the paper's Table 2 and Table 3 at `Rq = Zq[X]/(X^256 + 1)` and `S=1000`.

The paper uses a 59-bit NTT-friendly prime. Since our unified comparison uses a 64-bit modulus, storage sizes are scaled by `64/59` by default. Timing values are kept from the paper's benchmark anchors, because both 59-bit and 64-bit settings use 64-bit arithmetic in practice.

## Useful options

Use custom N values:

```powershell
python -S run_compare_fc26.py --N 1000 10000 --out results_custom
```

Use `l = ceil(log2(N))` internally instead of paper identity length `l=50`:

```powershell
python -S run_compare_fc26.py --target --use-log-identity-len --scale-time-by-identity-len --out results_log_identity
```

Disable storage scaling from 59-bit q to 64-bit q:

```powershell
python -S run_compare_fc26.py --target --no-scale-sizes-by-qbits --out results_no_qbit_scaling
```
