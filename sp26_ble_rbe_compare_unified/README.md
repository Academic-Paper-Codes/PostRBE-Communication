# SP26 BLE-RBE comparison data generator (unified parameters)

This script generates comparison data for **Scalable Registration-Based Encryption from Lattices** using the same clean CSV schema as the PostRBE experiments.

## Unified parameters used

```text
N = 10^3, 10^4, 10^5, 10^6, 10^7
B = ceil(sqrt(N))        # common table parameter in six_plot_data_clean.csv
n = 256
m = 512
r = 128
d = 10
q_bits = 64
sigma_inf = 2
short_range = {-2,-1,0,1,2}
message_bits = 256
```

## Important mapping notes

SP26 BLE-RBE is a module/ring-lattice scheme. Its internal module rank/ring degree are not the same as PostRBE's matrix dimensions. The script therefore:

- records the common table parameters in `six_plot_data_clean.csv`,
- uses the SP26 construction's native structure internally for ciphertext element counts,
- records the internal `B_batch_logN = ceil(log2(N))` in `operation_counts.csv`, because SP26's batch parameter differs from PostRBE's `B = ceil(sqrt(N))`.

In unified mode, `q_bits=64`, no bit-dropping is applied, and all sigma-like short/noise settings are recorded as `2`. Timings are estimated from the paper's benchmark constants and scaled by structural counts; they are not direct Rust measurements.

## Run

```powershell
python run_compare_sp26_ble_unified.py --target --out results_sp26_ble_unified
```

Outputs:

```text
results_sp26_ble_unified/operation_counts.csv
results_sp26_ble_unified/sizes_estimated.csv
results_sp26_ble_unified/six_plot_data_clean.csv
```
