# PostRBE benchmark patch: KeyGen and Register both exclude up_id generation

This version uses the experiment convention requested by the advisor:

- KeyGen measures only one user key generation: sample X and compute pk = U X.
- Register measures only one curator-side registration update after receiving (pk, up_id).
- The generation of up_id / registration upload data is not included in either plotted metric. It is precomputed outside the timed region in executable calibration runs.

Important modelling details:

- For PostRBE, Register opcount is (B-1) * m * t + n * t, not (B-1) * m * t^2.
- For PostRBE*, Register opcount is (B-1) * m * r * t + n * t, because the curator still computes P_{i,pos} * up_id after receiving up_id = Q_pos X.
- up_id sizes are still reported in sizes_estimated.csv for storage/communication accounting, but the computation to create up_id is not shown in the six computation plots.

Run target opcounts:

```powershell
python run_experiments.py --target --opcounts-only --out results_target_main_no_upid_register
```

Run calibration:

```powershell
python run_experiments.py --N 100 400 900 --nm 16,32 --r 8 --star-t 32 --repeats 5 --out results_calibration_small_no_upid_register
python run_experiments.py --N 100 400 900 --nm 32,64 --r 16 --star-t 64 --repeats 5 --out results_calibration_medium_no_upid_register
python run_experiments.py --N 100 400 900 --nm 64,128 --r 32 --star-t 128 --repeats 3 --out results_calibration_large_no_upid_register
```

Estimate times:

```powershell
python calibrate_estimate_v2.py `
  --target-opcounts results_target_main_no_upid_register/operation_counts.csv `
  --target-six results_target_main_no_upid_register/six_required_data.csv `
  --calib-dirs results_calibration_small_no_upid_register results_calibration_medium_no_upid_register results_calibration_large_no_upid_register `
  --out results_estimated_no_upid_register
```

Clean CSV:

```powershell
python make_clean_from_estimated.py `
  --input results_estimated_no_upid_register/six_required_data_estimated_time.csv `
  --out postrbe_six_plot_data_clean_no_upid_register.csv
```
