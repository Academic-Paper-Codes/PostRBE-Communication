# PostRBE Experimental Evaluation (Prototype Code and Data)

![python](https://img.shields.io/badge/Python-3.10%2B-blue)
![status](https://img.shields.io/badge/Status-Research%20Prototype-orange)
![license](https://img.shields.io/badge/License-TBD-lightgrey)

**Version:** `v0.2.0` (research / coursework prototype)

This repository contains the Python prototype code and experimental data used to evaluate the **PostRBE** family and several post-quantum Registration-Based Encryption (RBE) baselines. The code is designed to generate operation counts, estimated running times, size estimates, clean plotting CSV files, and the final figures used in the experimental section.

The evaluated schemes are:

- **PostRBE**: our baseline lattice-based RBE scheme.
- **PostRBE\***: our optimized scheme with fixed-size/decomposition-based structure.
- **DöttlingRBE**: the EUROCRYPT'23 laconic-encryption-based RBE baseline.
- **KlooßRBE**: the SP'26 scalable lattice-based RBE baseline.
- **ZhangRBE-I**: the FC'26 / ePrint base RBE construction.
- **ZhangRBE-II**: the FC'26 / ePrint more efficient RBE construction.

> ⚠️ **Security Notice**  
> These implementations are for research, coursework, and experimental evaluation only. They are not audited, not side-channel hardened, and not intended for production deployment.

---

## Main Experiment Convention

The experiments follow the convention used in the paper:

- The reported time is the cost of executing one algorithm once under a system with `N` registered users, **not** the cost of executing the algorithm `N` times.
- `KeyGen` measures one user key generation.
- `Register` measures one curator-side registration operation.
- In the final PostRBE/PostRBE* model, `KeyGen` and `Register` do **not** include `up_id` generation.
- The decryption-related operation is modeled as receiver-side reconstruction/decryption.
- For PostRBE/PostRBE*, decryption uses two vector-matrix products and one vector addition:

```text
c2 X_id        : (1 x t) @ (t x t), cost t^2
c1 L_{id*,id'}: (1 x m) @ (m x t), cost m*t
vector add     : (1 x t) + (1 x t), cost t
```

Therefore, the decryption operation count is:

```text
decrypt_muladds = t^2 + m*t + t
```

It is **not** modeled as matrix-matrix multiplication with cost `t^3`.

---

## Unified Parameters

Unless otherwise stated, the clean CSV files use the following unified parameters:

```text
N = 10^3, 10^4, 10^5, 10^6, 10^7
B = ceil(sqrt(N))
n = 256
m = 512
r = 128
d = 10                 # high-bit extraction parameter for F[.]
q_bits = 64            # unified modulus size
sigma_inf = 2
short_range = {-2,-1,0,1,2}
message_bits = 256
```

For minimum-modulus experiments, the modulus sizes used in the paper are:

```text
DöttlingRBE: 58 bits
KlooßRBE: 48 bits
ZhangRBE-I: 59 bits
ZhangRBE-II: 59 bits
PostRBE: 43 bits
PostRBE*: 51 bits
```

---

## Dependencies

- Python 3.10+
- NumPy
- pandas
- matplotlib

Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, install the minimal dependencies manually:

```bash
pip install numpy pandas matplotlib
```

---

## Recommended Repository Layout

A cleaned repository should keep only the final code, scripts, and selected clean data files:

```text
.
├── README.md
├── requirements.txt
├── .gitignore
│
├── postrbe_no_upid_in_keygen_register/
│   ├── postrbe/
│   │   ├── __init__.py
│   │   ├── benchmark.py
│   │   ├── linalg.py
│   │   ├── models.py
│   │   ├── params.py
│   │   └── schemes.py
│   ├── run_experiments.py
│   ├── calibrate_estimate_v2.py
│   ├── make_clean_from_estimated.py
│   └── requirements.txt
│
├── dkllmr23_compare/
│   ├── dkllmr23_compare/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   └── params.py
│   ├── run_compare_dkllmr23.py
│   ├── merge_clean_files.py
│   └── requirements.txt
│
├── sp26_ble_rbe_compare_unified/
│   ├── run_compare_sp26_ble_unified.py
│   └── README.md
│
├── fc26_fast_compact_compare/
│   ├── run_compare_fc26_v2_hskgen_amortized.py
│   └── README.md
│
└── Figure-Exp-Data/
    ├── plot_six_metrics_from_clean_csvs_v6_custom_no1e7_kb.py
    ├── dkllmr23_six_plot_data_clean_ms.csv
    ├── sp26_six_plot_data_clean.csv
    ├── fc26_six_plot_data_clean.csv
    └── postrbe_six_plot_data_clean_no_upid_register_vector_decrypt.csv
```

The plotting script accepts explicit CSV files, so the exact data folder name can be changed as long as the command is updated accordingly.

---

## Reproduce PostRBE / PostRBE* Data

Run the final PostRBE/PostRBE* target operation-count model:

```powershell
cd postrbe_no_upid_in_keygen_register

python run_experiments.py --target --opcounts-only --out results_target_main_vector_decrypt
```

Convert operation counts to estimated running times using the calibration data:

```powershell
python calibrate_estimate_v2.py `
  --target-opcounts results_target_main_vector_decrypt/operation_counts.csv `
  --target-six results_target_main_vector_decrypt/six_required_data.csv `
  --calib-dirs results_calibration_small_no_upid_register results_calibration_medium_no_upid_register results_calibration_large_no_upid_register `
  --out results_estimated_vector_decrypt
```

Generate the clean plotting CSV:

```powershell
python make_clean_from_estimated.py `
  --input results_estimated_vector_decrypt/six_required_data_estimated_time.csv `
  --out postrbe_six_plot_data_clean_no_upid_register_vector_decrypt.csv
```

The important output files are:

```text
results_target_main_vector_decrypt/operation_counts.csv
results_target_main_vector_decrypt/six_required_data.csv
results_target_main_vector_decrypt/sizes_estimated.csv
results_estimated_vector_decrypt/six_required_data_estimated_time.csv
postrbe_six_plot_data_clean_no_upid_register_vector_decrypt.csv
```

---

## Reproduce Baseline Data

### DöttlingRBE / DKLLMR23

```powershell
cd dkllmr23_compare
python run_compare_dkllmr23.py --target --q-bits 64 --time-model benchmark_anchor --out results_dkllmr23_fixed_64
python run_compare_dkllmr23.py --target --q-bits 58 --time-model benchmark_anchor --out results_dkllmr23_fixed_minmod
```

Outputs:

```text
results_dkllmr23_fixed_64/operation_counts.csv
results_dkllmr23_fixed_64/sizes_estimated.csv
results_dkllmr23_fixed_64/six_plot_data_clean.csv
results_dkllmr23_fixed_minmod/six_plot_data_clean.csv
```

### KlooßRBE / SP26 BLE-RBE

```powershell
cd sp26_ble_rbe_compare_unified
python run_compare_sp26_ble_unified.py --target --out results_sp26_ble_unified
```

Outputs:

```text
results_sp26_ble_unified/operation_counts.csv
results_sp26_ble_unified/sizes_estimated.csv
results_sp26_ble_unified/six_plot_data_clean.csv
```

### ZhangRBE-I and ZhangRBE-II / FC26

```powershell
cd fc26_fast_compact_compare
python run_compare_fc26_v2_hskgen_amortized.py --target --q-bits 64 --out results_fc26_64
python run_compare_fc26_v2_hskgen_amortized.py --target --q-bits 59 --out results_fc26_minmod
```

Outputs:

```text
results_fc26_64/operation_counts.csv
results_fc26_64/sizes_estimated.csv
results_fc26_64/six_plot_data_clean.csv
results_fc26_minmod/six_plot_data_clean.csv
```

---

## Generate Figures

Use the final plotting script and explicitly pass the clean CSV files:

```powershell
cd Figure-Exp-Data

python plot_six_metrics_from_clean_csvs_v6_custom_no1e7_kb.py `
  --csv dkllmr23_six_plot_data_clean_ms.csv `
        sp26_six_plot_data_clean.csv `
        fc26_six_plot_data_clean.csv `
        postrbe_six_plot_data_clean_no_upid_register_vector_decrypt.csv `
  --out Figure-Exp
```

The script generates individual PDFs and a combined six-panel figure:

```text
Figure-Exp/computation-encrypt-64.pdf
Figure-Exp/computation-decrypt-64.pdf
Figure-Exp/ciphertext-64.pdf
Figure-Exp/computation-six-panel.pdf
```

Depending on the plotting-script version, output names may also include:

```text
computation-setup.pdf
computation-keygen.pdf
computation-register.pdf
computation-ciphertext-sizes.pdf
computation-decrypt-update.pdf
computation-encrypt.pdf
```

---

## Clean CSV Format

All `six_plot_data_clean.csv` files follow this schema:

```csv
scheme,N,B,metric,plot_value,plot_unit,n,m,r,t,q_bits,d,sigma_inf,short_range,message_bits
```

The six main metrics are:

```text
Setup
KeyGen
Register
Encrypt
DecryptUpdate
CiphertextSizes
```

The plotting script normalizes scheme names into the final legend labels:

```text
DöttlingRBE
KlooßRBE
ZhangRBE-I
ZhangRBE-II
PostRBE
PostRBE*
```

---

## Files Recommended for Upload

Upload the final source code and the clean data needed to reproduce figures and tables:

```text
README.md
requirements.txt
.gitignore
postrbe_no_upid_in_keygen_register/postrbe/*.py
postrbe_no_upid_in_keygen_register/run_experiments.py
postrbe_no_upid_in_keygen_register/calibrate_estimate_v2.py
postrbe_no_upid_in_keygen_register/make_clean_from_estimated.py

dkllmr23_compare/dkllmr23_compare/*.py
dkllmr23_compare/run_compare_dkllmr23.py

fc26_fast_compact_compare/run_compare_fc26_v2_hskgen_amortized.py
sp26_ble_rbe_compare_unified/run_compare_sp26_ble_unified.py

Figure-Exp-Data/plot_six_metrics_from_clean_csvs_v6_custom_no1e7_kb.py
Figure-Exp-Data/*six_plot_data_clean*.csv
Figure-Exp-Data/*sizes_estimated*.csv
membership_nonmembership_estimated_64bit.csv
```

If you want a smaller repository, include only the final clean CSVs and not every intermediate `results_*` directory.

---

## Files Not Recommended for Upload

The following files are generated, duplicated, old, or unnecessary for the final repository:

```gitignore
# Python cache
__pycache__/
*.pyc
.pytest_cache/

# Old zip packages and patches
*.zip

# Backup or temporary files
*.bak
*.tmp
*.log

# Local generated result folders, unless intentionally archived
results_example/
results_test/
results_*/

# Generated figures, unless required by the paper submission
Figure-Exp-Data/Figure-Exp/
*.pdf
*.png

# Local documents and papers, not source code
#U6587#U4ef6/
*.docx
*.pptx
```

In the current working folder, the following are especially safe to remove before upload:

- `__pycache__/` folders
- `.pytest_cache/` folders
- old zip files such as `postrbe_python.zip`, `postrbe_python_v2.zip`, `postrbe_keygen_no_upid_patch.zip`, `postrbe_no_upid_in_keygen_register_patch.zip`
- old prototype folders such as `postrbe_python_v2/` and `postrbe_keygen_no_upid/` if the final folder `postrbe_no_upid_in_keygen_register/` is kept
- paper PDFs and screenshots inside `#U6587#U4ef6/`
- old or unused scripts such as `run_compare_fc26_v3_decrypt_metric.py` if not used in the final experiments
- duplicate old CSVs if a newer final clean CSV is already included

---

## Notes

- The scripts are estimation/benchmark harnesses, not production cryptographic implementations.
- For very large `N`, dense execution of PostRBE is not realistic; use `--opcounts-only` and calibrated estimation.
- The exact final paper figures should be generated from the final clean CSV files, not from old intermediate CSVs.
- Keep scheme names consistent in plots: `DöttlingRBE`, `KlooßRBE`, `ZhangRBE-I`, `ZhangRBE-II`, `PostRBE`, and `PostRBE*`.
