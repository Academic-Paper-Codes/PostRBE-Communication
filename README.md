# PostRBE Family (Prototype Implementations)

![python](https://img.shields.io/badge/Python-3.10%2B-blue)
![status](https://img.shields.io/badge/Status-Prototype-orange)
![license](https://img.shields.io/badge/License-TBD-lightgrey)

**Version:** `v0.1.0` (research / coursework prototype)

This repository contains **three self-implemented prototypes** in the PostRBE family:

- **PostRBE (base)**: baseline Registration-Based Encryption prototype
- **PostRBE\***: “star” variant (compact/global structure, indexed by `B = ⌊√N⌋`)
- **MPostRBE\***: multi-receiver extension based on PostRBE\* (one shared ciphertext + per-receiver wrappers)

> ⚠️ **Security Notice**  
> These implementations are provided for *experimental / educational* purposes only. They are **not audited**, not hardened, and not intended for production deployment.

---

## Language & Dependencies

- **Language:** Python (recommended **Python 3.10+**)
- **Core dependencies:**
  - `numpy`
  - `cryptography` (AES-GCM AEAD)

### Install
```bash
pip install -r requirements.txt
```

If you don’t have `requirements.txt` yet, you can install minimal deps:
```bash
pip install numpy cryptography
```

---

## Repository Layout

> Put `run.py` in the **root folder** that contains the three project folders.

Recommended structure:
```text
.
├── run.py
├── PostRBE/                 # base scheme
│   ├── demo_postrbe.py
│   ├── postrbe_core.py
│   ├── postrbe_structs.py
│   ├── postrbe_utils.py
│   └── postrbe_debug.py
├── PostRBE_star/            # PostRBE* scheme (folder name can vary)
│   ├── demo_postrbe_star.py
│   ├── postrbe_star_core.py
│   ├── postrbe_star_structs.py
│   └── postrbe_utils.py     # shared utils (same name)
└── MPostRBE_star/           # MPostRBE* scheme (folder name can vary)
    ├── demo_mpostrbe_star.py
    ├── mpostrbe_star_core.py
    ├── mpostrbe_star_structs.py
    └── postrbe_utils.py     # shared utils (same name)
```

---

## Quick Start (Recommended): Run via `run.py`

`run.py` is a cross-terminal safe launcher that:
- auto-detects project folders (base / star / multi)
- runs the corresponding demo using the **current Python interpreter**
- provides a menu UI

### Interactive menu
```bash
python run.py
```

### List detected projects
```bash
python run.py --list
```

### Run a specific project
```bash
python run.py --project base
python run.py --project star
python run.py --project multi
```

Disable dev flags if needed:
```bash
python run.py --no-dev-flags
```

---

## Run Demos Directly (Per-folder)

### PostRBE (base)
```bash
cd PostRBE
python demo_postrbe.py
```

### PostRBE*
```bash
cd PostRBE_star
python demo_postrbe_star.py
```

### MPostRBE*
```bash
cd MPostRBE_star
python demo_mpostrbe_star.py
```

### Windows / PowerShell (your lab-style command)
Run a file in the current folder with explicit interpreter + debug flags:
```powershell
& "C:\Users\userPC\anaconda3\python.exe" -u -X dev -X faulthandler ".\demo_postrbe.py"
```

---

## What Each Folder Contains

### `PostRBE/` (Base)
- `demo_postrbe.py`  
  Minimal runnable demo: setup → keygen → register → encrypt → decrypt.
- `postrbe_core.py`  
  Core algorithms for the base scheme.
- `postrbe_structs.py`  
  Data containers (CRS / public params / aux params).
- `postrbe_utils.py`  
  Matrix sampling, modular arithmetic helpers, hashing-to-key, (toy XOR), AEAD(AES-GCM).
- `postrbe_debug.py`  
  Debug utilities / verbose checks (helpful for inspecting intermediate values).

### `PostRBE_star/` (PostRBE*)
- `demo_postrbe_star.py`  
  Runnable demo + tamper test (AEAD tag failure expected on modification).
- `postrbe_star_core.py`  
  Core algorithms for PostRBE\* (star variant with `B = ⌊√N⌋` indexing).
- `postrbe_star_structs.py`  
  CRSStar / PublicParamsStar / AuxParamsStar (paper-aligned dimensions).
- `postrbe_utils.py`  
  Shared utilities (same filename as base).

### `MPostRBE_star/` (MPostRBE*)
- `demo_mpostrbe_star.py`  
  Multi-receiver demo: encrypt once, multiple receivers decrypt; includes tamper tests.
- `mpostrbe_star_core.py`  
  Core multi-receiver algorithms (group encryption / per-receiver wrapper).
- `mpostrbe_star_structs.py`  
  MCRSStar / MPublicParamsStar / MAuxParamsStar containers.
- `postrbe_utils.py`  
  Shared utilities (AES-GCM, hash-to-key, sampling, etc.).

---

## API Reference (Core Functions)

Below lists the **main public APIs** exposed by each scheme’s `*_core.py`.

> Naming convention: `*_star` indicates PostRBE\*; `*_mstar` indicates multi-receiver PostRBE\*.

### PostRBE (base) — `postrbe_core.py`
```python
setup(security_param, N_max, q, n, m, t) -> (crs, pp, aux)
keygen(user_id, crs, bound)              -> user_param
register(user_param, crs, pp, aux)       -> None
update(user_id, crs, aux)                -> L_id
encrypt(pp, crs, user_id, message)       -> ciphertext
decrypt(user_param, crs, aux, ciphertext)-> bytes
```

### PostRBE* — `postrbe_star_core.py`
```python
setup_star(security_param, N_max, q, n, m, t) -> (crs, pp, aux)
keygen_star(user_id, crs, bound)              -> user_param
register_star(user_param, crs, pp, aux)       -> None
update_star(user_id, crs, aux)                -> L_id
encrypt_star(pp, crs, user_id, message)       -> ciphertext
decrypt_star(user_param, crs, aux, ciphertext)-> bytes
```

### MPostRBE* (Multi-receiver) — `mpostrbe_star_core.py`
```python
setup_mstar(security_param, N_max, q, n, m, t)        -> (crs, pp, aux)
keygen_mstar(user_id, crs, bound)                     -> user_param
register_mstar(user_param, crs, pp, aux)              -> None
update_mstar(user_id, crs, aux)                       -> L_id
encrypt_group_mstar(pp, crs, P, message)              -> group_ciphertext
decrypt_group_mstar(user_param, crs, aux, ct)         -> bytes
```

#### Multi-receiver ciphertext layout (high-level)
- **Shared part:** encrypted payload (one copy)
- **Per-receiver wrapper:** an AEAD-encrypted session key for each recipient

This design avoids re-encrypting the payload for every receiver.

---

## Notes on Results / Data Policy (No Experiment Outputs)

Per course requirement, this repository contains **code only** and does **not** include:
- experimental results
- generated ciphertext/key size tables
- benchmark CSVs
- plots / PDFs

Suggested `.gitignore` entries if you generate local outputs:
```gitignore
*.csv
*.pdf
*.png
*.log
outputs/
Figure-Exp-Data/
__pycache__/
.venv/
```

---

## Reproducibility Tips

- Use the same Python version across machines (recommend 3.10+)
- Fix random seeds in demos if deterministic runs are required
- Keep parameters (`N_max`, `B`, `q`, `n`, `m`, `t`) consistent across all schemes for fair comparisons



