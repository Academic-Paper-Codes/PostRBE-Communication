# PostRBE / PostRBE* Artifact

This directory contains an executable research artifact for the six algorithms
in the paper: `Setup`, `KeyGen`, `Register`, `Update`, `Encrypt`, and `Decrypt`.
It also implements public membership/non-membership verification, validated
atomic registration, revocation, authenticated ciphertexts, deterministic
serialization, and independent-instance scaling beyond a configured `N`.

This is **not production cryptography**. The functional setup backend uses
`A=[I|0]` and padded preimages so every paper equation can be executed and
tested without a production lattice trapdoor library. Correctness-sensitive
modular multiplication nevertheless uses Python arbitrary-precision
intermediates and is tested near the runtime modulus.

## Paper

This artifact accompanies the paper **“Efficient Post-quantum
Registration-Based Encryption.”**

## Hardware and software requirements

No GPU, accelerator, special hardware, or server is required. All functional
tests and accounting workflows run on the CPU of a commodity x86-64 desktop
or laptop. A machine with at least 8 CPU cores and 16 GB RAM is recommended.

Use a recent Windows or Linux system with Python 3.10 or newer. The Python
dependencies are listed in `requirements.txt`. Internet access is needed only
to obtain the artifact and install those packages.

## Quick start

Tested with Python 3.10+.

Create the virtual environment:

```text
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or activate it on Linux:

```bash
source .venv/bin/activate
```

Then install the dependencies and run the evaluator workflows:

```text
python -m pip install -r requirements.txt
python scripts/run_environment.py
python scripts/run_encryption_demo.py
python scripts/run_smoke.py
python scripts/run_functional.py
```

Expected final lines are `ENVIRONMENT PASS`, `SMOKE PASS`, and
`FUNCTIONAL PASS`. The encryption demo ends with
`ENCRYPTION/DECRYPTION DEMO PASS`. Every command exits nonzero when an
assertion fails.

## Directory map

- `postrbe/params.py`: canonical parameters, dimensions, and identity bounds.
- `postrbe/arithmetic.py`: overflow-safe modular arithmetic plus an explicitly
  named historical unsafe NumPy path.
- `postrbe/extraction.py`: stable high-bit extraction with reconciliation.
- `postrbe/symmetric.py`: AES-256-GCM message protection.
- `postrbe/schemes.py`: both complete schemes and their state transitions.
- `postrbe/manager.py`: independent instances after the current `N` is full.
- `postrbe/serialization.py`: versioned deterministic external encodings.
- `postrbe/models.py`: paper-scale operation and size formulas.
- `postrbe/benchmark.py`: direct functional-demo timing harness.
- `scripts/`: one-command evaluator workflows.
- `tests/`: deterministic acceptance tests.
- `ARTIFACT_IMPLEMENTATION_SPEC.md`: normative implementation checklist.
- `OUTPUT_SCHEMA.md`: result labels, fields, and unit rules.

Historical CSV files, calibration outputs, caches, and superseded README files
are intentionally excluded from this upload-oriented directory. They remain in
the authors' separate backup and are not evaluator entry points.

## Functional API and paper mapping

Instantiate `PostRBE` or `PostRBEStar` with validated `RBEParams`, then call:

```python
scheme.setup()
sk, user = scheme.keygen(identity)       # user packages pk and up
scheme.register(identity, user)
proof = scheme.update(identity)
ciphertext = scheme.encrypt(identity, message)
message = scheme.decrypt(sk, proof, ciphertext)
```

`keygen_full(identity)` returns the literal paper-shaped triple
`(sk_id, pk_id, up_id)`. `keygen(..., include_upload=False)` and
`add_registration_upload(...)` only separate the manuscript timing boundary;
together they produce the same complete key material.

Public verification does not use a secret key:

```python
scheme.verify_membership(identity, pk_id, proof)
scheme.verify_nonmembership(identity, proof)
```

Registration checks the paper equations before changing state. A failed check
leaves `C`, `L`, active registrations, and the state version unchanged.
`revoke(identity)` subtracts the stored contribution. Revocation affects new
ciphertexts and current proofs; it does not erase access to old ciphertexts and
matching old state snapshots. The implementation permits an explicit fresh
registration after revocation; the old record has already been subtracted and
cannot be revoked or counted twice.

## Stable extraction and symmetric encryption

The manuscript specifies the stability contract
`F(x+e)=F(x)` for `||e||_inf < q/2^(d+1)` but does not give an executable bit
encoding. The functional path instantiates that contract with a public
low-part reconciliation hint and tests nonzero noise against the exact bound.
The hint is authenticated as part of AES-256-GCM associated data. AES-GCM also
authenticates the target identity, state version, `c1`, and `c2`.

This helper is reported separately from the paper's ciphertext formula. It is
included in actual functional serialization sizes and must not be silently
folded into or omitted from a claimed network size.

## Profiles and commands

Environment check:

```powershell
python scripts/run_environment.py --out results_environment
```

Fast all-algorithm smoke test (small parameters, normally seconds):

```powershell
python scripts/run_smoke.py
```

Presentation-oriented encryption/decryption demo:

```powershell
python scripts/run_encryption_demo.py
```

For both PostRBE and PostRBE*, this prints the original 256-bit plaintext, all
ciphertext fields (`c1`, `c2`, reconciliation hint, nonce, and authenticated
`c3`), the complete versioned serialized ciphertext, the recovered plaintext,
and the final byte-for-byte equality result. This is the recommended command
when demonstrating encryption and decryption to a reviewer.

Complete deterministic tests (normally under a few minutes):

```powershell
python scripts/run_functional.py
```

Paper-scale formula accounting, without dense allocation:

```powershell
python scripts/run_accounting.py --q-bits 64 --out results_accounting_64
python scripts/run_accounting.py --q-bits 43 --out results_accounting_postrbe_minmod
python scripts/run_accounting.py --q-bits 51 --out results_accounting_star_minmod
```

Historical/direct demo timing:

```powershell
python scripts/run_benchmarks.py --quick --out results_quick
```

Paper target accounting through the historical CLI:

```powershell
python scripts/run_benchmarks.py --target --opcounts-only --out results_target
```

Never remove `--opcounts-only` from a target-scale run without first checking
the reported dimensions. Dense PostRBE matrices at large `N` can require
terabytes and run for hours or longer.

## Commands and artifact claims

| Artifact claim | Evaluator command | Expected evidence |
| --- | --- | --- |
| C1: both schemes execute the six RBE algorithms and public membership/non-membership verification | `python scripts/run_encryption_demo.py`, `python scripts/run_smoke.py`, and `python scripts/run_functional.py` | Exact plaintext recovery, passes for both schemes, and 18 deterministic tests |
| C2: PostRBE* removes the user-scale dimension growth of baseline PostRBE | `python scripts/run_accounting.py --q-bits 64 --N 1000000 --out results_accounting_64` | At `N=10^6`, baseline `t=511745` and PostRBE* `t=512` |
| C3: PostRBE* substantially reduces the byte-aligned ciphertext size | The same accounting command as C2 | 4,098,088 bytes for PostRBE and 8,224 bytes for PostRBE*, about a 498x reduction |

These commands correspond to the functional constructions and correctness
analysis in Sections III–IV and to the complexity and ciphertext-size results
in Section VI and Fig. 5 of the paper. Formula accounting is explicitly
separated from direct timing measurements.

## Canonical experiment parameters

The accounting profile uses `N in {10^3,10^4,10^5,10^6}`,
`B=ceil(sqrt(N))`, `n=256`, `m=512`, `r=128`, `d=10`, short entries in
`{-2,-1,0,1,2}`, and 256-bit messages. PostRBE uses
`t=(B-1)m+n+1`; PostRBE* uses `t=512`. Unified accounting uses 64-bit
elements; minimum-modulus accounting uses 43 bits for PostRBE and 51 bits for
PostRBE*.

The runtime modulus and `q_bits` are separate. Functional-demo timings are not
paper-scale timings. Operation counts, formula sizes, extrapolations, direct
measurements, and manuscript anchors must remain separately labelled.

## Tests and success criteria

The acceptance suite covers:

- parameter and boundary identity validation;
- all setup linking/decomposition equations and zero initialization;
- honest, duplicate, malformed, and tampered registration, including atomic
  failure;
- encryption/decryption with nonzero error and an explicit noise audit;
- wrong keys, stale proofs, and ciphertext tampering;
- public membership and non-membership verification;
- revocation and unaffected-user correctness;
- overflow-safe multiplication near `q-1`;
- serialization round trips and exact encoded byte counts;
- capacity overflow into an independent instance and cross-instance rejection.

Passing these tests establishes functional fidelity of the documented
prototype backend. It does not turn the identity-trapdoor backend into a secure
production lattice implementation and does not independently validate every
historical manuscript benchmark value.

## Troubleshooting

- `cryptography is required`: install `requirements.txt` in the active Python
  environment.
- A stale-proof error means public state changed after `Update`; request a new
  proof for new ciphertexts.
- An out-of-memory risk at target scale means the direct profile was selected;
  use `run_accounting.py` or `--opcounts-only`.
- Preserve existing frozen result directories. Write new runs to a new output
  directory and record device, parameters, repeats, and result type.

For questions during anonymous evaluation, use the conference artifact-review
channel associated with the submission.
