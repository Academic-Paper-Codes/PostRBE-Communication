# PostRBE Artifact Implementation Specification

## 1. Purpose and Status

This document is the implementation contract for the PostRBE artifact. It is derived from the submitted paper `main-blue.tex`, the project audit rules in `RE/AGENTS.md`, and the final experiment conventions used by the manuscript.

The implementation must provide complete, executable demonstrations of both `PostRBE` and `PostRBE*`, including:

- system setup;
- user key generation;
- registration with public validity checks;
- opening update;
- encryption;
- decryption;
- membership proof generation and verification;
- non-membership proof generation and verification;
- registered-key revocation;
- scaling beyond the configured user bound;
- parameter-size, communication-size, and operation-count reporting;
- reproducible functional tests and benchmark entry points.

This is a research artifact, not a production cryptographic library. The artifact must clearly distinguish a paper-faithful algebraic prototype from a production-secure implementation. It must not claim production security, constant-time behavior, or production-quality trapdoor sampling unless those features are actually implemented and audited.

## 2. Sources of Truth and Precedence

When code, CSV files, and documentation disagree, use the following order:

1. the submitted paper's algorithm definitions and equations;
2. explicit, user-confirmed final experiment conventions in `RE/AGENTS.md`;
3. this implementation specification;
4. the latest implementation directory;
5. older code variants and historical CSV files.

The implementation base is:

```text
RE/ccs/postrbe_no_upid_in_keygen_register/
```

The directories `postrbe_python_v2/` and `postrbe_keygen_no_upid/` are historical versions. They may be consulted for provenance, but they must not silently overwrite the latest implementation.

## 3. Required Execution Profiles

The artifact must expose three explicitly named profiles. Results from different profiles must never be mixed without a source label.

### 3.1 Functional Demo Profile

Purpose: execute every algorithm end to end with small dimensions and verify all algebraic invariants.

Requirements:

- both PostRBE and PostRBE* execute using safe modular arithmetic;
- all correctness tests pass deterministically for multiple seeds, identities, blocks, and messages;
- nonzero error terms are exercised in a noisy-correctness test;
- a separate exact-algebra test may use zero noise, but it must be labeled `exact_algebra_test`, not as the noisy paper experiment;
- runtime should be short enough for the evaluator's kick-the-tires stage;
- output must state the parameter profile and must not be presented as a paper-scale timing result.

### 3.2 Paper-Scale Accounting Profile

Purpose: reproduce dimensions, operation counts, size formulas, and paper-scale planning data without allocating infeasible dense matrices.

Requirements:

- support `N = 10^3, 10^4, 10^5, 10^6`, with `10^7` allowed as an explicitly labeled extension;
- generate operation counts and size estimates without dense target-scale allocation;
- record formulas, parameter values, byte conventions, and result type in every output row;
- never label operation-count estimates or calibrated estimates as direct measurements.

### 3.3 Benchmark Reproduction Profile

Purpose: run the executable benchmark paths used to support the paper, where practical, and preserve the final timing conventions.

Requirements:

- separate direct measurements, streamed full-work measurements, calibrated estimates, extrapolations, formula sizes, paper anchors, and user-confirmed values;
- preserve raw outputs and do not overwrite manuscript values automatically;
- state whether the runtime modulus equals the reported modulus or is only a prototype modulus;
- refuse or clearly warn before an infeasible dense target-scale run;
- write results to a newly created, timestamped output directory.

## 4. Canonical Parameters

Unless a test explicitly selects smaller demo parameters, the paper parameter set is:

```text
N = 10^3, 10^4, 10^5, 10^6
B = ceil(sqrt(N))
n = 256
m = 512
r = 128
d = 10
short elements = {-2, -1, 0, 1, 2}
message_bits = 256

PostRBE:  t = (B - 1)m + n + 1
PostRBE*: t = 512
```

At `N = 10^6`, `B = 1000` and PostRBE uses `t = 511745`.

The two modulus profiles are:

```text
unified: q_bits = 64
minimum PostRBE:  q_bits = 43
minimum PostRBE*: q_bits = 51
```

The code must not infer runtime behavior by multiplying a 64-bit timing by `q_bits / 64`. The active backend, storage representation, and runtime modulus must be reported explicitly.

## 5. Identity and Block Indexing

The public API uses identities in the inclusive range `1 <= id <= N`.

To avoid ambiguity between mathematical and programming indexing, implementations must first convert to a zero-based identity:

```text
u = id - 1
block = floor(u / B)       # zero-based
position = u mod B         # zero-based
id_star = block + 1        # one-based paper display
id_prime = position + 1    # one-based paper display
```

Every public method must reject identities outside its active instance. Duplicate registration of an active identity must be rejected. The indexing convention must be stated in the README because the paper writes the mapping using mathematical notation.

## 6. Common Data Structures

All structures must validate dimensions and modulus compatibility at construction or deserialization time.

### 6.1 Parameters

`RBEParams` must include at least:

```text
lambda_security
N, B
n, m, r, t
q, q_bits
d / keep_bits
short_bound or short distribution
message_bits
seed, where deterministic testing is requested
profile name
arithmetic backend name
result type
```

Validation rules include:

- `N > 0`, `B = ceil(sqrt(N))`;
- `m > n` for the paper construction;
- PostRBE: `t > (B - 1)m + n`;
- PostRBE*: `t > r`;
- `q > 2`, `1 <= d < log2(q)`;
- the chosen correctness bound is satisfied for the noisy demo;
- dimensions fit the selected execution profile.

### 6.2 Common Reference String

The common reference string `crs` stores only public data after setup.

Common fields:

```text
N, B, n, m, r, t, q, d
A[0..B-1] where A_i is n x m
U[0..B-1] where U_i is n x t
public symmetric-encryption and extraction configuration
scheme identifier and format version
```

PostRBE adds public `T[i][j]` for `i != j`, each `m x t`, satisfying:

```text
A_i T_i,j = U_j mod q
```

PostRBE* adds:

```text
V[j]       n x r
Q[j]       r x t
P[i][j]    m x r for i != j
U_j = V_j Q_j mod q
A_i P_i,j = V_j mod q
```

Setup trapdoors are setup-only secret state. They must not appear in the exported `crs`, `pp`, or `aux`. A toy backend using `A = [I | 0]` and padded preimages is allowed only when clearly labeled as a functional prototype backend.

### 6.3 Public and Auxiliary State

```text
pp.C[block]              n x t block commitment
aux.L[block][position]   m x t opening
```

All entries are initialized to zero.

Updates must be atomic: if validation fails, neither `pp` nor `aux` may change.

### 6.4 User Records

Common secret and public records:

```text
SecretKey:
  identity
  instance_id
  block
  position
  X: t x t short matrix

PublicKey:
  identity
  pk: n x t matrix

RegistrationRecord:
  identity
  instance_id
  block
  position
  pk
  up
  active flag
  registration metadata
```

PostRBE registration upload:

```text
up[i] = T_i,position X for i != position
up[position] = zero or omitted by an unambiguous encoding
```

PostRBE* registration upload:

```text
up = Q_position X          # r x t
```

The curator must retain the active registration record needed for correct revocation.

### 6.5 Ciphertext and Proofs

```text
Ciphertext:
  scheme and format version
  instance_id
  target identity or unambiguous target block/position metadata
  c1: 1 x m
  c2: 1 x t
  c3: symmetric ciphertext bytes
  symmetric nonce/metadata if required by the selected SE implementation

OpeningProof:
  instance_id
  identity
  block
  position
  pi = L[block][position]
  state/version identifier
```

A proof is valid only for the public-state version from which it was generated.

## 7. Complete Algorithm Contracts

The public artifact API must expose the full paper algorithms. Benchmark-only timing splits may exist internally, but they must not replace the complete public algorithms.

### 7.1 Setup

Signature:

```text
(crs, pp, aux, setup_audit) = Setup(lambda_security, N, params, backend)
```

PostRBE steps:

1. Create `B` matrices `A_i` and setup-only trapdoor state.
2. Create `B` matrices `U_j`.
3. Derive short `T_i,j` for `i != j` satisfying `A_i T_i,j = U_j mod q`.
4. Initialize every `C_block` and `L_block,position` to zero.
5. Erase or discard setup-only trapdoor state before returning public state.

PostRBE* steps:

1. Create `A_i` and setup-only trapdoor state.
2. Create `V_j`, short `Q_j`, and `U_j = V_j Q_j mod q`.
3. Derive short `P_i,j` for `i != j` satisfying `A_i P_i,j = V_j mod q`.
4. Initialize public and auxiliary state to zero.
5. Erase or discard setup-only trapdoor state.

Required setup self-checks:

- every published linking equation holds;
- no self-link matrix is accidentally exported when the construction excludes it;
- trapdoor state is absent from serialized public outputs;
- dimensions and value bounds are valid.

### 7.2 KeyGen

Public signature:

```text
(sk_id, pk_id, up_id) = KeyGen(crs, id, rng)
```

Common steps:

1. Validate the identity and map it to block and position.
2. Sample short `X_id` in `Z_q^(t x t)`.
3. Compute `pk_id = U_position X_id mod q`.

PostRBE additionally computes every cross-position upload:

```text
up_id[i] = T_i,position X_id mod q for i != position
```

PostRBE* computes:

```text
up_id = Q_position X_id mod q
```

The functional API must return all three paper outputs. For timing compatibility, the implementation may internally expose:

```text
keygen_core()                 # sample X and compute pk
prepare_registration_upload()# compute up_id outside timed KeyGen/Register regions
```

These internal timing helpers must produce the same final values as full `KeyGen`.

### 7.3 Register

Signature:

```text
(pp_new, aux_new, receipt) = Register(crs, pp, aux, id, pk_id, up_id)
```

Common preconditions:

- identity is in range;
- identity is not already actively registered;
- shapes and modulus match the active instance;
- all uploaded matrices satisfy the configured shortness/format checks;
- validation occurs before any state mutation.

PostRBE must verify, for every `i != position`:

```text
pk_id = A_i up_id[i] mod q
```

PostRBE* must verify:

```text
pk_id = V_position up_id mod q
```

On successful PostRBE registration:

```text
C_block <- C_block + pk_id mod q
L_block,i <- L_block,i + up_id[i] mod q for i != position
L_block,position remains unchanged
```

On successful PostRBE* registration:

```text
C_block <- C_block + pk_id mod q
L_block,i <- L_block,i + P_i,position up_id mod q for i != position
L_block,position remains unchanged
```

On failure, return a typed error and leave all state byte-for-byte unchanged.

The final paper timing convention measures curator-side registration only after `(pk_id, up_id)` has already been received. Upload generation must be reported separately and must not be silently added to KeyGen or Register manuscript timings.

### 7.4 Update

Signature:

```text
proof = Update(aux, id)
```

Steps:

1. Validate and map the identity.
2. Return the current opening `pi = L_block,position` with the public-state version.

`Update` is a lookup in the artifact model. Database, network, and serialization overhead must be reported separately if measured.

### 7.5 Encrypt

Signature:

```text
c = Encrypt(crs, pp, id, message, rng)
```

Steps for both schemes:

1. Validate identity, message length, instance, and public-state version.
2. Sample short `S` in `Z_q^(1 x n)` and errors `e1`, `e2`.
3. Compute:

```text
c1 = S A_position + e1 mod q
c2 = S U_position + e2 mod q
shared = S C_block mod q
K = H(F(shared))
c3 = SE.Enc(K, message)
```

4. Return the complete ciphertext with any symmetric nonce and target metadata.

The symmetric layer must be a documented implementation of the paper's `SE.Enc/SE.Dec` interface. A toy XOR stream must not be described as production encryption. If retained for isolated benchmarks, it must be named and labeled as a toy backend. The evaluator-facing functional path should use an established symmetric primitive and deterministic test vectors where appropriate.

### 7.6 Decrypt

Signature:

```text
message = Decrypt(crs, sk_id, proof, c)
```

Steps:

1. Validate scheme, instance, identity/position, dimensions, state version, and ciphertext encoding.
2. Compute:

```text
reconstructed = c2 X_id + c1 pi mod q
K = H(F(reconstructed))
message = SE.Dec(K, c3)
```

3. Return the message on success, otherwise a typed decryption error.

The implementation must never report a successful correctness test merely because the membership equation passed. Decryption equality and proof verification are separate assertions.

The decryption operation-count model is:

```text
c2 X_id: t^2 multiply-adds
c1 pi:   m t multiply-adds
addition: t additions
total:   t^2 + m t + t
```

It must not be modeled as a `t^3` matrix-matrix multiplication.

## 8. Membership and Non-Membership Verifiability

The opening proof for both statements is `pi = Update(aux, id)`.

### 8.1 Membership

Public verifier signature:

```text
bool = VerifyMembership(crs, pp, id, pk_id, proof)
```

Verification equation:

```text
C_block = A_position pi + pk_id mod q
```

The verifier must use the public key, not the user's secret matrix. A convenience method may derive `pk_id` from a local secret key for testing, but the public verification API must not require `sk_id`.

### 8.2 Non-Membership

Public verifier signature:

```text
bool = VerifyNonMembership(crs, pp, id, proof)
```

Verification equation:

```text
C_block = A_position pi mod q
```

### 8.3 Required Negative Tests

- membership verification fails for an unregistered identity;
- non-membership verification fails for a registered identity;
- changing `pk_id`, `pi`, identity, block, position, instance, or state version causes verification failure;
- stale proofs are either rejected by version or explicitly re-evaluated against the matching historical state;
- proof verification uses safe modular arithmetic and does not depend on accidental `int64` wraparound.

## 9. Revocation

Signature:

```text
(pp_new, aux_new, receipt) = Revoke(crs, pp, aux, registration_record)
```

Preconditions:

- the identity is actively registered;
- the stored registration record matches the current instance;
- revocation updates are computed before atomic commit.

PostRBE revocation:

```text
C_block <- C_block - pk_id mod q
L_block,i <- L_block,i - up_id[i] mod q for i != position
```

PostRBE* revocation:

```text
C_block <- C_block - pk_id mod q
L_block,i <- L_block,i - P_i,position up_id mod q for i != position
```

After revocation:

- the identity is inactive;
- membership verification fails;
- non-membership verification succeeds for the updated state;
- unaffected users still decrypt ciphertexts generated from the updated state;
- the revoked key cannot satisfy the current reconstruction relation for newly generated ciphertexts;
- re-registering the identity is allowed only under an explicit policy and must not double-count old state.

Revocation does not retroactively erase access to old ciphertexts and old public-state snapshots. The README must state this scope.

## 10. Scaling Beyond N

The paper scales beyond the configured user bound by creating a fresh independent system instance after the current instance reaches capacity.

Required manager behavior:

```text
SystemManager:
  instances[]
  create_instance(N, params)
  locate_identity(global_identity)
  register_to_active_instance(...)
```

Requirements:

- a new instance has independent `crs`, `pp`, and `aux`;
- existing instances and registrations remain unchanged;
- existing users do not re-register;
- ciphertexts and proofs contain an `instance_id`;
- cross-instance keys, proofs, and ciphertexts are rejected;
- the artifact includes a small test that fills one instance, creates a second, and verifies both remain usable.

## 11. Correctness and Arithmetic Requirements

### 11.1 Algebraic Reconstruction

For a registered identity, both schemes must satisfy:

```text
A_position L_block,position + U_position X_id = C_block mod q
```

The receiver reconstructs:

```text
c2 X_id + c1 L_block,position
= S C_block + E_dec mod q

E_dec = e2 X_id + e1 L_block,position
```

### 11.2 Noise Bound

Correctness requires:

```text
||E_dec||_infinity < q / 2^(d + 1)
```

The test harness must calculate the actual infinity norm for demo runs and record the allowed threshold.

Useful analytical bounds are:

```text
PostRBE:
||E_dec||_infinity
<= t beta_e2 beta_X
 + m(B - 1)t beta_e1 beta_T beta_X

PostRBE*:
||E_dec||_infinity
<= t beta_e2 beta_X
 + m(B - 1)r t beta_e1 beta_P beta_Q beta_X
```

### 11.3 Safe Modular Arithmetic

The expression `(a @ b) % q` on signed NumPy `int64` arrays is forbidden when intermediate products or sums may overflow.

The implementation must provide and name a safe backend, using one of:

- checked chunked modular multiplication with a proven no-overflow bound;
- Python arbitrary-precision integers for small functional tests;
- a tested modular arithmetic implementation using Barrett, Montgomery, RNS, or another correct technique;
- a trusted external implementation with documented parameters.

Every backend must be tested against a Python big-integer reference on random small matrices.

The current historical NumPy path may remain only as `legacy_numpy_benchmark` if needed for provenance. It must not be used to assert cryptographic correctness.

### 11.4 Stable Extraction

The extractor `F` must have an explicit stability contract matching the paper's correctness condition. Directly shifting/truncating high bits is not sufficient evidence of stability.

Before upload, one of the following must be true:

1. the exact paper extractor/reconciliation mechanism is implemented and tested with nonzero errors; or
2. the functional artifact clearly separates exact algebra from the unresolved noisy extractor and does not claim full noisy correctness.

The required target is option 1. The artifact must not silently use zero noise, a constant key, or rejection behavior that changes the paper algorithm while claiming paper-faithful noisy correctness.

## 12. Serialization and Size Accounting

Serialized formats must be versioned and deterministic where practical.

Every reported size must identify whether it is:

- mathematical element count;
- bit-packed serialized size;
- byte-aligned serialized size;
- compressed or bit-dropped size;
- NumPy/Rust in-memory size;
- formula estimate.

Use:

```text
KB  = 1000 bytes when explicitly labeled decimal
MB  = 10^6 bytes
KiB = 2^10 bytes
MiB = 2^20 bytes
```

The common uncompressed ciphertext formula is:

```text
elements = m + t
bits = (m + t) ceil(log2(q)) + |c3|_bits
```

Any byte-aligned estimate must state `ceil(q_bits / 8)`. Bit-dropping, packing, compression, seeds, and protocol metadata require scheme-specific formulas. In-memory `uint64` size is not network communication size.

## 13. Benchmark Semantics and Provenance

The following metric definitions are mandatory:

```text
Setup:
  setup work only

KeyGen manuscript timing:
  sample X and compute pk
  excludes registration-upload generation

Registration upload generation:
  separately report preparation of up_id

Register manuscript timing:
  curator validation and public/auxiliary state update after receiving pk and up
  excludes upload generation and network transfer

Update:
  opening lookup/computation only

Encrypt:
  paper Encrypt algorithm

Decrypt:
  paper Decrypt algorithm

Decryption-related:
  Update + Decrypt

Membership/Non-membership computation:
  verification equation runtime

Proof size:
  serialized opening pi
```

Every benchmark row must include at least:

```text
scheme, metric
N, B, n, m, r, t
q_bits, q_runtime, arithmetic_backend
value, unit
device, platform
result_type
measured_N, measured_B
repeats, mean, median, stdev, min, max
source_file
original_value
notes
```

Allowed result types include:

```text
direct_pc_target
direct_mobile_target
direct_mobile_streamed_full_work
mobile_calibrated_estimate
extrapolated_from_mobile_N100
paper_anchor
paper_native_minmod_anchor
formula_size
external_phone_user_confirmed
current_manuscript_user_confirmed
hypothetical_not_measured
functional_demo_not_paper_result
operation_count_only
```

Generated results must not overwrite frozen manuscript tables. Any replacement requires explicit human approval and a change record.

## 14. Required Command-Line Workflows

Exact command names may change during implementation, but the final artifact must provide equivalent one-command workflows.

```text
1. Environment check
   Verify Python, dependencies, CPU, memory, and writable output path.

2. Smoke test
   Run both schemes with very small parameters in under a few minutes.

3. Full functional test
   Run all algorithms, membership, non-membership, invalid registration,
   revocation, and scaling tests.

4. Paper-scale accounting
   Generate dimensions, operation counts, and size estimates.

5. Reproduction workflow
   Recreate selected tables/figures or their supporting canonical CSV files.

6. Optional long benchmark
   Require an explicit flag and print estimated memory/time before execution.
```

Each command must print:

- active scheme and profile;
- complete parameters;
- whether values are direct, estimated, extrapolated, or formula-derived;
- expected and actual output paths;
- a final pass/fail summary.

No default command may accidentally launch a multi-hour or out-of-memory target run.

## 15. Mandatory Automated Tests

Tests must be deterministic when given a seed and must avoid writing into source directories.

### 15.1 Parameter and Index Tests

- correct `B = ceil(sqrt(N))`;
- correct identity mapping at first, last, and block-boundary identities;
- reject `id <= 0`, `id > N`, invalid dimensions, and invalid modulus/extractor settings;
- verify PostRBE and PostRBE* dimension constraints.

### 15.2 Setup Tests

- `A_i T_i,j = U_j` for all PostRBE cross-position links;
- `A_i P_i,j = V_j` and `U_j = V_j Q_j` for PostRBE*;
- correct zero initialization;
- no trapdoor in exported public structures.

### 15.3 Registration Tests

- honest registration succeeds;
- duplicate active registration fails;
- tampered `pk` fails;
- tampered `up` fails;
- wrong shape, modulus, instance, or identity fails;
- failed registration leaves state unchanged;
- registrations in multiple positions and blocks update the correct entries only.

### 15.4 Encryption and Decryption Tests

- round trip succeeds for both schemes;
- multiple messages, identities, blocks, and seeds succeed;
- noisy demo uses nonzero errors and passes the stated bound;
- wrong secret key fails;
- wrong opening fails;
- wrong instance or target metadata fails;
- ciphertext tampering fails or is explicitly handled according to the selected symmetric primitive;
- exact algebra and noisy correctness are reported separately.

### 15.5 Verification Tests

- registered identity: membership true, non-membership false;
- unregistered identity: membership false, non-membership true;
- tampered key/proof/state: verification false;
- public verifier does not require the user's secret key.

### 15.6 Revocation Tests

- active user can be revoked once;
- second revocation fails cleanly;
- revoked user's membership becomes false;
- revoked user's non-membership becomes true;
- unaffected users remain valid and decrypt new ciphertexts;
- revoked user fails to decrypt new ciphertexts for the updated state;
- optional re-registration follows the documented policy.

### 15.7 Scaling Tests

- capacity overflow creates a fresh independent instance;
- old registrations and ciphertexts remain bound to the old instance;
- new users operate in the new instance;
- cross-instance objects are rejected.

### 15.8 Arithmetic and Serialization Tests

- safe modular multiplication matches a big-integer reference;
- tests include values near `q - 1` and dimensions large enough to expose overflow;
- serialize/deserialize round trips preserve all structures;
- byte counts match serialized outputs and formulas;
- MB/MiB and bit-packed/byte-aligned units are not mixed.

### 15.9 Acceptance Gate

The artifact is not release-ready unless:

- all mandatory tests pass;
- the smoke test returns a nonzero exit code on any failed assertion;
- both schemes complete all public algorithms;
- noisy correctness is either fully implemented or explicitly blocked from being claimed;
- no manuscript value is regenerated from an unlabeled estimate;
- a clean-machine reproduction has been performed using only the published instructions.

## 16. Required Artifact Documentation

The final code package must contain:

```text
README.md
ARTIFACT_IMPLEMENTATION_SPEC.md
requirements.txt with pinned compatible versions or a lock file
LICENSE or an explicit evaluation-only license statement
source package
tests
smoke-test entry point
functional-demo entry point
paper-accounting entry point
output schema documentation
expected small-demo output
```

The README must include:

- artifact scope and non-production warning;
- directory map;
- exact environment setup;
- hardware/software requirements;
- quick start;
- full experiment commands;
- expected runtime and memory;
- expected outputs and success criteria;
- mapping from commands to paper claims, figures, and tables;
- distinction between direct measurements and estimates;
- troubleshooting and contact route.

## 17. Planned Implementation Layout

The existing compact layout may be retained, but responsibilities should be clear. A target structure is:

```text
postrbe_no_upid_in_keygen_register/
  README.md
  ARTIFACT_IMPLEMENTATION_SPEC.md
  requirements.txt
  postrbe/
    params.py
    types.py
    arithmetic.py
    extraction.py
    symmetric.py
    schemes.py
    verification.py
    benchmark.py
    models.py
    serialization.py
  scripts/
    run_smoke.py
    run_functional.py
    run_accounting.py
    run_benchmarks.py
  tests/
    test_params.py
    test_arithmetic.py
    test_postrbe.py
    test_postrbe_star.py
    test_membership.py
    test_revocation.py
    test_scaling.py
    test_serialization.py
```

File count is not an evaluation criterion. A smaller layout is acceptable if the same separation, functionality, tests, and documentation are present.

## 18. Implementation Order

Code changes should be performed in this order:

1. freeze this specification and record any approved changes;
2. add safe arithmetic and reference tests;
3. resolve the extractor/noisy-correctness contract;
4. formalize types, indexing, parameter validation, and error handling;
5. implement complete Setup and KeyGen for both schemes;
6. implement validated, atomic Register;
7. implement Update, Encrypt, and Decrypt;
8. implement public membership and non-membership verification;
9. implement revocation;
10. implement multi-instance scaling;
11. separate functional, accounting, and benchmark profiles;
12. add serialization and complete automated tests;
13. write README and expected-output documentation;
14. run the complete workflow in a fresh environment;
15. only then prepare the two-page Artifact Appendix and submission text.

## 19. Definition of Complete

The implementation is complete only when an evaluator can start from the README and, without reading the paper's source code or asking the authors for missing commands:

1. install the dependencies;
2. run the smoke test;
3. execute all six algorithms for PostRBE and PostRBE*;
4. verify successful decryption;
5. verify membership and non-membership;
6. observe rejection of invalid registration;
7. revoke a user and verify the updated state;
8. demonstrate creation of a fresh instance beyond capacity;
9. generate paper-scale operation-count and size CSV files;
10. identify exactly which outputs are direct, estimated, extrapolated, formula-derived, or manuscript anchors;
11. map the resulting outputs to the claims selected for Artifact Evaluation.

