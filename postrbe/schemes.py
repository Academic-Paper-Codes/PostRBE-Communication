"""Complete executable PostRBE and PostRBE* functional prototypes.

The implementation follows the paper's six algorithms and public verification
relations.  It is an evaluation artifact, not production cryptography: setup
uses the explicitly labelled ``A=[I|0]`` functional backend instead of a real
lattice trapdoor sampler.  All correctness-sensitive arithmetic uses Python
arbitrary-precision intermediates.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Tuple

import numpy as np

from .arithmetic import (
    Array,
    add_mod,
    canonical_mod,
    centered,
    identity_left_matrix,
    infinity_norm,
    matmul_mod,
    matrix_equal_mod,
    pad_preimage_n_to_m,
    rand_small,
    sub_mod,
    zeros,
)
from .extraction import prepare_reconciliation, reconcile
from .params import RBEParams
from .symmetric import decrypt_aes_gcm, derive_key, encrypt_aes_gcm
from .types import (
    Ciphertext,
    CorrectnessAudit,
    DecryptionError,
    OpeningProof,
    RegistrationError,
    RegistrationRecord,
    SecretKey,
    SetupRequiredError,
    StateReceipt,
    UserParams,
)


def id_to_block_pos(identity: int, B: int, N: int | None = None) -> Tuple[int, int]:
    """Map an external 1-based identity to internal 0-based coordinates."""
    if isinstance(identity, bool) or not isinstance(identity, int):
        raise TypeError("identity must be an integer")
    if identity <= 0 or (N is not None and identity > N):
        upper = f", {N}" if N is not None else ""
        raise ValueError(f"identity must be in [1{upper}], got {identity}")
    zero_based = identity - 1
    return zero_based // B, zero_based % B


def _copy_matrix(value: Array) -> Array:
    return np.asarray(value, dtype=np.int64).copy()


def _copy_upload(value: Any) -> Any:
    if isinstance(value, list):
        return [None if item is None else _copy_matrix(item) for item in value]
    return _copy_matrix(value)


class _BaseScheme:
    name = "abstract"
    scheme_parameter_name = ""

    def __init__(self, params: RBEParams, *, instance_id: str | None = None):
        params.validate(self.scheme_parameter_name)
        self.params = params
        self.rng = np.random.default_rng(params.seed)
        self.B = params.B
        self.q = params.q
        self.instance_id = instance_id or f"{self.name.lower().replace('*', 'star')}-{uuid.uuid4().hex}"
        self.backend = "functional_identity_trapdoor"
        self.A: List[Array] = []
        self.U: List[Array] = []
        self.C: Dict[int, Array] = {}
        self.L: Dict[Tuple[int, int], Array] = {}
        self.registered: Dict[int, RegistrationRecord] = {}
        self.state_version = 0
        self._setup_done = False

    def _matmul(self, a: Array, b: Array) -> Array:
        return matmul_mod(a, b, self.q, self.params.arithmetic_backend)

    def _identity(self, identity: int) -> Tuple[int, int]:
        self.params.validate_identity(identity)
        return id_to_block_pos(identity, self.B, self.params.N)

    def _require_setup(self) -> None:
        if not self._setup_done:
            raise SetupRequiredError("run setup() before this operation")

    def _initialize_state(self) -> None:
        p = self.params
        self.C = {block: zeros((p.n, int(p.t))) for block in range(p.block_count)}
        self.L = {
            (block, pos): zeros((p.m, int(p.t)))
            for block in range(p.block_count)
            for pos in range(self.B)
        }
        self.registered.clear()
        self.state_version = 0

    def setup(self) -> dict[str, Any]:
        raise NotImplementedError

    def setup_self_check(self) -> bool:
        raise NotImplementedError

    def keygen(self, identity: int, include_upload: bool = True) -> Tuple[SecretKey, UserParams]:
        raise NotImplementedError

    def keygen_full(self, identity: int) -> tuple[SecretKey, Array, Any]:
        """Paper-shaped KeyGen output: ``(sk_id, pk_id, up_id)``."""
        sk, user = self.keygen(identity, include_upload=True)
        return sk, _copy_matrix(user.pk), _copy_upload(user.up)

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        raise NotImplementedError

    def _validate_external_matrix(self, value: Any, shape: tuple[int, int], label: str) -> Array:
        array = np.asarray(value)
        if array.shape != shape:
            raise RegistrationError(f"{label} has shape {array.shape}, expected {shape}")
        if array.dtype.kind not in "iuO":
            raise RegistrationError(f"{label} must contain integers")
        canonical = canonical_mod(array, self.q)
        if not np.array_equal(array.astype(object), canonical.astype(object)):
            raise RegistrationError(f"{label} entries must be canonical residues in [0,q)")
        return canonical

    def _validate_user_params(self, identity: int, user_params: UserParams) -> tuple[int, int, Array]:
        self._require_setup()
        block, position = self._identity(identity)
        if identity in self.registered:
            raise RegistrationError(f"identity {identity} is already actively registered")
        if user_params.scheme != self.name:
            raise RegistrationError("registration scheme mismatch")
        if user_params.instance_id != self.instance_id:
            raise RegistrationError("registration instance mismatch")
        if user_params.identity != identity:
            raise RegistrationError("registration identity mismatch")
        pk = self._validate_external_matrix(user_params.pk, (self.params.n, int(self.params.t)), "pk")
        if user_params.up is None:
            raise RegistrationError("registration upload is missing")
        return block, position, pk

    def _registration_contributions(self, position: int, user_params: UserParams, pk: Array) -> Dict[int, Array]:
        raise NotImplementedError

    def register(self, identity: int, user_params: UserParams) -> StateReceipt:
        """Validate first, then atomically commit public and auxiliary updates."""
        block, position, pk = self._validate_user_params(identity, user_params)
        contributions = self._registration_contributions(position, user_params, pk)

        # Compute every new value before mutating live state.
        new_c = add_mod(self.C[block], pk, self.q)
        new_l = {
            pos: add_mod(self.L[(block, pos)], contribution, self.q)
            for pos, contribution in contributions.items()
        }
        stored_up = _copy_upload(user_params.up)
        old_version = self.state_version
        new_version = old_version + 1
        record = RegistrationRecord(
            scheme=self.name,
            instance_id=self.instance_id,
            identity=identity,
            block=block,
            position=position,
            pk=_copy_matrix(pk),
            up=stored_up,
            registered_version=new_version,
        )

        self.C[block] = new_c
        for pos, value in new_l.items():
            self.L[(block, pos)] = value
        self.registered[identity] = record
        self.state_version = new_version
        return StateReceipt("register", self.name, self.instance_id, identity, old_version, new_version)

    def register_with_upload(self, identity: int, sk: SecretKey, user_params: UserParams) -> StateReceipt:
        complete = user_params if user_params.up is not None else self.add_registration_upload(sk, user_params)
        return self.register(identity, complete)

    def update(self, identity: int) -> OpeningProof:
        self._require_setup()
        block, position = self._identity(identity)
        return OpeningProof(
            self.name,
            self.instance_id,
            identity,
            block,
            position,
            self.state_version,
            _copy_matrix(self.L[(block, position)]),
        )

    def _validate_proof_metadata(self, identity: int, proof: OpeningProof, *, current: bool) -> tuple[int, int]:
        block, position = self._identity(identity)
        if proof.scheme != self.name or proof.instance_id != self.instance_id:
            raise ValueError("proof scheme or instance mismatch")
        if (proof.identity, proof.block, proof.position) != (identity, block, position):
            raise ValueError("proof identity metadata mismatch")
        if current and proof.state_version != self.state_version:
            raise ValueError("stale proof")
        if np.asarray(proof.opening).shape != (self.params.m, int(self.params.t)):
            raise ValueError("proof opening shape mismatch")
        return block, position

    def verify_membership(self, identity: int, public_key: Array, proof: OpeningProof) -> bool:
        """Public verification: C = A*pi + pk. No secret key is required."""
        try:
            self._require_setup()
            block, position = self._validate_proof_metadata(identity, proof, current=True)
            pk = np.asarray(public_key)
            if pk.shape != (self.params.n, int(self.params.t)):
                return False
            lhs = add_mod(self._matmul(self.A[position], proof.opening), canonical_mod(pk, self.q), self.q)
            return matrix_equal_mod(lhs, self.C[block], self.q)
        except (TypeError, ValueError, SetupRequiredError):
            return False

    def verify_nonmembership(self, identity: int, proof: OpeningProof) -> bool:
        """Public verification: C = A*pi."""
        try:
            self._require_setup()
            block, position = self._validate_proof_metadata(identity, proof, current=True)
            lhs = self._matmul(self.A[position], proof.opening)
            return matrix_equal_mod(lhs, self.C[block], self.q)
        except (TypeError, ValueError, SetupRequiredError):
            return False

    # Backward-compatible name, now intentionally takes a public key rather than a secret key.
    def membership_verify(self, identity: int, public_key: Array, proof: OpeningProof) -> bool:
        return self.verify_membership(identity, public_key, proof)

    def nonmembership_verify(self, identity: int, proof: OpeningProof) -> bool:
        return self.verify_nonmembership(identity, proof)

    def _ciphertext_aad(
        self,
        identity: int,
        block: int,
        position: int,
        version: int,
        c1: Array,
        c2: Array,
        hint: Array,
    ) -> bytes:
        digest = hashlib.sha256()
        for matrix in (c1, c2, hint):
            array = np.asarray(matrix, dtype="<i8")
            digest.update(str(array.shape).encode("ascii"))
            digest.update(array.tobytes(order="C"))
        metadata = f"PostRBE-ct-v1|{self.name}|{self.instance_id}|{identity}|{block}|{position}|{version}|".encode()
        return metadata + digest.digest()

    def encrypt(self, identity: int, message: bytes) -> Ciphertext:
        self._require_setup()
        block, position = self._identity(identity)
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        if len(message) != self.params.message_bytes:
            raise ValueError(f"message must be exactly {self.params.message_bytes} bytes")
        p = self.params
        S = canonical_mod(rand_small(self.rng, (1, p.n), p.sigma_inf, nonzero=True), p.q)
        e1 = rand_small(self.rng, (1, p.m), p.sigma_inf, nonzero=True)
        e2 = rand_small(self.rng, (1, int(p.t)), p.sigma_inf, nonzero=True)
        c1 = add_mod(self._matmul(S, self.A[position]), e1, p.q)
        c2 = add_mod(self._matmul(S, self.U[position]), e2, p.q)
        shared = self._matmul(S, self.C[block])
        prepared = prepare_reconciliation(shared, p.q, p.keep_bits)
        key = derive_key(prepared.extracted)
        nonce = self.rng.integers(0, 256, size=12, dtype=np.uint8).tobytes()
        aad = self._ciphertext_aad(identity, block, position, self.state_version, c1, c2, prepared.hint)
        c3 = encrypt_aes_gcm(key, nonce, message, aad)
        return Ciphertext(
            self.name,
            self.instance_id,
            identity,
            block,
            position,
            self.state_version,
            c1,
            c2,
            prepared.hint,
            nonce,
            c3,
            _audit_shared=_copy_matrix(shared),
        )

    def _validate_decryption_inputs(self, sk: SecretKey, proof: OpeningProof, ct: Ciphertext) -> None:
        if sk.scheme != self.name or sk.instance_id != self.instance_id:
            raise DecryptionError("secret-key scheme or instance mismatch")
        if ct.scheme != self.name or ct.instance_id != self.instance_id:
            raise DecryptionError("ciphertext scheme or instance mismatch")
        if sk.identity != ct.identity:
            raise DecryptionError("secret key is for a different identity")
        try:
            self._validate_proof_metadata(ct.identity, proof, current=False)
        except ValueError as exc:
            raise DecryptionError(str(exc)) from exc
        if proof.state_version != ct.state_version:
            raise DecryptionError("proof and ciphertext state versions differ")
        if (ct.block, ct.position) != (sk.block, sk.position):
            raise DecryptionError("ciphertext target metadata mismatch")
        p = self.params
        expected = {
            "X": (int(p.t), int(p.t)),
            "c1": (1, p.m),
            "c2": (1, int(p.t)),
            "hint": (1, int(p.t)),
        }
        actual = {
            "X": np.asarray(sk.X).shape,
            "c1": np.asarray(ct.c1).shape,
            "c2": np.asarray(ct.c2).shape,
            "hint": np.asarray(ct.reconciliation_hint).shape,
        }
        for label, shape in expected.items():
            if actual[label] != shape:
                raise DecryptionError(f"{label} has shape {actual[label]}, expected {shape}")
        # For a ciphertext under the live state, enforce the same public
        # membership relation used by the paper's verifiability layer. This
        # makes revocation deterministic even in the deliberately tiny
        # functional backend, where a wrong reconstruction can otherwise land
        # in the same wide reconciliation bin by chance. Historical matching
        # (ciphertext, proof) versions remain decryptable after later updates.
        if ct.state_version == self.state_version:
            derived_pk = self._matmul(self.U[sk.position], sk.X)
            if not self.verify_membership(ct.identity, derived_pk, proof):
                raise DecryptionError("secret key is not a member of the ciphertext's current state")

    def reconstruct(self, sk: SecretKey, proof: OpeningProof, ct: Ciphertext) -> Array:
        self._validate_decryption_inputs(sk, proof, ct)
        left = self._matmul(ct.c2, sk.X)
        right = self._matmul(ct.c1, proof.opening)
        return add_mod(left, right, self.q)

    def decrypt(self, sk: SecretKey, proof: OpeningProof, ct: Ciphertext) -> bytes:
        reconstructed = self.reconstruct(sk, proof, ct)
        extracted = reconcile(reconstructed, ct.reconciliation_hint, self.q, self.params.keep_bits)
        key = derive_key(extracted)
        aad = self._ciphertext_aad(
            ct.identity,
            ct.block,
            ct.position,
            ct.state_version,
            ct.c1,
            ct.c2,
            ct.reconciliation_hint,
        )
        try:
            return decrypt_aes_gcm(key, ct.nonce, ct.c3, aad)
        except Exception as exc:
            raise DecryptionError("authentication failed or reconstruction key is incorrect") from exc

    def correctness_audit(self, sk: SecretKey, proof: OpeningProof, ct: Ciphertext) -> CorrectnessAudit:
        if ct._audit_shared is None:
            raise ValueError("audit data is not present in this deserialized ciphertext")
        reconstructed = self.reconstruct(sk, proof, ct)
        noise = centered(sub_mod(reconstructed, ct._audit_shared, self.q), self.q)
        norm = infinity_norm(noise)
        threshold = self.params.extraction_threshold
        expected = prepare_reconciliation(ct._audit_shared, self.q, self.params.keep_bits).extracted
        actual = reconcile(reconstructed, ct.reconciliation_hint, self.q, self.params.keep_bits)
        return CorrectnessAudit(norm, threshold, norm < threshold, expected == actual)

    def revoke(self, identity: int) -> StateReceipt:
        self._require_setup()
        self._identity(identity)
        record = self.registered.get(identity)
        if record is None:
            raise RegistrationError(f"identity {identity} is not actively registered")
        user = UserParams(record.scheme, record.instance_id, record.identity, record.pk, record.up)
        contributions = self._registration_contributions(record.position, user, record.pk)
        new_c = sub_mod(self.C[record.block], record.pk, self.q)
        new_l = {
            pos: sub_mod(self.L[(record.block, pos)], contribution, self.q)
            for pos, contribution in contributions.items()
        }
        old_version = self.state_version
        new_version = old_version + 1
        self.C[record.block] = new_c
        for pos, value in new_l.items():
            self.L[(record.block, pos)] = value
        del self.registered[identity]
        self.state_version = new_version
        return StateReceipt("revoke", self.name, self.instance_id, identity, old_version, new_version)

    def state_digest(self) -> str:
        """Deterministic digest used to assert atomic failure behavior."""
        digest = hashlib.sha256()
        digest.update(str(self.state_version).encode())
        for block in sorted(self.C):
            digest.update(np.asarray(self.C[block], dtype="<i8").tobytes())
        for key in sorted(self.L):
            digest.update(np.asarray(self.L[key], dtype="<i8").tobytes())
        digest.update(",".join(map(str, sorted(self.registered))).encode())
        return digest.hexdigest()

    def public_state(self) -> dict[str, Any]:
        """Export common public material; setup trapdoors are deliberately absent."""
        self._require_setup()
        return {
            "format": "postrbe-public-state-v1",
            "scheme": self.name,
            "instance_id": self.instance_id,
            "state_version": self.state_version,
            "backend": self.backend,
            "A": [_copy_matrix(x) for x in self.A],
            "U": [_copy_matrix(x) for x in self.U],
            "C": {k: _copy_matrix(v) for k, v in self.C.items()},
        }

    def auxiliary_state(self) -> dict[str, Any]:
        self._require_setup()
        return {
            "format": "postrbe-auxiliary-state-v1",
            "scheme": self.name,
            "instance_id": self.instance_id,
            "state_version": self.state_version,
            "L": {key: _copy_matrix(value) for key, value in self.L.items()},
        }

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        p = self.params
        eb = p.element_bytes
        paper_ct = (p.m + int(p.t)) * eb + p.message_bytes
        return {
            "pp_C_one_block": p.n * int(p.t) * eb,
            "aux_L_one_opening": p.m * int(p.t) * eb,
            "sk_X": int(p.t) * int(p.t) * eb,
            "ct_c1_only": p.m * eb,
            "ct_c2_only": int(p.t) * eb,
            "ct_c3_message": p.message_bytes,
            "ct_total": paper_ct,
            "ct_total_paper_formula": paper_ct,
            "functional_reconciliation_hint": int(p.t) * p.runtime_element_bytes,
            "functional_aes_gcm_nonce_and_tag": 12 + 16,
        }


class PostRBE(_BaseScheme):
    name = "PostRBE"
    scheme_parameter_name = "postrbe"

    def __init__(self, params: RBEParams, *, instance_id: str | None = None):
        super().__init__(params, instance_id=instance_id)
        self.T: Dict[Tuple[int, int], Array] = {}

    def setup(self) -> dict[str, Any]:
        p = self.params
        self.A = [identity_left_matrix(p.n, p.m) for _ in range(self.B)]
        self.U = [canonical_mod(rand_small(self.rng, (p.n, int(p.t)), p.sigma_inf, nonzero=True), p.q) for _ in range(self.B)]
        self.T = {
            (i, j): pad_preimage_n_to_m(self.U[j], p.m)
            for i in range(self.B)
            for j in range(self.B)
            if i != j
        }
        self._initialize_state()
        self._setup_done = True
        if not self.setup_self_check():
            raise RuntimeError("PostRBE setup linking-equation self-check failed")
        return {"backend": self.backend, "link_equations_checked": len(self.T), "trapdoor_exported": False}

    def setup_self_check(self) -> bool:
        if not self._setup_done:
            return False
        return all(matrix_equal_mod(self._matmul(self.A[i], value), self.U[j], self.q) for (i, j), value in self.T.items())

    def public_state(self) -> dict[str, Any]:
        state = super().public_state()
        state["T"] = {key: _copy_matrix(value) for key, value in self.T.items()}
        return state

    def _upload_from_secret(self, position: int, X: Array) -> List[Array | None]:
        return [None if i == position else self._matmul(self.T[(i, position)], X) for i in range(self.B)]

    def keygen(self, identity: int, include_upload: bool = True) -> Tuple[SecretKey, UserParams]:
        self._require_setup()
        block, position = self._identity(identity)
        p = self.params
        X = canonical_mod(rand_small(self.rng, (int(p.t), int(p.t)), p.sigma_inf, nonzero=True), p.q)
        pk = self._matmul(self.U[position], X)
        up = self._upload_from_secret(position, X) if include_upload else None
        sk = SecretKey(self.name, self.instance_id, identity, block, position, X)
        return sk, UserParams(self.name, self.instance_id, identity, pk, up)

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        if sk.scheme != self.name or sk.instance_id != self.instance_id or sk.identity != user_params.identity:
            raise RegistrationError("secret key and user parameters do not match this instance")
        return UserParams(self.name, self.instance_id, sk.identity, _copy_matrix(user_params.pk), self._upload_from_secret(sk.position, sk.X))

    def _registration_contributions(self, position: int, user_params: UserParams, pk: Array) -> Dict[int, Array]:
        p = self.params
        honest_bound = int(p.t) * p.sigma_inf * p.sigma_inf
        if infinity_norm(pk, self.q) > honest_bound:
            raise RegistrationError("PostRBE public key exceeds the configured honest-generation bound")
        if not isinstance(user_params.up, (list, tuple)) or len(user_params.up) != self.B:
            raise RegistrationError(f"PostRBE upload must contain {self.B} position entries")
        if user_params.up[position] is not None:
            raise RegistrationError("self-position PostRBE upload must be absent")
        contributions: Dict[int, Array] = {}
        for i in range(self.B):
            if i == position:
                continue
            upload = self._validate_external_matrix(user_params.up[i], (p.m, int(p.t)), f"up[{i}]")
            if infinity_norm(upload, self.q) > honest_bound:
                raise RegistrationError(f"PostRBE upload at position {i} exceeds the configured shortness bound")
            if not matrix_equal_mod(self._matmul(self.A[i], upload), pk, self.q):
                raise RegistrationError(f"PostRBE upload verification failed at position {i}")
            contributions[i] = upload
        return contributions

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        p = self.params
        base = super().estimated_sizes_bytes(registered_users_in_memory)
        base.update({
            "upid": (p.n * int(p.t) + (self.B - 1) * p.m * int(p.t)) * p.element_bytes,
            "crs_A_U_T_virtual": (
                self.B * (p.n * p.m + p.n * int(p.t))
                + self.B * (self.B - 1) * p.m * int(p.t)
            ) * p.element_bytes,
        })
        return base


class PostRBEStar(_BaseScheme):
    name = "PostRBE*"
    scheme_parameter_name = "star"

    def __init__(self, params: RBEParams, *, instance_id: str | None = None):
        super().__init__(params, instance_id=instance_id)
        self.V: List[Array] = []
        self.Q: List[Array] = []
        self.P: Dict[Tuple[int, int], Array] = {}

    def setup(self) -> dict[str, Any]:
        p = self.params
        self.A = [identity_left_matrix(p.n, p.m) for _ in range(self.B)]
        self.V = [canonical_mod(rand_small(self.rng, (p.n, p.r), p.sigma_inf, nonzero=True), p.q) for _ in range(self.B)]
        self.Q = [canonical_mod(rand_small(self.rng, (p.r, int(p.t)), p.sigma_inf, nonzero=True), p.q) for _ in range(self.B)]
        self.U = [self._matmul(self.V[j], self.Q[j]) for j in range(self.B)]
        self.P = {
            (i, j): pad_preimage_n_to_m(self.V[j], p.m)
            for i in range(self.B)
            for j in range(self.B)
            if i != j
        }
        self._initialize_state()
        self._setup_done = True
        if not self.setup_self_check():
            raise RuntimeError("PostRBE* setup linking-equation self-check failed")
        return {"backend": self.backend, "link_equations_checked": len(self.P), "trapdoor_exported": False}

    def setup_self_check(self) -> bool:
        if not self._setup_done:
            return False
        decomposition_ok = all(matrix_equal_mod(self._matmul(self.V[j], self.Q[j]), self.U[j], self.q) for j in range(self.B))
        linking_ok = all(matrix_equal_mod(self._matmul(self.A[i], value), self.V[j], self.q) for (i, j), value in self.P.items())
        return decomposition_ok and linking_ok

    def public_state(self) -> dict[str, Any]:
        state = super().public_state()
        state.update({
            "V": [_copy_matrix(value) for value in self.V],
            "Q": [_copy_matrix(value) for value in self.Q],
            "P": {key: _copy_matrix(value) for key, value in self.P.items()},
        })
        return state

    def _upload_from_secret(self, position: int, X: Array) -> Array:
        return self._matmul(self.Q[position], X)

    def keygen(self, identity: int, include_upload: bool = True) -> Tuple[SecretKey, UserParams]:
        self._require_setup()
        block, position = self._identity(identity)
        p = self.params
        X = canonical_mod(rand_small(self.rng, (int(p.t), int(p.t)), p.sigma_inf, nonzero=True), p.q)
        pk = self._matmul(self.U[position], X)
        up = self._upload_from_secret(position, X) if include_upload else None
        sk = SecretKey(self.name, self.instance_id, identity, block, position, X)
        return sk, UserParams(self.name, self.instance_id, identity, pk, up)

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        if sk.scheme != self.name or sk.instance_id != self.instance_id or sk.identity != user_params.identity:
            raise RegistrationError("secret key and user parameters do not match this instance")
        return UserParams(self.name, self.instance_id, sk.identity, _copy_matrix(user_params.pk), self._upload_from_secret(sk.position, sk.X))

    def _registration_contributions(self, position: int, user_params: UserParams, pk: Array) -> Dict[int, Array]:
        p = self.params
        upload = self._validate_external_matrix(user_params.up, (p.r, int(p.t)), "up")
        upload_bound = int(p.t) * p.sigma_inf * p.sigma_inf
        pk_bound = p.r * upload_bound * p.sigma_inf
        if infinity_norm(upload, self.q) > upload_bound:
            raise RegistrationError("PostRBE* upload exceeds the configured shortness bound")
        if infinity_norm(pk, self.q) > pk_bound:
            raise RegistrationError("PostRBE* public key exceeds the configured honest-generation bound")
        if not matrix_equal_mod(self._matmul(self.V[position], upload), pk, self.q):
            raise RegistrationError("PostRBE* upload verification failed")
        return {i: self._matmul(self.P[(i, position)], upload) for i in range(self.B) if i != position}

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        p = self.params
        base = super().estimated_sizes_bytes(registered_users_in_memory)
        base.update({
            "upid": (p.n * int(p.t) + p.r * int(p.t)) * p.element_bytes,
            "crs_A_V_Q_P_virtual": (
                self.B * (p.n * p.m + p.n * p.r + p.r * int(p.t))
                + self.B * (self.B - 1) * p.m * p.r
            ) * p.element_bytes,
        })
        return base
