"""Functional prototype of PostRBE and PostRBE*.

This code follows the algebraic relations used in the paper:

    A_i L_{block,i} + U_i X_id = C_block
    c1 = S A_i + e1, c2 = S U_i + e2
    c2 X_id + c1 L_{block,i} ~= S C_block

For PostRBE* we use U_j = V_j Q_j and A_i P_{i,j} = V_j.

Important: this is a research/benchmark prototype, not a secure implementation.
The setup uses A=[I|0] so preimages can be formed by padding, whereas a real
lattice implementation would need proper trapdoor/preimage sampling and careful
noise/security analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np

from .linalg import (
    Array,
    add_mod,
    high_bits,
    identity_left_matrix,
    kdf,
    matmul_mod,
    mod_q,
    pad_preimage_n_to_m,
    rand_small,
    xor_stream,
    zeros,
)
from .params import RBEParams


@dataclass
class SecretKey:
    id: int
    pos: int
    block: int
    X: Array


@dataclass
class UserParams:
    pk: Array
    up: object | None


@dataclass
class Ciphertext:
    c1: Array
    c2: Array
    c3: bytes
    block: int
    pos: int


def id_to_block_pos(identity: int, B: int) -> Tuple[int, int]:
    """Map 1-based identity to 0-based block and position."""
    if identity <= 0:
        raise ValueError("identity must be 1-based and positive")
    block = (identity - 1) // B
    pos = (identity - 1) % B
    return block, pos


class _BaseScheme:
    name = "abstract"

    def __init__(self, params: RBEParams):
        params.validate()
        self.params = params
        self.rng = np.random.default_rng(params.seed)
        self.B = params.B
        self.q = params.q
        self.A: List[Array] = []
        self.U: List[Array] = []
        self.C: Dict[int, Array] = {}
        self.L: Dict[Tuple[int, int], Array] = {}
        self.registered: Dict[int, UserParams] = {}

    def _ensure_block(self, block: int) -> None:
        if block not in self.C:
            self.C[block] = zeros((self.params.n, self.params.t))
            for pos in range(self.B):
                self.L[(block, pos)] = zeros((self.params.m, self.params.t))

    def setup(self) -> None:
        raise NotImplementedError

    def keygen(self, identity: int) -> Tuple[SecretKey, UserParams]:
        raise NotImplementedError

    def register(self, identity: int, user_params: UserParams) -> None:
        raise NotImplementedError

    def update(self, identity: int) -> Array:
        block, pos = id_to_block_pos(identity, self.B)
        self._ensure_block(block)
        return self.L[(block, pos)]

    def encrypt(self, identity: int, message: bytes) -> Ciphertext:
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        self._ensure_block(block)
        # Unified experiment: S, e1, e2 are short with infinity norm <= sigma_inf.
        S = mod_q(rand_small(self.rng, (1, p.n), p.sigma_inf), p.q)
        e1 = rand_small(self.rng, (1, p.m), p.sigma_inf)
        e2 = rand_small(self.rng, (1, p.t), p.sigma_inf)
        c1 = add_mod(matmul_mod(S, self.A[pos], p.q), e1, p.q)
        c2 = add_mod(matmul_mod(S, self.U[pos], p.q), e2, p.q)
        shared = matmul_mod(S, self.C[block], p.q)
        key = kdf(high_bits(shared, p.q, p.keep_bits))
        c3 = xor_stream(key, message)
        return Ciphertext(c1=c1, c2=c2, c3=c3, block=block, pos=pos)

    def decrypt(self, sk: SecretKey, opening: Array, ct: Ciphertext) -> bytes:
        p = self.params
        left = matmul_mod(ct.c2, sk.X, p.q)
        right = matmul_mod(ct.c1, opening, p.q)
        rec = add_mod(left, right, p.q)
        key = kdf(high_bits(rec, p.q, p.keep_bits))
        return xor_stream(key, ct.c3)

    def membership_verify(self, identity: int, sk: SecretKey, opening: Array) -> bool:
        """Verify A_pos*L + U_pos*X == C_block in this prototype."""
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        lhs = add_mod(matmul_mod(self.A[pos], opening, p.q), matmul_mod(self.U[pos], sk.X, p.q), p.q)
        return bool(np.array_equal(lhs, self.C[block]))

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        """Fill up_id / registration upload data.

        Generate up_id / registration upload data. In the final experiment
        convention, this helper is intentionally called outside KeyGen and
        outside Register timing, so the plotted Register cost measures only
        the curator-side update after receiving (pk, up_id).
        """
        raise NotImplementedError

    def register_with_upload(self, identity: int, sk: SecretKey, user_params: UserParams) -> None:
        if user_params.up is None:
            user_params = self.add_registration_upload(sk, user_params)
        self.register(identity, user_params)

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        """Byte counts using the paper q_bits setting, not NumPy dtype size."""
        p = self.params
        eb = p.element_bytes
        return {
            "pp_C_one_block": p.n * p.t * eb,
            "aux_L_one_opening": p.m * p.t * eb,
            "sk_X": p.t * p.t * eb,
            "ct_c1_only": p.m * eb,
            "ct_c2_only": p.t * eb,
            "ct_c3_message": p.message_bytes,
            "ct_total": (p.m + p.t) * eb + p.message_bytes,
        }


class PostRBE(_BaseScheme):
    name = "PostRBE"

    def setup(self) -> None:
        p = self.params
        self.A = [identity_left_matrix(p.n, p.m) for _ in range(self.B)]
        self.U = [mod_q(rand_small(self.rng, (p.n, p.t), p.sigma_inf), p.q) for _ in range(self.B)]

    def _T(self, i: int, j: int) -> Array:
        # Prototype preimage satisfying A_i T_{i,j}=U_j.
        return pad_preimage_n_to_m(self.U[j], self.params.m)

    def _upload_from_secret(self, pos: int, X: Array) -> List[Array | None]:
        # Only cross-position components are needed. The same-position
        # component is deliberately not generated or uploaded.
        up: List[Array | None] = [None for _ in range(self.B)]
        for i in range(self.B):
            if i == pos:
                continue
            up[i] = matmul_mod(self._T(i, pos), X, self.params.q)
        return up

    def keygen(self, identity: int, include_upload: bool = True) -> Tuple[SecretKey, UserParams]:
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        X = mod_q(rand_small(self.rng, (p.t, p.t), p.sigma_inf), p.q)
        pk = matmul_mod(self.U[pos], X, p.q)
        # Revised convention: KeyGen may exclude up_id.
        up = self._upload_from_secret(pos, X) if include_upload else None
        return SecretKey(identity, pos, block, X), UserParams(pk=pk, up=up)

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        return UserParams(pk=user_params.pk, up=self._upload_from_secret(sk.pos, sk.X))

    def register(self, identity: int, user_params: UserParams) -> None:
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        self._ensure_block(block)
        self.C[block] = add_mod(self.C[block], user_params.pk, p.q)
        if user_params.up is None:
            raise ValueError("registration upload up_id is missing")
        for i in range(self.B):
            if i == pos:
                continue
            self.L[(block, i)] = add_mod(self.L[(block, i)], user_params.up[i], p.q)
        self.registered[identity] = user_params

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        p = self.params
        eb = p.element_bytes
        base = super().estimated_sizes_bytes(registered_users_in_memory)
        base.update(
            {
                "upid": (p.n * p.t + (self.B - 1) * p.m * p.t) * eb,
                "crs_A_U_virtual": self.B * (p.n * p.m + p.n * p.t) * eb,
            }
        )
        return base


class PostRBEStar(_BaseScheme):
    name = "PostRBE*"

    def __init__(self, params: RBEParams):
        super().__init__(params)
        self.V: List[Array] = []
        self.Q: List[Array] = []

    def setup(self) -> None:
        p = self.params
        self.A = [identity_left_matrix(p.n, p.m) for _ in range(self.B)]
        self.V = [mod_q(rand_small(self.rng, (p.n, p.r), p.sigma_inf), p.q) for _ in range(self.B)]
        self.Q = [mod_q(rand_small(self.rng, (p.r, p.t), p.sigma_inf), p.q) for _ in range(self.B)]
        self.U = [matmul_mod(self.V[j], self.Q[j], p.q) for j in range(self.B)]

    def _P(self, i: int, j: int) -> Array:
        # Prototype linking matrix satisfying A_i P_{i,j}=V_j.
        return pad_preimage_n_to_m(self.V[j], self.params.m)

    def _upload_from_secret(self, pos: int, X: Array) -> Array:
        # In PostRBE* the registration upload is only Q_pos X.
        return matmul_mod(self.Q[pos], X, self.params.q)

    def keygen(self, identity: int, include_upload: bool = True) -> Tuple[SecretKey, UserParams]:
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        X = mod_q(rand_small(self.rng, (p.t, p.t), p.sigma_inf), p.q)
        pk = matmul_mod(self.U[pos], X, p.q)
        # Revised convention: KeyGen may exclude up_id.
        up = self._upload_from_secret(pos, X) if include_upload else None
        return SecretKey(identity, pos, block, X), UserParams(pk=pk, up=up)

    def add_registration_upload(self, sk: SecretKey, user_params: UserParams) -> UserParams:
        return UserParams(pk=user_params.pk, up=self._upload_from_secret(sk.pos, sk.X))

    def register(self, identity: int, user_params: UserParams) -> None:
        p = self.params
        block, pos = id_to_block_pos(identity, self.B)
        self._ensure_block(block)
        self.C[block] = add_mod(self.C[block], user_params.pk, p.q)
        if user_params.up is None:
            raise ValueError("registration upload up_id is missing")
        for i in range(self.B):
            if i == pos:
                continue
            contribution = matmul_mod(self._P(i, pos), user_params.up, p.q)
            self.L[(block, i)] = add_mod(self.L[(block, i)], contribution, p.q)
        self.registered[identity] = user_params

    def estimated_sizes_bytes(self, registered_users_in_memory: int = 1) -> Dict[str, int]:
        p = self.params
        eb = p.element_bytes
        base = super().estimated_sizes_bytes(registered_users_in_memory)
        base.update(
            {
                "upid": (p.n * p.t + p.r * p.t) * eb,
                "crs_A_V_Q_virtual": self.B * (p.n * p.m + p.n * p.r + p.r * p.t) * eb,
            }
        )
        return base
