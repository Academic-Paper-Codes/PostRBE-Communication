# mpostrbe_star_core.py  (paper-strict MPostRBE*)
from __future__ import annotations
from typing import List, Tuple, Dict, Any
import math
import os
import numpy as np

from mpostrbe_star_structs import MCRSStar, MPublicParamsStar, MAuxParamsStar
from postrbe_utils import (
    mod_q,
    sample_uniform_matrix, sample_short_matrix,
    invert_matrix_mod_q,
    aead_encrypt, aead_decrypt
)
import hashlib

def H_matrix_to_key32(mat, hash_name: str = "sha256") -> bytes:
    """
    Derive 32-byte key from a small numpy matrix/vector deterministically.
    Compatible with "hash_to_key" style but keeps MPostRBE* self-contained.
    """
    if not hasattr(mat, "tobytes"):
        mat = np.array(mat, dtype=np.int64)
    data = mat.astype(np.int64).tobytes()
    h = hashlib.new(hash_name)
    h.update(data)
    return h.digest()  # 32 bytes for sha256


def compute_indices(user_id: int, B: int):
    return user_id // B, user_id % B



# ---------- Setup (paper-aligned dimensions) ----------
def setup_mstar(security_param: int, N_max: int, q: int = 12289, n: int = 4, m: int = 6, t: int = 8):
    """
    Paper-strict dimension system:
      A   ∈ Z_q^{t×m}
      T_i ∈ Z_q^{m×n}
      U_i ∈ Z_q^{t×n} where U_i = A·T_i

    Public:
      C_row ∈ Z_q^{t×n}  (init 0)

    Aux:
      L[row][col] ∈ Z_q^{t×m} (init 0)
    """
    B = int(math.isqrt(N_max))

    A = sample_uniform_matrix(t, m, q)  # (t x m)

    T_list, U_list = [], []
    for j in range(B):
        T_j = sample_short_matrix(m, n, bound=3, q=q)   # (m x n)
        U_j = mod_q(A @ T_j, q)                         # (t x n)
        T_list.append(T_j)
        U_list.append(U_j)

    C_list = [np.zeros((t, n), dtype=np.int64) for _ in range(B)]
    L_mat = [[np.zeros((t, m), dtype=np.int64) for _ in range(B)] for __ in range(B)]

    crs = MCRSStar(N_max=N_max, B=B, q=q, n=n, m=m, t=t, A=A, T_list=T_list, U_list=U_list,
                  hash_name="sha256", se_mode="AEAD")
    pp  = MPublicParamsStar(C_list=C_list)
    aux = MAuxParamsStar(L_mat=L_mat)
    return crs, pp, aux


# ---------- KeyGen (X left-multiplies) ----------
def keygen_mstar(user_id: int, crs: MCRSStar, bound: int = 3) -> Dict[str, Any]:
    """
    Paper-strict KeyGen:
      X ∈ Z_q^{t×t} invertible
      pk = X · U_col   (t×n)
      up = X · A       (t×m)
    """
    q, t = crs.q, crs.t
    _, col = compute_indices(user_id, crs.B)

    while True:
        X = sample_short_matrix(t, t, bound=bound, q=q)
        try:
            X_inv = invert_matrix_mod_q(X, q)
            break
        except ValueError:
            continue

    pk = mod_q(X @ crs.U_list[col], q)  # (t x n)
    up = mod_q(X @ crs.A, q)            # (t x m)

    return {"user_id": user_id, "sk": X, "sk_inv": X_inv, "pk": pk, "up": up}


# -----------------------------
# Setup (same style as PostRBE*)
# -----------------------------
def setup_mstar(N_max=100, B=10, q=12289, n=4, m=6, t=8):
    """
    Use the SAME parameter shapes as PostRBE*:
      A: (n x m)
      T_j: (m x t)
      U_j = A @ T_j: (n x t)
      C_row: (n x t)
      L[row][col]: (m x t)
    """
    A = sample_uniform_matrix(n, m, q)

    T_list, U_list = [], []
    for j in range(B):
        T_j = sample_short_matrix(m, t, bound=3, q=q)   # (m x t)
        U_j = mod_q(A @ T_j, q)                         # (n x t)
        T_list.append(T_j)
        U_list.append(U_j)

    C_list = [np.zeros((n, t), dtype=np.int64) for _ in range(B)]
    L_mat = [[np.zeros((m, t), dtype=np.int64) for _ in range(B)] for _ in range(B)]

    crs = {
        "N_max": N_max, "B": B, "q": q, "n": n, "m": m, "t": t,
        "A": A, "T_list": T_list, "U_list": U_list,
    }
    pp = {"C_list": C_list}
    aux = {"L_mat": L_mat}
    return crs, pp, aux


# -----------------------------
# KeyGen (right-multiply X)
# -----------------------------
def keygen_mstar(user_id: int, crs: Dict[str, Any], bound: int = 3) -> Dict[str, Any]:
    q, t, B = crs["q"], crs["t"], crs["B"]
    _, id_prime = compute_indices(user_id, B)

    # X: (t x t) invertible
    while True:
        X = sample_short_matrix(t, t, bound=bound, q=q)
        try:
            X_inv = invert_matrix_mod_q(X, q)
            break
        except ValueError:
            continue

    # pk = U_{id'} @ X   (n x t)
    U_idp = crs["U_list"][id_prime]
    pk = mod_q(U_idp @ X, q)

    # up vector: for all i != id', up[i] = T_{id'} @ X ; up[id']=0
    up = []
    T_idp = crs["T_list"][id_prime]  # (m x t)
    for i in range(B):
        if i == id_prime:
            up.append(np.zeros((crs["m"], crs["t"]), dtype=np.int64))
        else:
            up.append(mod_q(T_idp @ X, q))  # (m x t)

    return {"user_id": user_id, "sk": X, "sk_inv": X_inv, "pk": pk, "up": up}


# -----------------------------
# Register
# -----------------------------
def register_mstar(user_param: Dict[str, Any], crs: Dict[str, Any], pp: Dict[str, Any], aux: Dict[str, Any]):
    """
    Check:  A @ up[i] == pk   for all i != id'
    Update:
      C[id*] += pk
      L[id*][i] += up[i] for all i != id'
    """
    q, B = crs["q"], crs["B"]
    user_id = user_param["user_id"]
    pk = user_param["pk"]
    up = user_param["up"]

    id_star, id_prime = compute_indices(user_id, B)

    A = crs["A"]
    for i in range(B):
        if i == id_prime:
            continue
        rhs = mod_q(A @ up[i], q)  # (n x m) @ (m x t) = (n x t)
        if not np.array_equal(rhs % q, pk % q):
            raise ValueError(f"[Register] check failed: user {user_id}, i={i}")

    pp["C_list"][id_star] = mod_q(pp["C_list"][id_star] + pk, q)
    for i in range(B):
        if i == id_prime:
            continue
        aux["L_mat"][id_star][i] = mod_q(aux["L_mat"][id_star][i] + up[i], q)

    return pp, aux


def update_mstar(user_id: int, crs: Dict[str, Any], aux: Dict[str, Any]) -> np.ndarray:
    B = crs["B"]
    id_star, id_prime = compute_indices(user_id, B)
    return aux["L_mat"][id_star][id_prime]


# -----------------------------
# Encrypt / Decrypt (group)
# -----------------------------
def encrypt_group_mstar(pp: Dict[str, Any], crs: Dict[str, Any], P: List[int], message: bytes) -> Dict[str, Any]:
    """
    Multi-receiver wrapper:
      - sample S (1 x n)
      - shared c2 = S @ A
      - shared c4 = AEAD(sk_s, M)
      - for each id in P:
          c1_id = S @ C[id*]
          key_id from SU_id = S @ U[id']
          c3_id = AEAD(key_id, sk_s)
    """
    q, n, m, t, B = crs["q"], crs["n"], crs["m"], crs["t"], crs["B"]
    A = crs["A"]

    S = sample_short_matrix(1, n, bound=3, q=q)       # (1 x n)
    c2 = mod_q(S @ A, q)                               # (1 x m)

    # session key + message wrapper
    sk_s = os.urandom(32)
    aad4 = b"MPostRBE*_c4"
    nonce4, c4, tag4 = aead_encrypt(sk_s, message, aad4)

    w = {}
    for rid in P:
        id_star, id_prime = compute_indices(rid, B)

        C_row = pp["C_list"][id_star]                 # (n x t)
        c1 = mod_q(S @ C_row, q)                      # (1 x t)

        U_idp = crs["U_list"][id_prime]               # (n x t)
        SU = mod_q(S @ U_idp, q)                      # (1 x t)

        key_r = H_matrix_to_key32(SU, hash_name="sha256")
        aad_r = b"|".join([b"MPostRBE*_c3", str(rid).encode(), str(P).encode()])
        nonce, c3, tag = aead_encrypt(key_r, sk_s, aad_r)

        w[rid] = {"c1": c1, "nonce": nonce, "c3": c3, "tag": tag}

    return {
        "P": list(P),
        "c2": c2,
        "w": w,
        "c4_pack": {"nonce": nonce4, "c4": c4, "tag": tag4, "aad": aad4},
    }


def decrypt_group_mstar(user_param: Dict[str, Any], crs: Dict[str, Any], aux: Dict[str, Any], ct: Dict[str, Any]) -> bytes:
    """
    For targeted id:
      - get c1_id from w
      - get L = Update(id)
      - recover SU: tmp = c1 - c2 @ L ; SU = tmp @ X_inv
      - key = H(SU)
      - decrypt sk_s from c3_id
      - decrypt message from c4
    """
    user_id = user_param["user_id"]
    X_inv = user_param["sk_inv"]

    P = ct["P"]
    if user_id not in ct["w"]:
        raise ValueError("user_id not in policy P")

    q, B = crs["q"], crs["B"]
    id_star, id_prime = compute_indices(user_id, B)

    c2 = ct["c2"]                     # (1 x m)
    myw = ct["w"][user_id]
    c1 = myw["c1"]                    # (1 x t)

    L = update_mstar(user_id, crs, aux)          # (m x t)

    tmp = mod_q(c1 - mod_q(c2 @ L, q), q)        # (1 x t)
    SU = mod_q(tmp @ X_inv, q)                   # (1 x t)

    key_r = H_matrix_to_key32(SU, hash_name="sha256")
    aad_r = b"|".join([b"MPostRBE*_c3", str(user_id).encode(), str(P).encode()])
    sk_s = aead_decrypt(key_r, myw["nonce"], myw["c3"], myw["tag"], aad_r)

    p4 = ct["c4_pack"]
    return aead_decrypt(sk_s, p4["nonce"], p4["c4"], p4["tag"], p4["aad"])