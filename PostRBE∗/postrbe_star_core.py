# postrbe_star_core.py
"""
PostRBE* (star) — compressed-CRS toy implementation on top of our LWE-style matrices.
Key differences vs. base PostRBE prototype:
  - CRS stores a *single* global A and per-column T_j; we do not keep A_i or T_{i,j}.
  - Encrypt uses c2 = S @ A (no per-id A_i); all other equations stay the same.
  - AEAD (AES-GCM) is mandatory (no XOR). We bind (user_id, c1, c2) via AAD.
This keeps shapes identical to the base prototype while reflecting the “star” idea of
collapsing many A_i’s into one A and sharing T_j across rows.
"""
from typing import Tuple, Dict, Any
import math
import numpy as np

from postrbe_star_structs import CRSStar, PublicParamsStar, AuxParamsStar
from postrbe_utils import (
    sample_uniform_matrix,
    sample_short_matrix,
    mod_q,
    invert_matrix_mod_q,
    hash_to_key,
    vector_to_bytes,
    aead_encrypt,
    aead_decrypt,
)

# ---------- index helpers ----------
def compute_indices(user_id: int, B: int) -> Tuple[int, int]:
    id_prime = user_id % B      # column index (0-based)
    id_star  = user_id // B     # row index (0-based)
    return id_star, id_prime



# ---------- Setup* ----------
def setup_star(security_param: int, N_max: int, q: int = 12289, n: int = 4, m: int = 6, t: int = 8):
    """
    PostRBE* Setup (paper, Fig.4):
      - A   ∈ Z_q^{t×m}
      - T_i ∈ Z_q^{m×n}
      - U_i ∈ Z_q^{t×n} where A·T_i = U_i
      - pp:  C_i = 0_{t×n}
      - aux: L_{i,j} = 0_{t×m}
    """
    B = int(math.isqrt(N_max))
    
    t_required = m + n
    if t is not None and t != t_required:
        raise ValueError(f"Scheme2(PostRBE*): require t=m+n={t_required}, but got t={t}")
    t = t_required
    # 1) single global A  (t x m)
    A = sample_uniform_matrix(t, m, q)

    # 2) per-index short T_i (m x n) and U_i = A @ T_i (t x n)
    T_list, U_list = [], []
    for j in range(B):
        T_j = sample_short_matrix(m, n, bound=3, q=q)   # (m x n)
        U_j = mod_q(A @ T_j, q)                         # (t x n)
        T_list.append(T_j)
        U_list.append(U_j)

    # 3) public params C_i = 0  (t x n)
    C_list = [np.zeros((t, n), dtype=np.int64) for _ in range(B)]

    # 4) aux L_{i,j} = 0  (t x m)
    L_mat = []
    for i in range(B):
        row = []
        for j in range(B):
            row.append(np.zeros((t, m), dtype=np.int64))
        L_mat.append(row)

    crs = CRSStar(N_max=N_max, B=B, q=q, n=n, m=m, t=t,
                 A=A, T_list=T_list, U_list=U_list,
                 hash_name="sha256", se_mode="AEAD")
    pp  = PublicParamsStar(C_list=C_list)
    aux = AuxParamsStar(L_mat=L_mat)
    return crs, pp, aux


# ---------- KeyGen* ----------
def keygen_star(user_id: int, crs: CRSStar, bound: int = 3):
    """
    KeyGen(id) (paper, Fig.4 / text):
      - sample invertible short X (t x t)
      - pk = X · U_{id'}    (t x n)
      - up = X · A          (t x m)
    """
    q, t, B = crs.q, crs.t, crs.B
    id_star, id_prime = compute_indices(user_id, B)

    while True:
        X = sample_short_matrix(t, t, bound=bound, q=q)
        try:
            X_inv = invert_matrix_mod_q(X, q)
            break
        except ValueError:
            continue

    U_idp = crs.U_list[id_prime]      # (t x n)
    pk = mod_q(X @ U_idp, q)          # (t x n)

    up = mod_q(X @ crs.A, q)          # (t x m)

    return {"user_id": user_id, "sk": X, "sk_inv": X_inv, "pk": pk, "up": up}


# ---------- Register* ----------
def register_star(user_param, crs: CRSStar, pp: PublicParamsStar, aux: AuxParamsStar):
    """
    Register(id, pk, up) (paper, Fig.4 / text):
      - check:  pk == up · T_{id'}   (since up=XA and U_{id'}=AT_{id'})
      - update: C_{id*} += pk, and  L_{id*,i} += up  for all i != id'
    """
    q, B = crs.q, crs.B
    user_id = user_param["user_id"]
    pk      = user_param["pk"]
    up      = user_param["up"]

    id_star, id_prime = compute_indices(user_id, B)

    rhs = mod_q(up @ crs.T_list[id_prime], q)  # (t x m) @ (m x n) = (t x n)
    if not np.array_equal(rhs % q, pk % q):
        raise ValueError(f"Registration check failed for user {user_id}: pk != up·T_id_prime")

    pp.C_list[id_star] = mod_q(pp.C_list[id_star] + pk, q)
    for i in range(B):
        if i == id_prime:
            continue
        aux.L_mat[id_star][i] = mod_q(aux.L_mat[id_star][i] + up, q)

    return pp, aux



# ---------- Update* ----------
def update_star(user_id: int, crs: CRSStar, aux: AuxParamsStar) -> np.ndarray:
    B = crs.B
    id_star, id_prime = compute_indices(user_id, B)
    return aux.L_mat[id_star][id_prime]


# ---------- Encrypt* ----------
def encrypt_star(pp: PublicParamsStar, crs: CRSStar, user_id: int, message: bytes):
    """
    Encrypt (paper Fig.4):
      S ∈ Z_q^{n×1}
      c1 = C_{id*}·S      (t×1)
      c2 = T_{id'}·S      (m×1)
      key = H(U_{id'}·S)  (t×1 -> bytes)
    """
    q, B, n, m, t = crs.q, crs.B, crs.n, crs.m, crs.t
    id_star, id_prime = compute_indices(user_id, B)

    S = sample_short_matrix(n, 1, bound=3, q=q)   # (n x 1)

    C_id = pp.C_list[id_star]          # (t x n)
    c1 = mod_q(C_id @ S, q)            # (t x 1)

    T_idp = crs.T_list[id_prime]       # (m x n)
    c2 = mod_q(T_idp @ S, q)           # (m x 1)

    U_idp = crs.U_list[id_prime]       # (t x n)
    US    = mod_q(U_idp @ S, q)        # (t x 1)

    key = hash_to_key(US, q, hash_name=crs.hash_name, key_len=16)
    aad = user_id.to_bytes(8, "big") + vector_to_bytes(c1, q) + vector_to_bytes(c2, q)
    nonce, c3, tag = aead_encrypt(key, message, aad)

    return {"user_id": user_id, "c1": c1, "c2": c2, "c3": c3, "nonce": nonce, "tag": tag}


# ---------- Decrypt* ----------
def decrypt_star(user_param, crs: CRSStar, aux: AuxParamsStar, ciphertext):
    """
    Decrypt (paper Fig.4):
      tmp = c1 - L_{id*,id'}·c2     (t×1)
      v   = X^{-1}·tmp             (t×1)
      M = SE.Dec[H(v), c3]
    """
    q, B = crs.q, crs.B
    user_id = user_param["user_id"]
    if ciphertext["user_id"] != user_id:
        raise ValueError("Ciphertext not intended for this user.")

    id_star, id_prime = compute_indices(user_id, B)
    c1, c2 = ciphertext["c1"], ciphertext["c2"]
    c3, nonce, tag = ciphertext["c3"], ciphertext["nonce"], ciphertext["tag"]

    L = aux.L_mat[id_star][id_prime]      # (t x m)
    tmp = mod_q(c1 - (L @ c2), q)         # (t x 1)

    X_inv = user_param["sk_inv"]          # (t x t)
    v = mod_q(X_inv @ tmp, q)             # (t x 1)

    key = hash_to_key(v, q, hash_name=crs.hash_name, key_len=16)
    aad = user_id.to_bytes(8, "big") + vector_to_bytes(c1, q) + vector_to_bytes(c2, q)
    return aead_decrypt(key, nonce, c3, tag, aad)