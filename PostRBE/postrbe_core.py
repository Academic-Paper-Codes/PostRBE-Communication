# postrbe_core.py
import math
from typing import Tuple, Dict, Any

import numpy as np

from postrbe_structs import CRS, PublicParams, AuxParams
from postrbe_utils import (
    sample_uniform_matrix,
    sample_short_matrix,
    mod_q,
    invert_matrix_mod_q,
    hash_to_key,
    vector_to_bytes,
    aead_encrypt,   # 需要在 postrbe_utils.py 中新增
    aead_decrypt,   # 需要在 postrbe_utils.py 中新增
)

# --------- 索引工具：id → (id_star, id_prime)（都是 0-based） ---------

def compute_indices(user_id: int, B: int) -> Tuple[int, int]:
    """
    根据论文：
      id' = id mod B + 1
      id* = floor(id / B) + 1
    我们在代码中使用 0-based：
      id_prime = id % B
      id_star  = id // B
    """
    id_prime = user_id % B
    id_star = user_id // B
    return id_star, id_prime


# --------- Setup ---------

def setup(security_param: int, N_max: int, q: int = 12289, n: int = 4, m: int = 6):
    """修改后的 Setup 函数，实现方案1中的 t = B * m + n"""
    # 计算 B 的值
    B = int(math.isqrt(N_max))  # B = floor(sqrt(N_max))

    # 计算 t = B * m + n，符合方案1的要求
    t = B * m + n  # 动态计算 t 的值

    # 生成全局矩阵 A，并复制成 B 份 A_i
    A_global = sample_uniform_matrix(n, m, q)
    A_list = [A_global.copy() for _ in range(B)]

    # 为每个 j 生成短矩阵 T_j 和对应的 U_j 矩阵
    U_list = []
    T_column_list = []
    for j in range(B):
        T_j = sample_short_matrix(m, t, bound=3, q=q)  # (m x t)
        U_j = mod_q(A_global @ T_j, q)                  # (n x m) @ (m x t) = (n x t)
        T_column_list.append(T_j)
        U_list.append(U_j)

    # 创建 T_mat，B x B 的 (m x t) 矩阵
    T_mat = []
    for i in range(B):
        row = []
        for j in range(B):
            row.append(T_column_list[j].copy())  # 复制每个 (m x t) 矩阵
        T_mat.append(row)

    # 初始化 C_list 和 L_mat，形状为零矩阵
    C_list = [np.zeros((n, t), dtype=np.int64) for _ in range(B)]
    L_mat = [[np.zeros((m, t), dtype=np.int64) for _ in range(B)] for _ in range(B)]

    # 返回 CRS、Public Params 和 Aux Params
    crs = {"N_max": N_max, "B": B, "q": q, "n": n, "m": m, "t": t, "A_list": A_list, "U_list": U_list, "T_mat": T_mat}
    pp = {"C_list": C_list}
    aux = {"L_mat": L_mat}

    return crs, pp, aux


# --------- KeyGen ---------

def keygen(user_id: int, crs: CRS, bound: int = 3) -> Dict[str, Any]:
    """
    KeyGen(id):
      - 生成可逆短矩阵 X_id 作为 sk
      - 计算 pk_id = U_{id'} * X_id
      - 计算 up_id = (T_{1,id'} X_id, ..., 0, ..., T_{B,id'} X_id)
    这里返回一个 dict，里面包含 user_id, sk, sk_inv, pk, up。
    """
    q, n, m, t, B = crs.q, crs.n, crs.m, crs.t, crs.B
    id_star, id_prime = compute_indices(user_id, B)

    # 1. 采样可逆短矩阵 X (t x t)，并计算其逆 X_inv
    while True:
        X = sample_short_matrix(t, t, bound=bound, q=q)
        try:
            X_inv = invert_matrix_mod_q(X, q)
            break
        except ValueError:
            continue

    # 2. pk_id = U_{id'} * X
    U_idp = crs.U_list[id_prime]               # (n x t)
    pk = mod_q(U_idp @ X, q)                   # (n x t)

    # 3. up_id：长度 B，每个 (m x t)；在位置 id_prime 为 0
    up_list = []
    for i in range(B):
        if i == id_prime:
            up_list.append(np.zeros((crs.m, crs.t), dtype=np.int64))
        else:
            T_i_idp = crs.T_mat[i][id_prime]   # (m x t)
            up_list.append(mod_q(T_i_idp @ X, q))

    return {
        "user_id": user_id,
        "sk": X,
        "sk_inv": X_inv,
        "pk": pk,
        "up": up_list,
    }


# --------- Register ---------

def register(user_param: Dict[str, Any], crs: CRS, pp: PublicParams, aux: AuxParams):
    """
    Register(id, pk_id, up_id):
      - 检查 pk_id ?= A_i * up_i  (i != id_prime)
      - 更新：
          C_{id*} += pk_id
          L_{id*,i} += up_i    (i != id_prime)
    """
    q, B = crs.q, crs.B
    user_id = user_param["user_id"]
    pk = user_param["pk"]
    up_list = user_param["up"]

    id_star, id_prime = compute_indices(user_id, B)
    A_list = crs.A_list

    # 1) 正确性检查：pk == A_i * up_i  (i != id_prime)
    for i in range(B):
        if i == id_prime:
            continue
        lhs = pk
        rhs = mod_q(A_list[i] @ up_list[i], q)    # (n x m) @ (m x t) = (n x t)
        if not np.array_equal(lhs % q, rhs % q):
            raise ValueError(f"Registration check failed for user {user_id}")

    # 2) 更新 C_{id_star} 和 L_{id_star, i}
    C_list = pp.C_list
    L_mat = aux.L_mat

    C_list[id_star] = mod_q(C_list[id_star] + pk, q)
    for i in range(B):
        if i == id_prime:
            continue
        L_mat[id_star][i] = mod_q(L_mat[id_star][i] + up_list[i], q)

    # L_{id_star}[id_prime] 保持不变
    return pp, aux


# --------- Update ---------

def update(user_id: int, crs: CRS, aux: AuxParams) -> np.ndarray:
    """
    Update(id, aux) -> L_{id*, id'}
    """
    B = crs.B
    id_star, id_prime = compute_indices(user_id, B)
    return aux.L_mat[id_star][id_prime]


# --------- Encrypt ---------

def encrypt(pp: PublicParams, crs: CRS, user_id: int, message: bytes) -> Dict[str, Any]:
    """
    Encrypt(pp, P, M)
    这里为了简单，P 就是单一 user_id。
    """
    q, B, n, m, t = crs.q, crs.B, crs.n, crs.m, crs.t
    id_star, id_prime = compute_indices(user_id, B)

    # 1. 采样短向量 S (1 x n)
    S = sample_short_matrix(1, n, bound=3, q=q)            # (1 x n)

    # 2. 计算 c1, c2, SU
    C_idstar = pp.C_list[id_star]                          # (n x t)
    A_idp = crs.A_list[id_prime]                           # (n x m)
    U_idp = crs.U_list[id_prime]                           # (n x t)

    c1 = mod_q(S @ C_idstar, q)                            # (1 x n)@(n x t)=(1 x t)
    c2 = mod_q(S @ A_idp, q)                               # (1 x n)@(n x m)=(1 x m)
    SU = mod_q(S @ U_idp, q)                               # (1 x n)@(n x t)=(1 x t)

    # 3. H(SU) → 对称密钥；AEAD 加密得到 (nonce, c3, tag)
    key = hash_to_key(SU, q, hash_name=crs.hash_name, key_len=16)

    # 绑定 AAD：user_id || c1 || c2
    aad = user_id.to_bytes(8, "big") + vector_to_bytes(c1, q) + vector_to_bytes(c2, q)

    nonce, c3, tag = aead_encrypt(key, message, aad)

    return {
        "user_id": user_id,
        "c1": c1,
        "c2": c2,
        "c3": c3,       # AEAD 密文（不含 tag）
        "nonce": nonce,
        "tag": tag,
    }


# --------- Decrypt ---------

def decrypt(user_param: Dict[str, Any], crs: CRS, aux: AuxParams, ciphertext: Dict[str, Any]) -> bytes:
    """
    Decrypt(sk_id, aux_id, c) -> M
    这里 user_param 来自 keygen 的返回（包含 sk, sk_inv）。
    """
    q, B = crs.q, crs.B
    user_id = user_param["user_id"]

    if ciphertext["user_id"] != user_id:
        raise ValueError("Ciphertext not intended for this user (simple check)")

    id_star, id_prime = compute_indices(user_id, B)
    c1 = ciphertext["c1"]          # (1 x t)
    c2 = ciphertext["c2"]          # (1 x m)
    c3 = ciphertext["c3"]          # bytes (AEAD 密文)
    nonce = ciphertext["nonce"]    # bytes
    tag = ciphertext["tag"]        # bytes

    # 1. 获得 L_{id*, id'}
    L_id = aux.L_mat[id_star][id_prime]   # (m x t)

    # 2. tmp = (c1 - c2 * L) mod q
    tmp = mod_q(c1 - c2 @ L_id, q)        # (1 x t)

    # 3. 乘以 X^{-1}
    X_inv = user_param["sk_inv"]          # (t x t)
    v = mod_q(tmp @ X_inv, q)             # (1 x t)

    # 4. H(v) 作为对称密钥，AEAD 验证与还原
    key = hash_to_key(v, q, hash_name=crs.hash_name, key_len=16)
    aad = user_id.to_bytes(8, "big") + vector_to_bytes(c1, q) + vector_to_bytes(c2, q)

    try:
        plaintext = aead_decrypt(key, nonce, c3, tag, aad)
    except Exception as e:
        raise ValueError(f"AEAD verification failed: {e}")

    return plaintext
