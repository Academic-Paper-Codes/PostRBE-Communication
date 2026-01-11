# postrbe_debug.py
"""
调试版：使用 logger 打印 PostRBE 每一步的关键矩阵和中间结果。

运行：
    python postrbe_debug.py
"""

import logging
import numpy as np
from postrbe_utils import (
    mod_q,
    hash_to_key,
    aead_encrypt,   # 新
    aead_decrypt,   # 新
)


from postrbe_core import (
    setup,
    keygen,
    register,
    update,
    compute_indices,  # 注意：postrbe_core 里要 export 这个函数
)
from postrbe_utils import (
    mod_q,
    hash_to_key,
    xor_encrypt,
    xor_decrypt,
)

from postrbe_structs import CRS, PublicParams, AuxParams


# ---------- 日志配置 ----------

logger = logging.getLogger("postrbe_debug")
logger.setLevel(logging.DEBUG)

# 控制台输出 handler
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# 日志格式
formatter = logging.Formatter(
    "[%(levelname)s] %(message)s"
)
ch.setFormatter(formatter)

# 避免重复添加 handler
if not logger.handlers:
    logger.addHandler(ch)

# numpy 打印设置（方便看矩阵）
np.set_printoptions(linewidth=120, suppress=True)


# ---------- 带日志的 Encrypt / Decrypt ----------

def encrypt_debug(pp: PublicParams, crs: CRS, user_id: int, message: bytes):
    """
    带详细日志输出的 Encrypt(pp, user_id, M)。
    完全仿照 postrbe_core.encrypt，只是加了 logger.debug。
    """
    q, B, n, m, t = crs.q, crs.B, crs.n, crs.m, crs.t
    id_star, id_prime = compute_indices(user_id, B)

    logger.debug("=== [Encrypt] Start for user_id = %d ===", user_id)
    logger.debug("B = %d, id_star = %d, id_prime = %d", B, id_star, id_prime)

    # 1. 采样短向量 S (1 x n)
    from postrbe_utils import sample_short_matrix
    S = sample_short_matrix(1, n, bound=3, q=q)           # (1 x n)
    logger.debug("S (1 x n):\n%s", S)

    # 2. 取出矩阵
    C_idstar = pp.C_list[id_star]                         # (n x t)
    A_idp = crs.A_list[id_prime]                          # (n x m)
    U_idp = crs.U_list[id_prime]                          # (n x t)

    logger.debug("C[id_star] (n x t):\n%s", C_idstar)
    logger.debug("A[id_prime] (n x m):\n%s", A_idp)
    logger.debug("U[id_prime] (n x t):\n%s", U_idp)

    # 3. 计算 c1, c2, SU
    c1 = mod_q(S @ C_idstar, q)                           # (1 x t)
    c2 = mod_q(S @ A_idp, q)                              # (1 x m)
    SU = mod_q(S @ U_idp, q)                              # (1 x t)

    logger.debug("c1 = S * C[id_star] (1 x t):\n%s", c1)
    logger.debug("c2 = S * A[id_prime] (1 x m):\n%s", c2)
    logger.debug("SU = S * U[id_prime] (1 x t):\n%s", SU)

    key = hash_to_key(SU, q, hash_name=crs.hash_name, key_len=16)
    logger.debug("H(SU) as key (len=%d): %s", len(key), key.hex())
    c3  = aead_encrypt(key, message)
    logger.debug("c3 (nonce||ciphertext+tag, len=%d)", len(c3))


    ct = {
        "user_id": user_id,
        "c1": c1,
        "c2": c2,
        "c3": c3,
    }

    logger.debug("=== [Encrypt] End ===\n")
    return ct


def decrypt_debug(user_param, crs: CRS, aux: AuxParams, ciphertext):
    """
    带详细日志输出的 Decrypt。
    仿照 postrbe_core.decrypt，只是加了 logger.debug。
    """
    q, B = crs.q, crs.B
    user_id = user_param["user_id"]

    logger.debug("=== [Decrypt] Start for user_id = %d ===", user_id)

    if ciphertext["user_id"] != user_id:
        logger.error("Ciphertext not intended for this user.")
        raise ValueError("Ciphertext not intended for this user")

    id_star, id_prime = compute_indices(user_id, B)
    c1 = ciphertext["c1"]
    c2 = ciphertext["c2"]
    c3 = ciphertext["c3"]

    logger.debug("B = %d, id_star = %d, id_prime = %d", B, id_star, id_prime)
    logger.debug("c1 (1 x t):\n%s", c1)
    logger.debug("c2 (1 x m):\n%s", c2)

    # 1. L_{id*, id'}
    L_id = aux.L_mat[id_star][id_prime]   # (m x t)
    logger.debug("L[id_star][id_prime] (m x t):\n%s", L_id)

    # 2. tmp = (c1 - c2 * L) mod q
    tmp = mod_q(c1 - c2 @ L_id, q)        # (1 x t)
    logger.debug("tmp = c1 - c2 * L (1 x t):\n%s", tmp)

    # 3. 乘以 X^{-1}
    X_inv = user_param["sk_inv"]          # (t x t)
    X = user_param["sk"]
    logger.debug("X (t x t):\n%s", X)
    logger.debug("X_inv (t x t):\n%s", X_inv)

    v = mod_q(tmp @ X_inv, q)             # (1 x t)
    logger.debug("v = tmp * X^{-1} (1 x t):\n%s", v)

    # 4. H(v) 作为密钥
    key = hash_to_key(v, q, hash_name=crs.hash_name, key_len=16)
    logger.debug("H(v) as key (len=%d): %s", len(key), key.hex())
    plaintext = aead_decrypt(key, c3)


    plaintext = xor_decrypt(key, c3)
    logger.debug("Recovered plaintext bytes (len=%d): %s", len(plaintext), plaintext)
    logger.debug("=== [Decrypt] End ===\n")

    return plaintext


# ---------- 主调试流程 ----------

def main():
    # 1. Setup
    logger.info(">>> Running Setup")
    crs, pp, aux = setup(security_param=128, N_max=100)

    logger.debug("CRS parameters: N_max=%d, B=%d, q=%d, n=%d, m=%d, t=%d",
                 crs.N_max, crs.B, crs.q, crs.n, crs.m, crs.t)

    # 打印第一块的 A, U, T 作为示例
    logger.debug("A[0] (n x m):\n%s", crs.A_list[0])
    logger.debug("U[0] (n x t):\n%s", crs.U_list[0])
    logger.debug("T[0][1] (m x t):\n%s", crs.T_mat[0][1])

    # 验证一下 A[0] * T[0][1] 是否等于 U[1]
    lhs = mod_q(crs.A_list[0] @ crs.T_mat[0][1], crs.q)
    rhs = crs.U_list[1]
    logger.debug("Check A[0] * T[0][1] == U[1] ? %s", np.array_equal(lhs, rhs))
    logger.debug("A[0] * T[0][1]:\n%s", lhs)
    logger.debug("U[1]:\n%s", rhs)

    # 2. KeyGen + Register
    user_id = 7
    logger.info(">>> Running KeyGen for user_id=%d", user_id)
    user = keygen(user_id, crs)

    logger.debug("Secret key X (t x t):\n%s", user["sk"])
    logger.debug("Secret key inverse X_inv (t x t):\n%s", user["sk_inv"])
    logger.debug("Public key pk (n x t):\n%s", user["pk"])

    logger.debug("up list length = %d", len(user["up"]))
    logger.debug("up[0] (m x t):\n%s", user["up"][0])

    logger.info(">>> Running Register for user_id=%d", user_id)
    pp, aux = register(user, crs, pp, aux)

    logger.debug("After register, C[id_star]:\n%s", pp.C_list[compute_indices(user_id, crs.B)[0]])
    logger.debug("After register, some L[id_star][i]:\n%s", aux.L_mat[compute_indices(user_id, crs.B)[0]][0])

    # 3. Encrypt + Decrypt（带详细日志）
    message = b"hello PostRBE! this is a debug message."
    logger.info(">>> Running Encrypt_debug")
    ct = encrypt_debug(pp, crs, user_id, message)

    logger.info(">>> Running Decrypt_debug")
    pt = decrypt_debug(user, crs, aux, ct)

    logger.info("Original:  %s", message)
    logger.info("Decrypted: %s", pt)
    logger.info("Equal?    %s", message == pt)


if __name__ == "__main__":
    main()
