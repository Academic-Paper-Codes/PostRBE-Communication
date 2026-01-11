# postrbe_utils.py
import numpy as np
import hashlib
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    AESGCM = None

def sample_uniform_matrix(rows: int, cols: int, q: int) -> np.ndarray:
    """
    在 Z_q 上均匀随机采样一个 rows x cols 的矩阵。
    """
    return np.random.randint(0, q, size=(rows, cols), dtype=np.int64)


def sample_short_matrix(rows: int, cols: int, bound: int, q: int) -> np.ndarray:
    """
    在 [-bound, bound] 中采样短整数矩阵，并映射到 Z_q。
    """
    mat = np.random.randint(-bound, bound + 1, size=(rows, cols), dtype=np.int64)
    return np.mod(mat, q)


def mod_q(mat: np.ndarray, q: int) -> np.ndarray:
    """
    按元素对矩阵取模 q。
    """
    return np.mod(mat, q)


def inv_mod(a: int, q: int) -> int:
    """
    计算 a 在 Z_q 上的乘法逆元。假设 q 为质数且 a != 0 (mod q)。
    """
    return pow(int(a) % q, q - 2, q)


def invert_matrix_mod_q(M: np.ndarray, q: int) -> np.ndarray:
    """
    高斯消元，在 Z_q 上求矩阵逆矩阵。
    若不可逆，则抛出 ValueError。
    """
    M = np.array(M, dtype=np.int64)
    n = M.shape[0]
    assert M.shape[0] == M.shape[1]
    # 构造增广矩阵 [M | I]
    aug = np.zeros((n, 2 * n), dtype=np.int64)
    aug[:, :n] = np.mod(M, q)
    aug[:, n:] = np.eye(n, dtype=np.int64)

    for col in range(n):
        # 找主元
        pivot = None
        for row in range(col, n):
            if aug[row, col] % q != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix not invertible mod q")

        # 换行
        if pivot != col:
            aug[[col, pivot]] = aug[[pivot, col]]

        # 归一化主元行
        inv_piv = inv_mod(aug[col, col], q)
        aug[col, :] = (aug[col, :] * inv_piv) % q

        # 消去其他行该列
        for row in range(n):
            if row == col:
                continue
            factor = aug[row, col] % q
            if factor != 0:
                aug[row, :] = (aug[row, :] - factor * aug[col, :]) % q

    invM = aug[:, n:]
    return np.mod(invM, q)


def vector_to_bytes(vec: np.ndarray, q: int) -> bytes:
    """
    将向量/矩阵展平为 1D 后，每个元素用 2 字节编码为 bytes。
    （由于 q < 2^15，2 字节足够）
    """
    flat = np.array(vec, dtype=np.int64).flatten()
    ba = bytearray()
    for x in flat:
        x_mod = int(x) % q
        ba.extend(x_mod.to_bytes(2, 'big', signed=False))
    return bytes(ba)


def hash_to_key(vec: np.ndarray, q: int, hash_name: str = "sha256", key_len: int = 16) -> bytes:
    """
    H(vec) -> key_bytes：用于对称加密密钥。
    """
    data = vector_to_bytes(vec, q)
    h = hashlib.new(hash_name)
    h.update(data)
    digest = h.digest()
    return digest[:key_len]


# ------ toy 对称加密：简单 XOR（纯为了 demo，方便跑通流程） ------

def xor_encrypt(key_bytes: bytes, plaintext: bytes) -> bytes:
    """
    玩具版“对称加密”：使用 key 重复 XOR。
    注意：这不是安全的，只用于实验 demo。
    """
    out = bytearray()
    L = len(key_bytes)
    for i, b in enumerate(plaintext):
        out.append(b ^ key_bytes[i % L])
    return bytes(out)


def xor_decrypt(key_bytes: bytes, ciphertext: bytes) -> bytes:
    """
    XOR 自反，所以解密 = 加密。
    """
    return xor_encrypt(key_bytes, ciphertext)



def aead_encrypt(key_bytes: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    AES-GCM 加密：返回 nonce || ciphertext+tag
    key_bytes: 16/24/32 字节；我们用 16 字节（AES-128）
    aad: 可选的附加认证数据（此处默认空）
    """
    if AESGCM is None:
        raise RuntimeError("Missing dependency: pip install cryptography")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 16/24/32 bytes")
    nonce = os.urandom(12)  # 96-bit nonce
    ct = AESGCM(key_bytes).encrypt(nonce, plaintext, aad)
    return nonce + ct

def aead_decrypt(key_bytes: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """
    AES-GCM 解密：输入 nonce || ciphertext+tag
    """
    if AESGCM is None:
        raise RuntimeError("Missing dependency: pip install cryptography")
    if len(data) < 12:
        raise ValueError("ciphertext too short")
    nonce, ct = data[:12], data[12:]
    return AESGCM(key_bytes).decrypt(nonce, ct, aad)


# --- AEAD (AES-GCM) helpers ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _normalize_key(key: bytes) -> bytes:
    return key if len(key) in (16, 24, 32) else hashlib.sha256(key).digest()[:16]

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b""):
    key = _normalize_key(key)
    nonce = os.urandom(12)  # 96-bit nonce
    aes = AESGCM(key)
    ct_with_tag = aes.encrypt(nonce, plaintext, aad)  # = ciphertext || tag
    return nonce, ct_with_tag[:-16], ct_with_tag[-16:]

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    key = _normalize_key(key)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext + tag, aad)
