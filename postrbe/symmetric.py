"""Authenticated symmetric encryption for encapsulated PostRBE messages."""
from __future__ import annotations

import hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover - exercised by environment check
    AESGCM = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def require_aesgcm() -> None:
    if AESGCM is None:
        raise RuntimeError("cryptography is required for AES-256-GCM") from _IMPORT_ERROR


def derive_key(extracted: bytes) -> bytes:
    return hashlib.sha256(b"PostRBE-AESGCM-v1\x00" + extracted).digest()


def encrypt_aes_gcm(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    require_aesgcm()
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    require_aesgcm()
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
