"""Cryptographic helpers: secure memory/file wipe and AES-GCM encryption."""

import os
from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM uses 128-bit (16-byte) tags; key must be 256-bit for AES-256
KEY_BYTES = 32
NONCE_BYTES = 12


def secure_zero(buf: Union[bytearray, bytes]) -> None:
    """Overwrite a buffer with zeros to avoid leaving key material in memory.

    Modifies in place; use bytearray for mutable buffers.
    """
    if isinstance(buf, bytes):
        # bytes are immutable; caller should use bytearray for sensitive data
        return
    n = len(buf)
    for i in range(n):
        buf[i] = 0


def secure_overwrite_file(path: os.PathLike[str]) -> None:
    """Overwrite file contents with random data before deletion (secure delete).

    Used for key files. File is left in place; caller should remove it afterward.
    """
    path = os.fspath(path)
    if not os.path.isfile(path):
        return
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM; returns nonce + ciphertext + tag (single blob)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes")
    nonce = os.urandom(NONCE_BYTES)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    """Decrypt a blob produced by encrypt_bytes (nonce + ciphertext + tag)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes")
    if (
        len(blob) < NONCE_BYTES + 16
    ):  # nonce + at least 16 bytes (tag + some ciphertext)
        raise ValueError("Blob too short")
    nonce = blob[:NONCE_BYTES]
    ciphertext = blob[NONCE_BYTES:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)
