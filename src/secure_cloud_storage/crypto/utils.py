"""Cryptographic helpers: secure memory/file wipe and AES-GCM encryption."""

import base64
import json
import os
from typing import Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

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


def encrypt_bytes(
    key: bytes, plaintext: bytes, algorithm: str, metadata: dict
) -> bytes:
    """Encrypt plaintext using the specified algorithm. For AESGCM it will used the metadata to encrypt too.
    Returns nonce + ciphertext + tag (single blob)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes")

    # Encode metadata to aad
    aad = json.dumps(metadata).encode()
    blob = b""

    # We select the algorithm and encrypt
    if algorithm == "aesgcm":
        nonce = os.urandom(NONCE_BYTES)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)
        blob = b"aesgcm|" + aad + b"|" + nonce + ciphertext

    elif algorithm == "chacha20":
        nonce = os.urandom(NONCE_BYTES)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        blob = b"chacha20|" + aad + b"|" + nonce + ciphertext

    elif algorithm == "fernet":
        # fernet needs a specified kind of key, so we modify the master_key
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        ciphertext = f.encrypt(plaintext)
        blob = b"fernet|" + aad + b"|" + ciphertext

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return blob


def decrypt_bytes(key: bytes, blob: bytes) -> tuple[bytes, dict]:
    """Decrypt a blob produced by encrypt_bytes using the algorithm specified on it (metadata + nonce + ciphertext + tag)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes")

    # We get the algorithm, metadata and the rest of the data
    algorithm, rest = blob.split(b"|", 1)
    aad_raw, payload = rest.split(b"|", 1)
    metadata = json.loads(aad_raw.decode())

    plaintext = None
    # We select the algorithm
    if algorithm == b"aesgcm":
        if (len(blob) < NONCE_BYTES + 16):  # nonce + at least 16 bytes (tag + some ciphertext)
            raise ValueError("Blob too short")
        nonce = payload[:NONCE_BYTES]
        ciphertext = payload[NONCE_BYTES:]
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, aad_raw)

    elif algorithm == b"chacha20":
        if (len(blob) < NONCE_BYTES + 16):  # nonce + at least 16 bytes (tag + some ciphertext)
            raise ValueError("Blob too short")
        nonce = payload[:NONCE_BYTES]
        ciphertext = payload[NONCE_BYTES:]
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, aad_raw)

    elif algorithm == b"fernet":
        # fernet needs a specified kind of key, so we modify the master_key
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        plaintext = f.decrypt(payload)

    else:
        raise ValueError("Unsupported algorithm")

    return plaintext, metadata
