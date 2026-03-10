"""Configuration from environment variables."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Base directory for persistent data (default: project root / data)
_DATA_ROOT = os.environ.get("SECURE_STORAGE_DATA_ROOT")
if _DATA_ROOT:
    _BASE = Path(_DATA_ROOT).resolve()
else:
    _BASE = Path(__file__).resolve().parent.parent.parent / "data"

# KMS: directory for encrypted master keys and user registry
KMS_STORE_DIR = Path(os.environ.get("SECURE_STORAGE_KMS_DIR", str(_BASE / "kms_store"))).resolve()

# Storage: directory for file blobs (per-user and shared folders)
FILE_BIN_DIR = Path(os.environ.get("SECURE_STORAGE_FILE_BIN", str(_BASE / "file_bin"))).resolve()

# Session token file (CLI/UI); one line with token
SESSION_FILE = Path(os.environ.get("SECURE_STORAGE_SESSION_FILE", str(_BASE / ".session"))).resolve()

# PBKDF2 iterations for key derivation from password
KDF_ITERATIONS = int(os.environ.get("SECURE_STORAGE_KDF_ITERATIONS", "600_000"))

# Application key for shared folder FK (32 bytes, hex-encoded in env). Used so invitees can accept without creator online.
_APP_KEY_HEX = os.environ.get("SECURE_STORAGE_APP_KEY", "").strip()


def get_app_key() -> bytes:
    """Return the 32-byte app key from env. Raises if not set or invalid (must be 64 hex chars)."""
    if len(_APP_KEY_HEX) != 64 or not all(c in "0123456789abcdefABCDEF" for c in _APP_KEY_HEX):
        raise ValueError(
            "SECURE_STORAGE_APP_KEY must be set in .env and be 64 hex characters (32 bytes). "
            "Generate with: python -c import secrets; print(secrets.token_hex(32))"
        )
    return bytes.fromhex(_APP_KEY_HEX)
