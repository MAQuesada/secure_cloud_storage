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
