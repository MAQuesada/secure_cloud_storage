"""Storage backend: file_bin layout, token-based API, KMS integration for SSE."""

import json
import os
from pathlib import Path
from typing import Literal

from secure_cloud_storage.crypto import encrypt_bytes, decrypt_bytes
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.config import FILE_BIN_DIR

EncryptionMode = Literal["cse", "sse"]
EncAlgMode = Literal["aesgcm", "chacha20", "fernet"]
BLOB_SUFFIX = ".blob"
META_SUFFIX = ".meta"


class StorageError(Exception):
    """Raised when a storage operation fails."""

    pass


class StorageBackend:
    """Storage layer over file_bin; uses token for identity and calls KMS for keys in SSE mode."""

    def __init__(
        self, file_bin_dir: Path | None = None, kms: KMS | None = None
    ) -> None:
        self._root = Path(file_bin_dir) if file_bin_dir else FILE_BIN_DIR
        self._kms = kms
        self._root.mkdir(parents=True, exist_ok=True)
        (self._root / "shared").mkdir(parents=True, exist_ok=True)

    def _user_dir(self, user_id: str) -> Path:
        return self._root / user_id

    def _shared_dir(self, folder_id: str) -> Path:
        return self._root / "shared" / folder_id

    def _resolve_user_id(self, token: str) -> str:
        if not self._kms:
            raise StorageError("KMS not configured")
        return self._kms.get_user_id_for_token(token)

    def _base_dir(self, token: str, folder_id: str | None) -> Path:
        user_id = self._resolve_user_id(token)
        if folder_id is None:
            return self._user_dir(user_id)
        return self._shared_dir(folder_id)

    def list_files(self, token: str, folder_id: str | None = None) -> list[dict]:
        """List files for the user (or in the shared folder). Returns list of {file_id, filename}."""
        base = self._base_dir(token, folder_id)
        if not base.is_dir():
            return []
        result = []
        for p in base.iterdir():
            if p.suffix == META_SUFFIX:
                file_id = p.stem
                blob_path = base / f"{file_id}{BLOB_SUFFIX}"
                if not blob_path.is_file():
                    continue
                try:
                    with open(p, encoding="utf-8") as f:
                        meta = json.load(f)
                    result.append(
                        {
                            "file_id": file_id,
                            "filename": meta.get("filename", file_id),
                            "encryption_mode": meta.get("encryption_mode") or "cse",
                            "algorithm_mode": meta.get("algorithm_mode") or "aesgcm",
                        }
                    )
                except (json.JSONDecodeError, OSError):
                    result.append(
                        {
                            "file_id": file_id,
                            "filename": file_id,
                            "encryption_mode": "cse",
                            "algorithm_mode": "aesgcm",
                        }
                    )
        return result

    def upload(
        self,
        token: str,
        file_id: str,
        data: bytes,
        folder_id: str | None = None,
        filename: str | None = None,
        encryption_mode: EncryptionMode = "cse",
        algorithm: EncAlgMode = "aesgcm",
    ) -> None:
        """Store data. In CSE mode data is already encrypted; in SSE mode we encrypt here using KMS."""
        base = self._base_dir(token, folder_id)
        base.mkdir(parents=True, exist_ok=True)
        if encryption_mode == "sse":
            if not self._kms:
                raise StorageError("KMS required for SSE")
            if folder_id:
                key = self._kms.get_folder_key(token, folder_id)
            else:
                key = self._kms.get_key_for_token(token)

            metadata = {
                "algorithm": algorithm,
                "encryption_mode": encryption_mode,
                "filename": filename,
                # OJOOOOO -> MAYBE IT IS NECESSARY TO PUT KEY_ID HERE OR SOMETHING LIKE THAT IN THE FUTURE
            }
            data = encrypt_bytes(key, data, algorithm, metadata)
        blob_path = base / f"{file_id}{BLOB_SUFFIX}"
        meta_path = base / f"{file_id}{META_SUFFIX}"
        with open(blob_path, "wb") as f:
            f.write(data)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "filename": filename or file_id,
                    "encryption_mode": encryption_mode,
                    "algorithm_mode": algorithm,
                },
                f,
            )

    def download(
        self,
        token: str,
        file_id: str,
        folder_id: str | None = None,
    ) -> tuple[bytes, str]:
        """Return (file_contents, encryption_mode). Mode is read from file metadata for correct decryption."""
        base = self._base_dir(token, folder_id)
        blob_path = base / f"{file_id}{BLOB_SUFFIX}"
        meta_path = base / f"{file_id}{META_SUFFIX}"
        if not blob_path.is_file():
            raise StorageError(f"File not found: {file_id}")
        mode: EncryptionMode = "cse"
        if meta_path.is_file():
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
                mode = meta.get("encryption_mode") or "cse"
            except (json.JSONDecodeError, OSError):
                pass
        with open(blob_path, "rb") as f:
            data = f.read()
        if mode == "sse":
            if not self._kms:
                raise StorageError("KMS required for SSE")
            if folder_id:
                key = self._kms.get_folder_key(token, folder_id)
            else:
                key = self._kms.get_key_for_token(token)
            data, _ = decrypt_bytes(key, data)
        return (data, mode)

    def delete(self, token: str, file_id: str, folder_id: str | None = None) -> None:
        """Remove file blob and metadata. No key material involved."""
        base = self._base_dir(token, folder_id)
        blob_path = base / f"{file_id}{BLOB_SUFFIX}"
        meta_path = base / f"{file_id}{META_SUFFIX}"
        if not blob_path.is_file():
            raise StorageError(f"File not found: {file_id}")
        blob_path.unlink()
        if meta_path.is_file():
            meta_path.unlink()
