"""Storage backend: file_bin layout, token-based API, KMS integration for SSE using DEKs."""

import json
import os
from pathlib import Path
from typing import Literal

from secure_cloud_storage.crypto import encrypt_bytes, decrypt_bytes
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.config import FILE_BIN_DIR

from cryptography.exceptions import InvalidTag

EncryptionMode = Literal["cse", "sse"]
EncAlgMode = Literal["aesgcm", "chacha20", "fernet"]
BLOB_SUFFIX = ".blob"
META_SUFFIX = ".meta"
CHUNK_SIZE = 1024 * 1024  # 1MB per chunk


class StorageError(Exception):
    """Raised when a storage operation fails."""
    pass


class StorageBackend:
    """Storage layer over file_bin; uses token for identity and calls KMS for keys in SSE mode.
    In SSE mode, files are split into chunks, each encrypted with a different DEK.
    """

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

    def _split_chunks(self, data: bytes) -> list[bytes]:
        """Split data into chunks of CHUNK_SIZE bytes."""
        return [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)] or [b""]

    def list_files(self, token: str, folder_id: str | None = None) -> list[dict]:
        """List files for the user (or in the shared folder). Returns list of {file_id, filename}."""
        base = self._base_dir(token, folder_id)
        if not base.is_dir():
            return []
        result = []
        for p in base.iterdir():
            if p.suffix == META_SUFFIX:
                file_id = p.stem
                chunk_path = base / f"{file_id}_chunk_0{BLOB_SUFFIX}"
                blob_path = base / f"{file_id}{BLOB_SUFFIX}"
                if not chunk_path.is_file() and not blob_path.is_file():
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
        client_wrapped_dek_hex: str | None = None,
        client_key_version: int | None = None,
    ) -> None:
        """Store data. In SSE mode: split into chunks, each encrypted with its own DEK.
        In CSE mode: data is already encrypted, stored as a single chunk.
        """
        base = self._base_dir(token, folder_id)
        base.mkdir(parents=True, exist_ok=True)

        meta_dict = {
            "filename": filename or file_id,
            "encryption_mode": encryption_mode,
            "algorithm_mode": algorithm,
        }

        if encryption_mode == "sse":
            if not self._kms:
                raise StorageError("KMS required for SSE")

            user_id = self._resolve_user_id(token)
            chunks = self._split_chunks(data)
            chunk_metas = []

            for i, chunk in enumerate(chunks):
                chunk_meta_aad = {
                    "filename": filename or file_id,
                    "encryption_mode": encryption_mode,
                    "algorithm_mode": algorithm,
                    "chunk_index": i,
                }

                if folder_id:
                    key = self._kms.get_folder_key(token, folder_id)
                    encrypted_chunk = encrypt_bytes(key, chunk, algorithm, chunk_meta_aad)
                    chunk_metas.append({"wrapped_dek_hex": None, "key_version": None})
                else:
                    raw_dek, wrapped_dek = self._kms.generate_dek(user_id)
                    key_version = self._kms.get_key_version(user_id)
                    encrypted_chunk = encrypt_bytes(raw_dek, chunk, algorithm, chunk_meta_aad)
                    chunk_metas.append({
                        "wrapped_dek_hex": wrapped_dek.hex(),
                        "key_version": key_version,
                    })
                    import secure_cloud_storage.crypto as crypto
                    crypto.secure_zero(bytearray(raw_dek))

                chunk_path = base / f"{file_id}_chunk_{i}{BLOB_SUFFIX}"
                with open(chunk_path, "wb") as f:
                    f.write(encrypted_chunk)

            meta_dict["num_chunks"] = len(chunks)
            meta_dict["chunk_metas"] = chunk_metas

        else:
            # CSE: data already encrypted, store as single chunk
            chunk_path = base / f"{file_id}_chunk_0{BLOB_SUFFIX}"
            with open(chunk_path, "wb") as f:
                f.write(data)
            meta_dict["num_chunks"] = 1
            meta_dict["chunk_metas"] = [{"wrapped_dek_hex": None, "key_version": None}]
            if client_wrapped_dek_hex and client_key_version:
                meta_dict["wrapped_dek_hex"] = client_wrapped_dek_hex
                meta_dict["key_version"] = client_key_version

        meta_path = base / f"{file_id}{META_SUFFIX}"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f)

    def download(
        self,
        token: str,
        file_id: str,
        folder_id: str | None = None,
    ) -> tuple[bytes, str, str, str, dict]:
        """Return (file_contents, encryption_mode, algorithm, filename, raw_meta).
        Reads all chunks, decrypts each with its DEK, and reassembles.
        """
        base = self._base_dir(token, folder_id)
        meta_path = base / f"{file_id}{META_SUFFIX}"

        if not meta_path.is_file():
            raise StorageError(f"File not found: {file_id}")

        try:
            with open(meta_path, encoding="utf-8") as f:
                meta_raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            raise StorageError(f"Corrupted metadata for file: {file_id}")

        mode: EncryptionMode = meta_raw.get("encryption_mode", "cse")
        alg: EncAlgMode = meta_raw.get("algorithm_mode", "aesgcm")
        filename = meta_raw.get("filename", file_id)
        num_chunks = meta_raw.get("num_chunks", 1)
        chunk_metas = meta_raw.get("chunk_metas", [])

        reassembled = b""

        for i in range(num_chunks):
            chunk_path = base / f"{file_id}_chunk_{i}{BLOB_SUFFIX}"

            if not chunk_path.is_file():
                old_blob = base / f"{file_id}{BLOB_SUFFIX}"
                if old_blob.is_file():
                    chunk_path = old_blob
                else:
                    raise StorageError(f"Missing chunk {i} for file: {file_id}")

            with open(chunk_path, "rb") as f:
                chunk_data = f.read()

            if mode == "sse":
                if not self._kms:
                    raise StorageError("KMS required for SSE")

                user_id = self._resolve_user_id(token)

                if folder_id:
                    key = self._kms.get_folder_key(token, folder_id)
                else:
                    chunk_meta_info = chunk_metas[i] if i < len(chunk_metas) else {}
                    wrapped_dek_hex = chunk_meta_info.get("wrapped_dek_hex")
                    key_version = chunk_meta_info.get("key_version")

                    if not wrapped_dek_hex or not key_version:
                        raise StorageError(f"Missing DEK metadata for chunk {i}")

                    wrapped_dek = bytes.fromhex(wrapped_dek_hex)
                    try:
                        key = self._kms.unwrap_dek(user_id, wrapped_dek, key_version)
                    except KMSError as e:
                        raise StorageError(f"Failed to unwrap DEK for chunk {i}: {e}")

                try:
                    chunk_plain, chunk_meta_aad = decrypt_bytes(key, chunk_data)
                except InvalidTag:
                    self.delete(token, file_id, folder_id)
                    raise StorageError(f"Integrity check failed on chunk {i} (AAD mismatch)")
                finally:
                    if not folder_id:
                        import secure_cloud_storage.crypto as crypto
                        crypto.secure_zero(bytearray(key))

                if chunk_meta_aad.get("filename") != filename:
                    self.delete(token, file_id, folder_id)
                    raise StorageError(f"Chunk {i} filename AAD mismatch")
                if chunk_meta_aad.get("encryption_mode") != mode:
                    self.delete(token, file_id, folder_id)
                    raise StorageError(f"Chunk {i} encryption mode AAD mismatch")
                if chunk_meta_aad.get("chunk_index") != i:
                    self.delete(token, file_id, folder_id)
                    raise StorageError(f"Chunk {i} index AAD mismatch")

                reassembled += chunk_plain
            else:
                reassembled += chunk_data

        return (reassembled, mode, alg, filename, meta_raw)

    def delete(self, token: str, file_id: str, folder_id: str | None = None) -> None:
        """Remove all chunks and metadata for a file."""
        base = self._base_dir(token, folder_id)
        meta_path = base / f"{file_id}{META_SUFFIX}"

        num_chunks = 1
        if meta_path.is_file():
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
                num_chunks = meta.get("num_chunks", 1)
            except (json.JSONDecodeError, OSError):
                pass

        deleted_any = False
        for i in range(num_chunks):
            chunk_path = base / f"{file_id}_chunk_{i}{BLOB_SUFFIX}"
            if chunk_path.is_file():
                chunk_path.unlink()
                deleted_any = True

        old_blob = base / f"{file_id}{BLOB_SUFFIX}"
        if old_blob.is_file():
            old_blob.unlink()
            deleted_any = True

        if not deleted_any and not meta_path.is_file():
            raise StorageError(f"File not found: {file_id}")

        if meta_path.is_file():
            meta_path.unlink()

    def reencrypt_file(self, token: str, file_id: str, folder_id: str | None = None) -> None:
        """Re-encrypt all chunks of a file with new DEKs (called after key rotation)."""
        base = self._base_dir(token, folder_id)
        meta_path = base / f"{file_id}{META_SUFFIX}"

        if not meta_path.is_file():
            raise StorageError(f"File not found: {file_id}")

        with open(meta_path, encoding="utf-8") as f:
            meta_raw = json.load(f)

        mode: EncryptionMode = meta_raw.get("encryption_mode", "cse")
        alg: EncAlgMode = meta_raw.get("algorithm_mode", "aesgcm")
        filename = meta_raw.get("filename", file_id)
        num_chunks = meta_raw.get("num_chunks", 1)
        chunk_metas = meta_raw.get("chunk_metas", [])

        # Only SSE personal files need re-encryption
        if mode != "sse" or folder_id:
            return

        if not self._kms:
            raise StorageError("KMS required for re-encryption")

        user_id = self._resolve_user_id(token)
        new_chunk_metas = []

        for i in range(num_chunks):
            chunk_path = base / f"{file_id}_chunk_{i}{BLOB_SUFFIX}"
            if not chunk_path.is_file():
                raise StorageError(f"Missing chunk {i} for file: {file_id}")

            with open(chunk_path, "rb") as f:
                chunk_data = f.read()

            # 1. Decrypt with OLD DEK
            chunk_meta_info = chunk_metas[i] if i < len(chunk_metas) else {}
            wrapped_dek_hex = chunk_meta_info.get("wrapped_dek_hex")
            key_version = chunk_meta_info.get("key_version")

            if not wrapped_dek_hex or not key_version:
                raise StorageError(f"Missing DEK metadata for chunk {i}")

            old_wrapped_dek = bytes.fromhex(wrapped_dek_hex)
            old_key = self._kms.unwrap_dek(user_id, old_wrapped_dek, key_version)

            try:
                chunk_plain, _ = decrypt_bytes(old_key, chunk_data)
            except InvalidTag:
                raise StorageError(f"Integrity check failed on chunk {i} during re-encryption")
            finally:
                import secure_cloud_storage.crypto as crypto
                crypto.secure_zero(bytearray(old_key))

            # 2. Re-encrypt with NEW DEK
            new_raw_dek, new_wrapped_dek = self._kms.generate_dek(user_id)
            new_key_version = self._kms.get_key_version(user_id)

            chunk_meta_aad = {
                "filename": filename,
                "encryption_mode": mode,
                "algorithm_mode": alg,
                "chunk_index": i,
            }

            new_encrypted_chunk = encrypt_bytes(new_raw_dek, chunk_plain, alg, chunk_meta_aad)

            import secure_cloud_storage.crypto as crypto
            crypto.secure_zero(bytearray(new_raw_dek))

            # 3. Overwrite chunk on disk
            with open(chunk_path, "wb") as f:
                f.write(new_encrypted_chunk)

            new_chunk_metas.append({
                "wrapped_dek_hex": new_wrapped_dek.hex(),
                "key_version": new_key_version,
            })

        # 4. Update metadata
        meta_raw["chunk_metas"] = new_chunk_metas
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_raw, f)