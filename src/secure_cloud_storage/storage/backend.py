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
        client_wrapped_dek_hex: str | None = None,
        client_key_version: int | None = None,
    ) -> None:
        """Store data. In CSE mode data is already encrypted (and may provide DEK meta); in SSE mode we encrypt here using KMS DEK."""
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
            
            if folder_id:
                # OJO: Para shared folders por simplicidad actual mantenemos el viejo método adaptado
                # En un rediseño completo de shared folders, habría una folder_dek
                key = self._kms.get_folder_key(token, folder_id)
                data = encrypt_bytes(key, data, algorithm, meta_dict)
            else:
                # === NEW: Envelope Encryption con DEK (SSE Personal) ===
                raw_dek, wrapped_dek = self._kms.generate_dek(user_id)
                key_version = self._kms.get_key_version(user_id)
                
                # Ciframos usando la DEK plana
                data = encrypt_bytes(raw_dek, data, algorithm, meta_dict)
                
                # Guardamos la DEK envuelta en los metadatos del archivo
                meta_dict["wrapped_dek_hex"] = wrapped_dek.hex()
                meta_dict["key_version"] = key_version
                
                # Borramos la DEK plana por seguridad (aunque al acabar la función se elimina, es buena práctica)
                import secure_cloud_storage.crypto as crypto
                crypto.secure_zero(bytearray(raw_dek))
        else:
            # === CSE Mode ===
            # The data is already encrypted. If the client passed DEK info, we save it.
            if client_wrapped_dek_hex and client_key_version:
                meta_dict["wrapped_dek_hex"] = client_wrapped_dek_hex
                meta_dict["key_version"] = client_key_version

        blob_path = base / f"{file_id}{BLOB_SUFFIX}"
        meta_path = base / f"{file_id}{META_SUFFIX}"
        
        with open(blob_path, "wb") as f:
            f.write(data)
            
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f)

    def download(
        self,
        token: str,
        file_id: str,
        folder_id: str | None = None,
    ) -> tuple[bytes, str, str, str, dict]:
        """Return (file_contents, encryption_mode, algorithm, filename, raw_meta). Mode is read from metadata."""
        base = self._base_dir(token, folder_id)
        blob_path = base / f"{file_id}{BLOB_SUFFIX}"
        meta_path = base / f"{file_id}{META_SUFFIX}"
        
        if not blob_path.is_file():
            raise StorageError(f"File not found: {file_id}")
            
        mode: EncryptionMode = "cse"
        alg: EncAlgMode = "aesgcm"
        file = ""
        meta_raw = {}
        
        if meta_path.is_file():
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta_raw = json.load(f)
                mode = meta_raw.get("encryption_mode", "cse")
                file = meta_raw.get("filename", "")
                alg = meta_raw.get("algorithm_mode", "aesgcm")
            except (json.JSONDecodeError, OSError):
                pass
                
        with open(blob_path, "rb") as f:
            data = f.read()
            
        if mode == "sse":
            if not self._kms:
                raise StorageError("KMS required for SSE")
                
            user_id = self._resolve_user_id(token)
            
            if folder_id:
                # Shared folders viejo
                key = self._kms.get_folder_key(token, folder_id)
            else:
                # === NEW: Envelope Encryption (SSE Personal) ===
                wrapped_dek_hex = meta_raw.get("wrapped_dek_hex")
                key_version = meta_raw.get("key_version")
                
                if not wrapped_dek_hex or not key_version:
                    raise StorageError("Missing DEK metadata in SSE file. File cannot be decrypted.")
                    
                wrapped_dek = bytes.fromhex(wrapped_dek_hex)
                try:
                    key = self._kms.unwrap_dek(user_id, wrapped_dek, key_version)
                except KMSError as e:
                    raise StorageError(f"Failed to unwrap DEK: {e}")

            try:
                # Desciframos usando la DEK
                data, metadata = decrypt_bytes(key, data)
            except InvalidTag:
                self.delete(token, file_id, folder_id)
                raise StorageError("File integrity verification failed (AAD/authentication tag mismatch)")
            finally:
                if not folder_id:
                     import secure_cloud_storage.crypto as crypto
                     crypto.secure_zero(bytearray(key))

            # Verificación de integridad AAD
            file_aad = metadata.get("filename")
            encryp_aad = metadata.get("encryption_mode")
            alg_aad = metadata.get("algorithm_mode")
            
            if file is None or file != file_aad:
                self.delete(token, file_id, folder_id)
                raise StorageError(f"File .meta was modified in name -> .meta: {file}; Verified: {file_aad}")
            if mode is None or mode != encryp_aad:
                self.delete(token, file_id, folder_id)
                raise StorageError(f"File .meta was modified in mode -> .meta: {mode}; Verified: {encryp_aad}")
            if alg is None or alg != alg_aad:
                self.delete(token, file_id, folder_id)
                raise StorageError(f"File .meta was modified in encryption algorithm-> .meta: {alg}; Verified: {alg_aad}")
                
        # We return meta_raw as well so the client can extract DEK info for CSE decryption
        return (data, mode, alg, file, meta_raw)

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