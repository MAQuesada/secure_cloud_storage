"""Client service: orchestrates KMS + Storage; handles CSE (encrypt/decrypt) and SSE (plain) using DEKs."""

import uuid
from pathlib import Path
from typing import Literal

from secure_cloud_storage.crypto import encrypt_bytes, decrypt_bytes, secure_zero
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.storage import StorageBackend
from secure_cloud_storage.storage.backend import StorageError

from cryptography.exceptions import InvalidTag

EncryptionMode = Literal["cse", "sse"]
EncAlgMode = Literal["aesgcm", "chacha20", "fernet"]


class ClientService:
    """High-level client: login, list, upload, download, delete; CSE/SSE and shared folders."""

    def __init__(self, kms: KMS, storage: StorageBackend) -> None:
        self._kms = kms
        self._storage = storage

    def register(self, username: str, password: str) -> str:
        """Register a new user. Returns session token."""
        return self._kms.register(username, password)

    def login(self, username: str, password: str) -> str:
        """Authenticate and start session. Returns session token."""
        return self._kms.login(username, password)

    def get_username(self, token: str) -> str | None:
        """Return the username for the current session (for display in UI)."""
        return self._kms.get_username_for_token(token)

    def list_files(self, token: str, folder_id: str | None = None) -> list[dict]:
        """List files for the user or in the shared folder. Returns [{file_id, filename}]."""
        return self._storage.list_files(token, folder_id)

    def upload_file(
        self,
        token: str,
        local_path: Path | str,
        filename: str | None = None,
        folder_id: str | None = None,
        encryption_mode: EncryptionMode = "cse",
        algorithm: EncAlgMode = "aesgcm",
    ) -> str:
        """Upload a file. Returns the assigned file_id."""
        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        file_id = uuid.uuid4().hex
        display_name = filename or path.name
        data = path.read_bytes()
        
        if encryption_mode == "cse":
            wrapped_dek_hex = None
            key_version = None
            
            if folder_id:
                # Carpetas compartidas mantienen su lógica por ahora
                key = self._kms.get_folder_key(token, folder_id)
            else:
                # === NEW: Envelope Encryption (CSE Personal) ===
                user_id = self._kms.get_user_id_for_token(token)
                raw_dek, wrapped_dek = self._kms.generate_dek(user_id)
                key_version = self._kms.get_key_version(user_id)
                key = raw_dek
                wrapped_dek_hex = wrapped_dek.hex()

            metadata = {
                "filename": filename or file_id,
                "encryption_mode": encryption_mode,
                "algorithm_mode": algorithm,
            }
            
            try:
                data = encrypt_bytes(key, data, algorithm, metadata)
            finally:
                if not folder_id:
                    # Borrado seguro de la DEK de la memoria
                    secure_zero(bytearray(key))
                    
            self._storage.upload(
                token,
                file_id,
                data,
                folder_id=folder_id,
                filename=display_name,
                encryption_mode="cse",
                algorithm=algorithm,
                client_wrapped_dek_hex=wrapped_dek_hex,
                client_key_version=key_version,
            )
        else:
            self._storage.upload(
                token,
                file_id,
                data,
                folder_id=folder_id,
                filename=display_name,
                encryption_mode="sse",
                algorithm=algorithm,
            )
        return file_id

    def download_file(
        self,
        token: str,
        file_id: str,
        output_path: Path | str,
        folder_id: str | None = None,
    ) -> str:
        """Download a file to the given path. Uses mode stored in file metadata. Returns encryption mode used."""
        data, mode = self.get_file_bytes(token, file_id, folder_id=folder_id)
        Path(output_path).write_bytes(data)
        return mode

    def get_file_bytes(
        self,
        token: str,
        file_id: str,
        folder_id: str | None = None,
    ) -> tuple[bytes, str]:
        """Return (file contents, encryption_mode). Mode is read from file metadata for correct key."""
        
        # Ahora el backend devuelve 5 parámetros, incluyendo meta_raw
        data, mode, alg, file, meta_raw = self._storage.download(
            token, file_id, folder_id=folder_id
        )
        
        if mode == "cse":
            if folder_id:
                key = self._kms.get_folder_key(token, folder_id)
            else:
                # === NEW: Envelope Encryption (CSE Personal) ===
                user_id = self._kms.get_user_id_for_token(token)
                wrapped_dek_hex = meta_raw.get("wrapped_dek_hex")
                key_version = meta_raw.get("key_version")
                
                if not wrapped_dek_hex or not key_version:
                    raise StorageError("Missing DEK metadata in CSE file. Cannot decrypt.")
                    
                wrapped_dek = bytes.fromhex(wrapped_dek_hex)
                try:
                    key = self._kms.unwrap_dek(user_id, wrapped_dek, key_version)
                except KMSError as e:
                    raise StorageError(f"Failed to unwrap DEK: {e}")

            try:
                data, metadata = decrypt_bytes(key, data)
            except InvalidTag:
                self.delete_file(token, file_id, folder_id)
                raise StorageError(
                    "File integrity verification failed (AAD/authentication tag mismatch)"
                )
            finally:
                if not folder_id:
                     secure_zero(bytearray(key))

            # If it doesnt raise the exception, the file metadata is correct
            file_aad = metadata.get("filename")
            encryp_aad = metadata.get("encryption_mode")
            alg_aad = metadata.get("algorithm_mode")
            if file is None or file != file_aad:
                self.delete_file(token, file_id, folder_id)
                raise StorageError(
                    f"File .meta was modified in name -> .meta: {file}; Verified: {file_aad}"
                )
            if mode is None or mode != encryp_aad:
                self.delete_file(token, file_id, folder_id)
                raise StorageError(
                    f"File .meta was modified in mode -> .meta: {mode}; Verified: {encryp_aad}"
                )
            if alg is None or alg != alg_aad:
                self.delete_file(token, file_id, folder_id)
                raise StorageError(
                    f"File .meta was modified in encryption algorithm-> .meta: {alg}; Verified: {alg_aad}"
                )
        return (data, mode)

    def delete_file(
        self, token: str, file_id: str, folder_id: str | None = None
    ) -> None:
        """Delete a file. No key material involved."""
        self._storage.delete(token, file_id, folder_id=folder_id)

    def create_shared_folder(self, token: str, name: str | None = None) -> str:
        """Create a shared folder. Returns folder_id. Optional name for display."""
        return self._kms.create_shared_folder(token, name=name)

    def set_folder_name(self, token: str, folder_id: str, name: str) -> None:
        """Set or change the display name of a shared folder."""
        self._kms.set_folder_name(token, folder_id, name)

    def list_shared_folders(self, token: str) -> list[dict]:
        """Return list of {folder_id, name} for folders the user is a member of."""
        return self._kms.list_shared_folders(token)

    def invite_to_shared_folder(
        self, creator_token: str, folder_id: str, username: str
    ) -> None:
        """Invite a user to the shared folder by username. They must accept to get access."""
        self._kms.invite_member(creator_token, folder_id, username)

    def accept_invite(self, token: str, folder_id: str) -> None:
        """Accept a shared folder invite. Gives immediate access (no creator needed)."""
        self._kms.accept_invite(token, folder_id)

    def list_pending_invites(self, token: str) -> list[dict]:
        """List folders you are invited to but have not accepted yet."""
        return self._kms.list_pending_invites(token)

    def list_members(self, token: str, folder_id: str) -> dict:
        """List members of a shared folder. Returns {members: [{user_id, username}, ...], you_are_creator: bool}. Creator is excluded from members."""
        return self._kms.list_members(token, folder_id)

    def remove_member(self, token: str, folder_id: str, username: str) -> None:
        """Remove a member from the shared folder (creator only)."""
        self._kms.remove_member(token, folder_id, username)