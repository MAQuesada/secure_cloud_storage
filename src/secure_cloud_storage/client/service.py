"""Client service: orchestrates KMS + Storage; handles CSE (encrypt/decrypt) and SSE (plain)."""

import uuid
from pathlib import Path
from typing import Literal

from secure_cloud_storage.crypto import encrypt_bytes, decrypt_bytes
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.storage import StorageBackend
from secure_cloud_storage.storage.backend import StorageError

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
        algorithm: EncAlgMode = "aesgcm"
    ) -> str:
        """Upload a file. Returns the assigned file_id."""
        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        file_id = uuid.uuid4().hex
        display_name = filename or path.name
        data = path.read_bytes()
        if encryption_mode == "cse":
            key = (
                self._kms.get_key_for_token(token)
                if not folder_id
                else self._kms.get_folder_key(token, folder_id)
            )
            metadata = {
                "algorithm": algorithm,
                "encryption_mode": encryption_mode,
                "filename": filename,
                # OJOOOOO -> MAYBE IT IS NECESSARY TO PUT KEY_ID HERE OR SOMETHING LIKE THAT IN THE FUTURE
            }
            data = encrypt_bytes(key, data, algorithm, metadata)
            self._storage.upload(
                token,
                file_id,
                data,
                folder_id=folder_id,
                filename=display_name,
                encryption_mode="cse",
                algorithm=algorithm
            )
        else:
            self._storage.upload(
                token,
                file_id,
                data,
                folder_id=folder_id,
                filename=display_name,
                encryption_mode="sse",
                algorithm=algorithm
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
        data, mode = self._storage.download(token, file_id, folder_id=folder_id)
        if mode == "cse":
            key = (
                self._kms.get_key_for_token(token)
                if not folder_id
                else self._kms.get_folder_key(token, folder_id)
            )
            data,_ = decrypt_bytes(key, data)
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
        self, creator_token: str, folder_id: str, invitee_token: str
    ) -> None:
        """Add invitee to the shared folder (invitee must be logged in)."""
        self._kms.invite_member(creator_token, folder_id, invitee_token)
