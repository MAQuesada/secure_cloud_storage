"""Key Management Service: user registry, master keys, session tokens, shared folder keys."""

import json
import os
import secrets
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from secure_cloud_storage.config import KDF_ITERATIONS, KMS_STORE_DIR
from secure_cloud_storage.crypto import (
    decrypt_bytes,
    encrypt_bytes,
    secure_overwrite_file,
    secure_zero,
)
from secure_cloud_storage.crypto.utils import KEY_BYTES

USERS_FILE = "users.json"
SHARED_FOLDERS_FILE = "shared_folders.json"
SESSIONS_FILE = "sessions.json"
SESSION_SALT_FILE = ".session_salt"
MK_FILENAME = "mk.enc"


class KMSError(Exception):
    """Raised when a KMS operation fails (auth, not found, etc.)."""

    pass


class KMS:
    """Key Management Service: register, login, master keys, shared folder keys.

    All keys are stored encrypted. Session tokens map to (user_id, mk_bytes) in memory.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self._store_dir = Path(store_dir) if store_dir else KMS_STORE_DIR
        self._users_path = self._store_dir / USERS_FILE
        self._shared_path = self._store_dir / SHARED_FOLDERS_FILE
        self._sessions_path = self._store_dir / SESSIONS_FILE
        self._session_salt_path = self._store_dir / SESSION_SALT_FILE
        # token -> (user_id, mk_bytes) in memory; also persisted encrypted in sessions file
        self._sessions: dict[str, tuple[str, bytearray]] = {}
        self._ensure_store()

    def _ensure_store(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        if not self._users_path.exists():
            self._write_json(self._users_path, {})
        if not self._shared_path.exists():
            self._write_json(self._shared_path, {})
        if not self._sessions_path.exists():
            self._write_json(self._sessions_path, {})
        if not self._session_salt_path.is_file():
            self._session_salt_path.write_bytes(os.urandom(16))

    def _derive_session_key(self, token: str) -> bytes:
        """Derive key from token for encrypting MK in session file."""
        salt = self._session_salt_path.read_bytes()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(token.encode("utf-8"))

    def _load_session_mk(self, token: str) -> tuple[str, bytes]:
        """Load user_id and MK from session file (persisted across restarts)."""
        sessions = self._read_json(self._sessions_path)
        if token not in sessions:
            raise KMSError("Invalid or expired token")
        rec = sessions[token]
        user_id = rec["user_id"]
        mk_enc = bytes.fromhex(rec["mk_enc_hex"])
        key = self._derive_session_key(token)
        mk = decrypt_bytes(key, mk_enc)
        return user_id, mk

    def _save_session(self, token: str, user_id: str, mk: bytes) -> None:
        """Persist session: MK encrypted with key derived from token."""
        key = self._derive_session_key(token)
        mk_enc = encrypt_bytes(key, mk)
        sessions = self._read_json(self._sessions_path)
        sessions[token] = {"user_id": user_id, "mk_enc_hex": mk_enc.hex()}
        self._write_json(self._sessions_path, sessions)

    def _read_json(self, path: Path) -> dict[str, Any]:
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def register(self, username: str, password: str) -> str:
        """Register a new user: create master key, encrypt with password-derived key, persist.

        Returns the session token for immediate use (same as login after register).
        """
        users = self._read_json(self._users_path)
        if username in users:
            raise KMSError(f"User already exists: {username}")
        user_id = uuid.uuid4().hex
        salt = os.urandom(16)
        mk = bytearray(secrets.token_bytes(KEY_BYTES))
        try:
            key = self._derive_key(password, salt)
            mk_enc = encrypt_bytes(key, bytes(mk))
            user_dir = self._store_dir / user_id
            user_dir.mkdir(parents=True, exist_ok=True)
            mk_path = user_dir / MK_FILENAME
            with open(mk_path, "wb") as f:
                f.write(mk_enc)
            users[username] = {
                "user_id": user_id,
                "salt_hex": salt.hex(),
                "mk_path": str(mk_path.relative_to(self._store_dir)),
            }
            self._write_json(self._users_path, users)
            token = secrets.token_urlsafe(32)
            self._sessions[token] = (user_id, mk)
            self._save_session(token, user_id, bytes(mk))
            return token
        finally:
            secure_zero(mk)

    def login(self, username: str, password: str) -> str:
        """Verify password, decrypt master key, create session token. Returns token."""
        users = self._read_json(self._users_path)
        if username not in users:
            raise KMSError("Invalid username or password")
        rec = users[username]
        user_id = rec["user_id"]
        salt = bytes.fromhex(rec["salt_hex"])
        mk_path = self._store_dir / rec["mk_path"]
        if not mk_path.is_file():
            raise KMSError("Key store corrupted")
        key = self._derive_key(password, salt)
        with open(mk_path, "rb") as f:
            mk_enc = f.read()
        try:
            mk = bytearray(decrypt_bytes(key, mk_enc))
        except Exception:
            raise KMSError("Invalid username or password")
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (user_id, mk)
        self._save_session(token, user_id, bytes(mk))
        return token

    def get_key_for_token(self, token: str) -> bytes:
        """Return a copy of the master key for this session. Caller must not persist it."""
        if token in self._sessions:
            _, mk = self._sessions[token]
            return bytes(mk)
        user_id, mk = self._load_session_mk(token)
        return mk

    def get_user_id_for_token(self, token: str) -> str:
        """Resolve session token to user_id (for Storage to know which directory to use)."""
        if token in self._sessions:
            user_id, _ = self._sessions[token]
            return user_id
        user_id, _ = self._load_session_mk(token)
        return user_id

    def get_username_for_token(self, token: str) -> str | None:
        """Resolve session token to username (for display in UI). Returns None if not found."""
        user_id = self.get_user_id_for_token(token)
        users = self._read_json(self._users_path)
        for username, rec in users.items():
            if rec.get("user_id") == user_id:
                return username
        return None

    def revoke_token(self, token: str) -> None:
        """Invalidate a session: overwrite in-memory MK and remove from session file."""
        if token in self._sessions:
            _, mk = self._sessions[token]
            secure_zero(mk)
            del self._sessions[token]
        sessions = self._read_json(self._sessions_path)
        if token in sessions:
            del sessions[token]
            self._write_json(self._sessions_path, sessions)

    def delete_user(self, username: str, password: str) -> None:
        """Securely delete user: overwrite MK file with random data, then remove. Requires password."""
        users = self._read_json(self._users_path)
        if username not in users:
            raise KMSError("User not found")
        rec = users[username]
        salt = bytes.fromhex(rec["salt_hex"])
        key = self._derive_key(password, salt)
        mk_path = self._store_dir / rec["mk_path"]
        if mk_path.is_file():
            with open(mk_path, "rb") as f:
                mk_enc = f.read()
            try:
                decrypt_bytes(key, mk_enc)
            except Exception:
                raise KMSError("Invalid password")
            blob = bytearray(mk_enc)
            secure_zero(blob)
            secure_overwrite_file(mk_path)
            mk_path.unlink()
        user_dir = mk_path.parent
        if user_dir.is_dir():
            for p in user_dir.iterdir():
                p.unlink()
            user_dir.rmdir()
        del users[username]
        self._write_json(self._users_path, users)
        # Revoke any session for this user
        user_id = rec["user_id"]
        for t, (uid, mk) in list(self._sessions.items()):
            if uid == user_id:
                secure_zero(mk)
                del self._sessions[t]

    # ---------- Shared folders ----------

    def create_shared_folder(self, token: str, name: str | None = None) -> str:
        """Create a shared folder; creator gets FK encrypted with their MK. Returns folder_id."""
        user_id = self.get_user_id_for_token(token)
        mk = self.get_key_for_token(token)
        folder_id = uuid.uuid4().hex
        fk = os.urandom(KEY_BYTES)
        fk_enc = encrypt_bytes(mk, fk)
        folders = self._read_json(self._shared_path)
        folders[folder_id] = {
            "members": [user_id],
            "fk_encrypted": {user_id: fk_enc.hex()},
            "name": (name or "").strip() or None,
        }
        self._write_json(self._shared_path, folders)
        return folder_id

    def set_folder_name(self, token: str, folder_id: str, name: str) -> None:
        """Set or change the display name of a shared folder (creator or member)."""
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        if user_id not in folders[folder_id].get("members", []):
            raise KMSError("Not a member of this shared folder")
        folders[folder_id]["name"] = (name or "").strip() or None
        self._write_json(self._shared_path, folders)

    def get_folder_key(self, token: str, folder_id: str) -> bytes:
        """Return the folder key (FK) for this user. User must be a member."""
        user_id = self.get_user_id_for_token(token)
        mk = self.get_key_for_token(token)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        meta = folders[folder_id]
        members = meta.get("members", [])
        fk_encrypted = meta.get("fk_encrypted", {})
        if user_id not in members or user_id not in fk_encrypted:
            raise KMSError("Not a member of this shared folder")
        fk_enc = bytes.fromhex(fk_encrypted[user_id])
        return decrypt_bytes(mk, fk_enc)

    def invite_member(self, creator_token: str, folder_id: str, invitee_token: str) -> None:
        """Add invitee to shared folder: decrypt FK with creator MK, encrypt with invitee MK."""
        creator_id = self.get_user_id_for_token(creator_token)
        invitee_id = self.get_user_id_for_token(invitee_token)
        creator_mk = self.get_key_for_token(creator_token)
        invitee_mk = self.get_key_for_token(invitee_token)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        meta = folders[folder_id]
        if creator_id not in meta.get("members", []):
            raise KMSError("Only the creator can invite members")
        if invitee_id in meta.get("members", []):
            return
        fk_enc_creator = meta["fk_encrypted"][creator_id]
        fk = decrypt_bytes(creator_mk, bytes.fromhex(fk_enc_creator))
        fk_enc_invitee = encrypt_bytes(invitee_mk, fk)
        meta.setdefault("members", []).append(invitee_id)
        meta.setdefault("fk_encrypted", {})[invitee_id] = fk_enc_invitee.hex()
        self._write_json(self._shared_path, folders)

    def list_shared_folders(self, token: str) -> list[dict]:
        """Return folder_ids and display names for which the user is a member."""
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        return [
            {"folder_id": fid, "name": meta.get("name") or fid}
            for fid, meta in folders.items()
            if user_id in meta.get("members", [])
        ]
