"""Key Management Service: user registry, master keys, session tokens, shared folder keys.
Version 02: Hardware KEK simulation, Versioned Master Keys, and DEK API.
"""

import json
import os
import secrets
import uuid
import hmac
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from secure_cloud_storage.config import KDF_ITERATIONS, KMS_STORE_DIR, get_app_key
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

# KEK specific files (Hardware Simulation)
KEK_FILENAME = "kek.enc"
KEK_SALT_FILE = ".kek_salt"
USER_KEYS_FILE = "keys.json"  # Stores versioned MKs for a user

DEFAULT_ENCRYPTED_ALG_LOGIN = "fernet"
DEFAULT_METADATA_LOGIN = {
    "encryption_mode": "sse",
    "algorithm_mode": DEFAULT_ENCRYPTED_ALG_LOGIN,
}
DEFAULT_ENC_ALG_SHARED_FOLDER = "fernet"
DEFAULT_METADATA_SHARED_FOLDER = {
    "encryption_mode": "sse",
    "algorithm_mode": DEFAULT_ENC_ALG_SHARED_FOLDER,
}


class KMSError(Exception):
    """Raised when a KMS operation fails (auth, not found, locked KEK, etc.)."""
    pass


class KMS:
    """Key Management Service: Hardware KEK simulation, DEK API, shared folder keys.
    All Master Keys are encrypted by the KEK. The KEK must be unlocked by an admin.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self._store_dir = Path(store_dir) if store_dir else KMS_STORE_DIR
        self._users_path = self._store_dir / USERS_FILE
        self._shared_path = self._store_dir / SHARED_FOLDERS_FILE
        self._sessions_path = self._store_dir / SESSIONS_FILE
        self._kek_path = self._store_dir / KEK_FILENAME
        self._kek_salt_path = self._store_dir / KEK_SALT_FILE
        
        # token -> user_id (We no longer keep MKs in memory globally to increase security)
        self._sessions: dict[str, str] = {}
        
        # Hardware KEK simulation: Kept in memory only when unlocked
        self._unlocked_kek: bytearray | None = None
        
        self._ensure_store()
        self._load_persisted_sessions()

    def _ensure_store(self) -> None:
        self._store_dir.mkdir(parents=True, exist_ok=True)
        if not self._users_path.exists():
            self._write_json(self._users_path, {})
        if not self._shared_path.exists():
            self._write_json(self._shared_path, {})
        if not self._sessions_path.exists():
            self._write_json(self._sessions_path, {})
        if not self._kek_salt_path.is_file():
            self._kek_salt_path.write_bytes(os.urandom(16))

    # ---------- KEK Management (Hardware Simulation) ----------

    def unlock_kek(self, admin_password: str) -> None:
        """Unlocks the KEK. If it doesn't exist, generates and encrypts it."""
        salt = self._kek_salt_path.read_bytes()
        derived_admin_key = self._derive_key(admin_password, salt)
        
        if not self._kek_path.exists():
            # Generate KEK for the first time
            raw_kek = secrets.token_bytes(KEY_BYTES)
            kek_enc = encrypt_bytes(derived_admin_key, raw_kek, "fernet", {})
            self._kek_path.write_bytes(kek_enc)
            self._unlocked_kek = bytearray(raw_kek)
        else:
            # Decrypt existing KEK
            kek_enc = self._kek_path.read_bytes()
            try:
                raw_kek, _ = decrypt_bytes(derived_admin_key, kek_enc)
                self._unlocked_kek = bytearray(raw_kek)
            except Exception:
                raise KMSError("Invalid admin password. KEK remains locked.")
                
    def lock_kek(self) -> None:
        """Locks the KEK by securely wiping it from memory."""
        if self._unlocked_kek:
            secure_zero(self._unlocked_kek)
            self._unlocked_kek = None

    def _require_kek(self) -> None:
        if not self._unlocked_kek:
            raise KMSError("KMS is locked. Administrator must unlock the KEK first.")

    # ---------- Internal Helpers ----------

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

    def _load_persisted_sessions(self) -> None:
        sessions = self._read_json(self._sessions_path)
        for token, rec in sessions.items():
            self._sessions[token] = rec["user_id"]

    def _save_session(self, token: str, user_id: str) -> None:
        sessions = self._read_json(self._sessions_path)
        sessions[token] = {"user_id": user_id}
        self._write_json(self._sessions_path, sessions)

    def _get_mk(self, user_id: str, version: int | None = None) -> bytearray:
        """Retrieves and decrypts a specific Master Key for a user using the KEK."""
        self._require_kek()
        keys_path = self._store_dir / user_id / USER_KEYS_FILE
        if not keys_path.exists():
            raise KMSError("Master Keys not found for user")
            
        keys_data = self._read_json(keys_path)
        target_mk_enc_hex = None
        
        for key_record in keys_data:
            if version is not None:
                if key_record["version"] == version:
                    target_mk_enc_hex = key_record["mk_enc_hex"]
                    break
            else:
                if key_record["status"] == "active":
                    target_mk_enc_hex = key_record["mk_enc_hex"]
                    break
                    
        if not target_mk_enc_hex:
            raise KMSError(f"Master Key (version={version or 'active'}) not found")
            
        mk_enc = bytes.fromhex(target_mk_enc_hex)
        mk_raw, _ = decrypt_bytes(self._unlocked_kek, mk_enc)
        return bytearray(mk_raw)

    # ---------- User Registration & Auth ----------

    def register(self, username: str, password: str) -> str:
        """Registers a user, generates MK v1 protected by KEK, and saves pwd hash."""
        self._require_kek()
        users = self._read_json(self._users_path)
        if username in users:
            raise KMSError(f"User already exists: {username}")
            
        user_id = uuid.uuid4().hex
        salt = os.urandom(16)
        
        # Derive key to act as a password hash for login verification
        pwd_hash = self._derive_key(password, salt)
        
        # Generate Master Key
        mk = bytearray(secrets.token_bytes(KEY_BYTES))
        try:
            # Encrypt MK with KEK (NOT with user password)
            mk_enc = encrypt_bytes(self._unlocked_kek, bytes(mk), "fernet", {})
            
            user_dir = self._store_dir / user_id
            user_dir.mkdir(parents=True, exist_ok=True)
            
            keys_data = [{
                "version": 1,
                "mk_enc_hex": mk_enc.hex(),
                "status": "active"
            }]
            self._write_json(user_dir / USER_KEYS_FILE, keys_data)
            
            users[username] = {
                "user_id": user_id,
                "salt_hex": salt.hex(),
                "pwd_hash_hex": pwd_hash.hex(),
            }
            self._write_json(self._users_path, users)
            
            token = secrets.token_urlsafe(32)
            self._sessions[token] = user_id
            self._save_session(token, user_id)
            return token
        finally:
            secure_zero(mk)

    def login(self, username: str, password: str) -> str:
        """Verifies password hash and creates a session token."""
        self._require_kek()
        users = self._read_json(self._users_path)
        if username not in users:
            raise KMSError("Invalid username or password")
            
        rec = users[username]
        user_id = rec["user_id"]
        salt = bytes.fromhex(rec["salt_hex"])
        expected_hash = bytes.fromhex(rec["pwd_hash_hex"])
        
        actual_hash = self._derive_key(password, salt)
        if not hmac.compare_digest(expected_hash, actual_hash):
            raise KMSError("Invalid username or password")
            
        token = secrets.token_urlsafe(32)
        self._sessions[token] = user_id
        self._save_session(token, user_id)
        return token

    # ---------- DEK API (The Core Requirement) ----------

    def get_key_version(self, user_id: str) -> int:
        """Returns the version number of the user's currently active Master Key."""
        keys_path = self._store_dir / user_id / USER_KEYS_FILE
        keys_data = self._read_json(keys_path)
        for key_record in keys_data:
            if key_record["status"] == "active":
                return key_record["version"]
        raise KMSError("No active key found")

    def generate_dek(self, user_id: str) -> tuple[bytes, bytes]:
        """Generates a new DEK. Returns (raw_dek, wrapped_dek)."""
        raw_dek = secrets.token_bytes(KEY_BYTES)
        wrapped_dek = self.wrap_dek(user_id, raw_dek)
        return raw_dek, wrapped_dek

    def wrap_dek(self, user_id: str, dek: bytes) -> bytes:
        """Wraps a DEK using the user's ACTIVE Master Key."""
        active_version = self.get_key_version(user_id)
        mk = self._get_mk(user_id, version=active_version)
        try:
            # Wrap DEK using Fernet and store the MK version in metadata
            wrapped_dek = encrypt_bytes(mk, dek, "fernet", {"version": active_version})
            return wrapped_dek
        finally:
            secure_zero(mk)

    def unwrap_dek(self, user_id: str, wrapped_dek: bytes, key_version: int) -> bytes:
        """Unwraps a DEK using the specified version of the user's Master Key."""
        mk = self._get_mk(user_id, version=key_version)
        try:
            raw_dek, _ = decrypt_bytes(mk, wrapped_dek)
            return raw_dek
        finally:
            secure_zero(mk)

    def rotate_master_key(self, user_id: str) -> None:
        """Generates a new MK, sets it as active, and archives the old one."""
        self._require_kek()
        keys_path = self._store_dir / user_id / USER_KEYS_FILE
        keys_data = self._read_json(keys_path)
        
        max_version = 0
        for key_record in keys_data:
            key_record["status"] = "old"
            if key_record["version"] > max_version:
                max_version = key_record["version"]
                
        new_mk = bytearray(secrets.token_bytes(KEY_BYTES))
        try:
            new_mk_enc = encrypt_bytes(self._unlocked_kek, bytes(new_mk), "fernet", {})
            keys_data.append({
                "version": max_version + 1,
                "mk_enc_hex": new_mk_enc.hex(),
                "status": "active"
            })
            self._write_json(keys_path, keys_data)
        finally:
            secure_zero(new_mk)

    def get_key_for_token(self, token: str) -> bytes:
        """DEPRECATED: Client/Storage should use generate_dek/wrap_dek/unwrap_dek."""
        raise NotImplementedError("SECURITY BREACH: Master Keys must never leave the KMS. Use the DEK API instead.")

    # ---------- Token Utilities & Secure Deletion ----------

    def get_user_id_for_token(self, token: str) -> str:
        if token in self._sessions:
            return self._sessions[token]
        raise KMSError("Invalid or expired token")

    def get_username_for_token(self, token: str) -> str | None:
        user_id = self.get_user_id_for_token(token)
        users = self._read_json(self._users_path)
        for username, rec in users.items():
            if rec.get("user_id") == user_id:
                return username
        return None

    def revoke_token(self, token: str) -> None:
        if token in self._sessions:
            del self._sessions[token]
        sessions = self._read_json(self._sessions_path)
        if token in sessions:
            del sessions[token]
            self._write_json(self._sessions_path, sessions)

    def delete_user(self, username: str, password: str) -> None:
        """Securely deletes user, wiping all versioned Master Keys."""
        self._require_kek()
        users = self._read_json(self._users_path)
        if username not in users:
            raise KMSError("User not found")
            
        rec = users[username]
        salt = bytes.fromhex(rec["salt_hex"])
        expected_hash = bytes.fromhex(rec["pwd_hash_hex"])
        actual_hash = self._derive_key(password, salt)
        
        if not hmac.compare_digest(expected_hash, actual_hash):
            raise KMSError("Invalid password")
            
        user_id = rec["user_id"]
        keys_path = self._store_dir / user_id / USER_KEYS_FILE
        
        # Securely wipe the keys file
        if keys_path.is_file():
            secure_overwrite_file(keys_path)
            keys_path.unlink()
            
        user_dir = keys_path.parent
        if user_dir.is_dir():
            for p in user_dir.iterdir():
                p.unlink()
            user_dir.rmdir()
            
        del users[username]
        self._write_json(self._users_path, users)
        
        # Revoke sessions
        for t, uid in list(self._sessions.items()):
            if uid == user_id:
                del self._sessions[t]

    # ---------- Shared folders ----------
    # Using internal _get_mk to preserve functionality without exposing MKs

    def create_shared_folder(self, token: str, name: str | None = None) -> str:
        user_id = self.get_user_id_for_token(token)
        mk = self._get_mk(user_id) # Gets active MK
        try:
            folder_id = uuid.uuid4().hex
            fk = os.urandom(KEY_BYTES)
            fk_enc = encrypt_bytes(
                mk, fk, DEFAULT_ENC_ALG_SHARED_FOLDER, DEFAULT_METADATA_SHARED_FOLDER
            )
            app_key = get_app_key()
            fk_app_enc = encrypt_bytes(
                app_key, fk, DEFAULT_ENC_ALG_SHARED_FOLDER, DEFAULT_METADATA_SHARED_FOLDER
            )
            folders = self._read_json(self._shared_path)
            folders[folder_id] = {
                "creator_id": user_id,
                "members": [user_id],
                "fk_encrypted": {user_id: fk_enc.hex()},
                "fk_app_enc": fk_app_enc.hex(),
                "name": (name or "").strip() or None,
            }
            self._write_json(self._shared_path, folders)
            return folder_id
        finally:
            secure_zero(mk)

    def set_folder_name(self, token: str, folder_id: str, name: str) -> None:
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        if user_id not in folders[folder_id].get("members", []):
            raise KMSError("Not a member of this shared folder")
        folders[folder_id]["name"] = (name or "").strip() or None
        self._write_json(self._shared_path, folders)

    def get_folder_key(self, token: str, folder_id: str) -> bytes:
        user_id = self.get_user_id_for_token(token)
        mk = self._get_mk(user_id)
        try:
            folders = self._read_json(self._shared_path)
            if folder_id not in folders:
                raise KMSError("Shared folder not found")
            meta = folders[folder_id]
            members = meta.get("members", [])
            fk_encrypted = meta.get("fk_encrypted", {})
            if user_id not in members or user_id not in fk_encrypted:
                raise KMSError("Not a member of this shared folder")
            fk_enc = bytes.fromhex(fk_encrypted[user_id])
            fk, _ = decrypt_bytes(mk, fk_enc)
            return fk
        finally:
            secure_zero(mk)

    def _username_to_user_id(self, username: str) -> str:
        users = self._read_json(self._users_path)
        if username not in users:
            raise KMSError(f"User not found: {username}")
        return users[username]["user_id"]

    def _user_id_to_username(self, user_id: str) -> str | None:
        users = self._read_json(self._users_path)
        for uname, rec in users.items():
            if rec.get("user_id") == user_id:
                return uname
        return None

    def invite_member(self, creator_token: str, folder_id: str, username: str) -> None:
        creator_id = self.get_user_id_for_token(creator_token)
        invitee_id = self._username_to_user_id(username)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        meta = folders[folder_id]
        creator = meta.get("creator_id") or (meta["members"][0] if meta.get("members") else None)
        if creator != creator_id:
            raise KMSError("Only the creator can invite members")
        if invitee_id in meta.get("members", []):
            raise KMSError("User is already a member")
        meta.setdefault("members", []).append(invitee_id)
        self._write_json(self._shared_path, folders)

    def accept_invite(self, invitee_token: str, folder_id: str) -> None:
        invitee_id = self.get_user_id_for_token(invitee_token)
        invitee_mk = self._get_mk(invitee_id)
        try:
            folders = self._read_json(self._shared_path)
            if folder_id not in folders:
                raise KMSError("Shared folder not found")
            meta = folders[folder_id]
            if invitee_id not in meta.get("members", []):
                raise KMSError("You are not invited to this folder")
            if invitee_id in meta.get("fk_encrypted", {}):
                return  
            fk_app_enc_hex = meta.get("fk_app_enc")
            if not fk_app_enc_hex:
                raise KMSError("Folder was created before app-key support; cannot accept. Ask creator to re-create the folder.")
            app_key = get_app_key()
            fk, _ = decrypt_bytes(app_key, bytes.fromhex(fk_app_enc_hex))
            fk_enc_invitee = encrypt_bytes(
                invitee_mk,
                fk,
                DEFAULT_ENC_ALG_SHARED_FOLDER,
                DEFAULT_METADATA_SHARED_FOLDER,
            )
            meta.setdefault("fk_encrypted", {})[invitee_id] = fk_enc_invitee.hex()
            self._write_json(self._shared_path, folders)
        finally:
            secure_zero(invitee_mk)

    def list_pending_invites(self, token: str) -> list[dict]:
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        pending = []
        for fid, meta in folders.items():
            if user_id not in meta.get("members", []):
                continue
            if user_id in meta.get("fk_encrypted", {}):
                continue
            pending.append({"folder_id": fid, "name": meta.get("name") or fid})
        return pending

    def list_members(self, token: str, folder_id: str) -> dict:
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        meta = folders[folder_id]
        if user_id not in meta.get("members", []):
            raise KMSError("Not a member of this shared folder")
        creator = meta.get("creator_id") or (meta["members"][0] if meta.get("members") else None)
        members = [
            {"user_id": uid, "username": self._user_id_to_username(uid) or uid}
            for uid in meta.get("members", [])
            if uid != creator
        ]
        return {"members": members, "you_are_creator": (creator == user_id)}

    def remove_member(self, token: str, folder_id: str, username: str) -> None:
        creator_id = self.get_user_id_for_token(token)
        to_remove_id = self._username_to_user_id(username)
        folders = self._read_json(self._shared_path)
        if folder_id not in folders:
            raise KMSError("Shared folder not found")
        meta = folders[folder_id]
        creator = meta.get("creator_id") or (meta["members"][0] if meta.get("members") else None)
        if creator != creator_id:
            raise KMSError("Only the creator can remove members")
        if to_remove_id == creator_id:
            raise KMSError("Creator cannot remove themselves")
        if to_remove_id not in meta.get("members", []):
            raise KMSError("User is not a member")
        meta["members"] = [m for m in meta["members"] if m != to_remove_id]
        meta.get("fk_encrypted", {}).pop(to_remove_id, None)
        self._write_json(self._shared_path, folders)

    def list_shared_folders(self, token: str) -> list[dict]:
        user_id = self.get_user_id_for_token(token)
        folders = self._read_json(self._shared_path)
        return [
            {"folder_id": fid, "name": meta.get("name") or fid}
            for fid, meta in folders.items()
            if user_id in meta.get("fk_encrypted", {})
        ]