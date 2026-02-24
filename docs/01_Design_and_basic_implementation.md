# 01 — Design and basic implementation

This document describes the **design and the implementation** of the Secure Cloud Storage system (first version): requirements, components, key usage (Master Key only).

## 1. Requirements covered

### 1.1 Lab and product requirements

| Requirement |
|-------------|
| Simulated cloud storage (all local; files under e.g. `file_bin/`)
| Client: list, upload, download, delete
| Client: CLI and visual UI (Streamlit); same capabilities; run one at a time
| Storage Server: list, upload, download, delete (as a module, no separate process)
| KMS: key material; one **Master Key (MK)** per user in this version
| User management: username + password
| Basic CLI: login, list, upload, download, delete
| Advanced CLI: `--mode cse\|sse`, shared folders (create, list, invite), help
| Secure deletion of keys: overwrite with zeros/random before delete
| Shared folder: members see all files; encryption preserved on disk
| Encryption mode stored per file (metadata); download uses stored mode

### 1.2 Key types — what is implemented and what is not

| Key type | Description | Implemented in this version? |
|----------|-------------|------------------------------|
| **Master Key (MK)** | One per user. Used to encrypt/decrypt file data (and, in shared folders, to protect the Folder Key). Never stored in plain text; derived at login and provided via session token. | **Yes** |
| **Data Encryption Key (DEK)** | Per-file key used only to encrypt that file’s data. | **No** |
| **Key Encryption Key (KEK)** | Key used to encrypt another key (e.g. to wrap a DEK). | **No** |

In this version, **only the Master Key (MK)** is used and saved in the Key Management Service (KMS) component. File contents (and in shared folders, the Folder Key) are encrypted directly with the MK (or with the Folder Key, which is itself protected by each member’s MK). There is no DEK-per-file and no KEK layer; those can be added in a future version.

## 2. How the Master Key (MK) is used

### 2.1 Lifecycle

1. **Registration**  
   KMS generates a random 32-byte MK for the user. A key is derived from the password (PBKDF2-HMAC-SHA256) and used to encrypt the MK. The encrypted MK is stored in `kms_store/<user_id>/mk.enc`. The MK is never written to disk in plain form.

2. **Login**  
   KMS verifies the password, decrypts the MK into memory, creates a session token, and stores the association token → (user_id, MK) in memory and (for persistence across restarts) in `sessions.json` with the MK encrypted under a key derived from the token.

3. **During session**  
   - **CSE (client-side encryption):** The client calls `KMS.get_key_for_token(token)` to obtain the MK, encrypts data before upload and decrypts after download. The storage only sees ciphertext.  
   - **SSE (server-side encryption):** The client sends plain data; the storage layer calls `KMS.get_key_for_token(token)` (or `get_folder_key(token, folder_id)` for shared folders) to get the key, encrypts on upload and decrypts on download.  
   In both cases the MK (or the Folder Key in shared folders) is only used in memory and never passed as a normal parameter from client to storage; the storage always obtains it from the KMS using the token.

4. **Secure deletion**  
   When a user is deleted (or key material is revoked), the MK buffer and the `mk.enc` file are overwritten with random data (or zeros) before the file is removed. Helpers: `secure_zero()`, `secure_overwrite_file()`.

### 2.2 Where the MK is never stored

- Not in plain form on disk (only encrypted in `mk.enc` and in session data).  
- Not in logs or in UI/CLI parameters.  
- Not sent over the wire (in this design there is no network; everything is in one process).

## 3. Architecture and components

Everything runs in **one process** (no separate server process, no HTTP). The “storage server” is a Python module that reads/writes under `file_bin/`.

```
┌─────────────────────────────────────────────────────────────────┐
│  Single process                                                 │
│  ┌─────────────┐    token     ┌──────────────┐    token         │
│  │   Client    │──────────────│   Storage    ┤ _____            |
│  │ (CLI / UI)  │              │   (module)   │      │           │
│  └──────┬──────┘              └──────┬───────┘      │           │
│         │                            │              │           │
│         │ get_key_for_token          │ get_key_*    │           │
│         │ get_folder_key             │              ▼           │
│         └────────────────────────────┼──────────► ┌─────┐       │
│                                      │            │ KMS │       │
│                                      │            └──▲──┘       │
│                                      │               │          │
│  file_bin/                           │______   kms_store/       │
│  (blobs + .meta)                             (users, MK enc)    │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 KMS (Key Management Service)

- **Role:** User registration and login, MK generation and storage (encrypted), session tokens, and (for shared folders) Folder Key (FK) management.  
- **Location:** `src/secure_cloud_storage/kms/`.  
- **Persistence:** `kms_store/` (configurable):  
  - `users.json`: username → user_id, salt, path to `mk.enc`  
  - `<user_id>/mk.enc`: MK encrypted with password-derived key  
  - `sessions.json`: token → encrypted MK (for session persistence across restarts)  
  - `shared_folders.json`: folder_id → members, FK encrypted per member  
- **Main operations:**  
  - `register(username, password)` → creates user, MK, stores encrypted MK, returns token  
  - `login(username, password)` → returns token; session (and optionally persisted session) holds MK  
  - `get_key_for_token(token)` → returns MK for that session (from memory or by decrypting from sessions.json)  
  - `get_user_id_for_token(token)`, `get_username_for_token(token)` → for storage path and UI display  
  - `get_folder_key(token, folder_id)` → returns Folder Key for shared folder (user must be member)  
  - `create_shared_folder(token)`, `invite_member(creator_token, folder_id, invitee_token)`, `list_shared_folders(token)`  
  - `delete_user(username, password)`: verifies password, then secure wipe of MK and file removal  

No DEK or KEK is used; only MK (and FK for shared folders, protected by MK).

### 3.2 Storage (storage backend)

- **Role:** List, upload, download, delete blobs under `file_bin/`. Never receives keys as parameters; obtains them from the KMS using the session token (and optionally `folder_id` for shared folders).  
- **Location:** `src/secure_cloud_storage/storage/`.  
- **Persistence:**  
  - `file_bin/<user_id>/`: private files (`.blob` + `.meta` per file)  
  - `file_bin/shared/<folder_id>/`: shared folder files (`.blob` + `.meta`)  
- **Per-file metadata (`.meta`):** `filename`, `encryption_mode` (cse | sse). The stored mode is used on download so that the correct key and path (CSE vs SSE) are used even if the system later supports different keys per mode.  
- **Main operations:**  
  - `list_files(token, folder_id=None)` → list of {file_id, filename, encryption_mode}  
  - `upload(token, file_id, data, folder_id=None, filename=..., encryption_mode=...)` → in SSE, storage gets key from KMS and encrypts; in CSE, stores data as-is (already encrypted by client)  
  - `download(token, file_id, folder_id=None)` → reads `encryption_mode` from `.meta`, then returns (plaintext_bytes, mode); in SSE it decrypts using KMS; in CSE it returns the blob and the client decrypts  
  - `delete(token, file_id, folder_id=None)`  

All key access is via KMS (token ± folder_id); no keys are passed in from the client.

### 3.3 Client (application layer)

- **Role:** Orchestrates KMS and storage: login, list, upload, download, delete, shared folders. Implements CSE (encrypt/decrypt in client) and SSE (plain data to/from storage).  
- **Location:** `src/secure_cloud_storage/client/`.  
- **Main operations:**  
  - `register`, `login`, `get_username`  
  - `list_files`, `upload_file`, `download_file`, `get_file_bytes`, `delete_file`  
  - `create_shared_folder`, `list_shared_folders`, `invite_to_shared_folder`, `set_folder_name`  

Upload uses the **current** session’s encryption mode (CSE or SSE) and stores it in file metadata. Download **always** uses the mode stored in the file’s metadata (so the correct key is used and the app can log “File downloaded correctly using &lt;MODE&gt;”).

### 3.4 CLI (Click)

- **Entry:** `uv run python -m secure_cloud_storage`

- **Commands:**  
  - `register <username> -p <password>`, `login <username> -p <password>`, `logout`  
  - `list [--folder <id>]`, `upload <path> [--folder <id>]`, `download <file_id> [-o <path>] [--folder <id>]`, `delete <file_id> [--folder <id>]`  
  - `shared create [--name <name>]`, `shared list`, `shared set-name <folder_id> <name>`, `shared invite <folder_id> <invitee_token>`  
  - `help`  
- **Options:** `--mode cse | sse` (default: cse) for **upload**; download ignores this and uses the mode stored in file metadata.  
- Session token is stored in a file (e.g. `data/.session`) so later invocations can use it.

### 3.5 UI (Streamlit)

- **Entry:** `uv run python -m secure_cloud_storage --ui`.  
- **Behaviour:** Provides all core functionalities available in the CLI, including user login and registration; listing of personal and shared folders; file upload and download; file deletion; and shared folder management (create, list, invite users, and rename). In addition, the interface extends the CLI by exposing contextual information not directly visible there. For file uploads, it allows explicit selection between CSS and SSE; and clearly indicates where the encryption is performed. For downloads, it displays a confirmation message specifying the encryption mode used. The shared folder workflow is also enhanced by making the sharing context more explicit, including visibility of the user’s invitation token (“Your token (for invites)”) and clearer feedback during invite and access operations.

## 4. CSE vs SSE (encryption modes)

- **CSE (Client-Side Encryption):** The client gets the MK (or Folder Key) from the KMS with the token, encrypts data before upload and decrypts after download. The storage only stores and returns opaque blobs; it does not use keys for those files.

- **SSE (Server-Side Encryption):** The client sends plain data to the storage layer. The storage obtains the key from the KMS (via token, and `folder_id` when in a shared folder), encrypts on upload and decrypts on download. The client never sees the key; it only sends/receives plain data.

- **How encryption is executed:**  In both modes, encryption uses **AES-256-GCM** (via the `cryptography` library): a random 12-byte nonce is generated per operation, the plaintext is encrypted with the key (MK or FK), and the result is stored as `nonce + ciphertext + tag`. On download, the stored mode (CSE or SSE) is read from the file’s `.meta`; the same key (MK or FK) is obtained from the KMS using the token (and `folder_id` for shared folders), and decryption is applied by whoever holds the key (client in CSE, storage in SSE). The key is never persisted in plain form; it is only used in memory for the duration of the operation.

In both cases the **same key type** is used in this version (MK, or FK for shared folders). The only difference is **who** applies encryption/decryption (client vs storage). The mode used at upload time is saved in the file’s `.meta` and used again at download so that the correct key and path are used. This design allows a future extension where CSE and SSE use different keys (e.g. DEK/KEK); the stored mode would still determine which key to use.

## 5. Shared folders and Folder Key (FK)

- Each shared folder has a **Folder Key (FK)**. All files in that folder are encrypted with the FK (not with each user’s MK).  
- The FK is stored in the KMS **encrypted with the MK of each member**. So each member can recover the FK using their own MK.  
- **Create:** Creator gets a new FK; it is encrypted with the creator’s MK and stored in `shared_folders.json`.  
- **Invite:** Creator calls `invite_member(creator_token, folder_id, invitee_token)`. The KMS decrypts the FK with the creator’s MK and re-encrypts it with the invitee’s MK (so the invitee must be logged in and provide their token).  
- **List/upload/download** in a shared folder: Storage uses `get_folder_key(token, folder_id)` to get the FK and encrypt/decrypt.  
- Encryption on disk is preserved: only FK-encrypted blobs and FK encrypted per member are stored; no plaintext keys.

## 6. Secure deletion of keys

- Before deleting a user or revoking key material, the code:  
  - Overwrites in-memory key buffers with zeros or random data (`secure_zero`).  
  - Overwrites key files (e.g. `mk.enc`) with random data (`secure_overwrite_file`) before deleting them.  
- This applies to the MK in the KMS and is implemented in the crypto helpers used by the KMS.

## 7. Persistence and layout on disk

- **KMS:** `kms_store/` (users, encrypted MKs, sessions, shared folder metadata).  
- **Storage:** `file_bin/<user_id>/` and `file_bin/shared/<folder_id>/` (each file: `<file_id>.blob`, `<file_id>.meta`).  
- **Session:** One token per session stored in a file (e.g. `data/.session`) so that both CLI and UI can reuse the same session across runs.  
- All of this is configurable via environment variables (see `example.env` and README).