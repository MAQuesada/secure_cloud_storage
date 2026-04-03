# 03 — Key Management Service and Envelope Encryption

This document describes the **KMS architecture and Envelope Encryption implementation** of the Secure Cloud Storage system (third version): requirements, key hierarchy, implementation details, and how the different components interact with the new cryptographic boundaries.

## 1. Requirements covered

### 1.1 Lab and product requirements

| Requirement |
|-------------|
| **Hardware KEK simulation**: Implemented a global Key Encryption Key (KEK) that remains locked until an administrator provides the correct password. All user keys are protected by this KEK. |
| **Key Versioning**: Master Keys (MKs) are now versioned (`keys.json`) to allow key rotation while maintaining access to older files. |
| **Envelope Encryption (AWS KMS style)**: The system never exposes the Master Keys to the client or storage. Instead, it uses a DEK (Data Encryption Key) API to generate, wrap, and unwrap temporary keys for file encryption. |


## 2. Key Hierarchy Architecture

To comply with high-security standards, the system now enforces a strict 3-tier key hierarchy:

| Key Type | Name | Purpose | Protection Method |
|----------|------|---------|-------------------|
| **KEK** | Key Encryption Key | Master lock for the entire KMS. Simulates a Hardware Security Module (HSM). | Encrypted via PBKDF2 derived key from the **Admin Password**. |
| **MK** | Master Key | User-specific key. Versioned to allow rotations. Never leaves the KMS. | Encrypted by the **KEK** using Fernet. |
| **DEK** | Data Encryption Key | Temporary key generated per-file for actual data encryption. | Encrypted (Wrapped) by the user's active **MK** using Fernet. |

The authentication process has also been decoupled from key encryption. User passwords are now only used to generate a secure hash for login verification, not to decrypt their Master Key directly.

## 3. Implementation

### 3.1 KMS (Key Management Service)

- **Role**: The core vault of the system. Generates, wraps, and unwraps keys without exposing sensitive material.
- **Location**: `src/secure_cloud_storage/kms/store.py`
- **Implemented Changes with respect to Version 02:**
    - Replaced in-memory globally accessible MKs with the `_unlocked_kek` hardware simulation pattern. The system must be initialized via `unlock_kek(admin_password)`.
    - Deprecated the insecure `get_key_for_token()` method, converting it into a hard exception (`NotImplementedError: SECURITY BREACH`) to enforce the new DEK API.
    - Implemented the DEK API: `generate_dek(user_id)`, `wrap_dek(user_id, dek)`, and `unwrap_dek(user_id, wrapped_dek, key_version)`.
    - Refactored `register` and `login` to use password hashing instead of using the user's password as the encryption key for the MK.

### 3.2 Client (Application Layer)

- **Location**: `src/secure_cloud_storage/client/service.py`
- **Implemented Changes with respect to Version 02:**
    - In **CSE mode**, the client no longer requests the Master Key. It calls `generate_dek` to obtain a temporary raw DEK and a wrapped DEK.
    - The client encrypts the file locally using the raw DEK.
    - The client securely destroys the raw DEK from memory (`secure_zero`) and sends the encrypted file along with the `wrapped_dek_hex` and `key_version` metadata to the Storage layer.
    - For downloads in CSE mode, it reads the wrapped DEK from the server, calls `unwrap_dek` on the KMS to retrieve the raw DEK, and decrypts the file locally.

### 3.3 Storage (Storage Backend)

- **Location**: `src/secure_cloud_storage/storage/backend.py`
- **Implemented Changes with respect to Version 02:**
    - Modified the `upload` and `download` logic to support Envelope Encryption metadata.
    - In **SSE mode**, the server requests a DEK from the KMS via `generate_dek`, encrypts the incoming plaintext file, and stores the `wrapped_dek_hex` and `key_version` in the `.meta` file.
    - The `.meta` JSON structure was expanded to natively store these two new fields.

### 3.4 Command Line Interface (CLI)

- **Location**: `src/secure_cloud_storage/cli/main.py`
- **Implemented Changes with respect to Version 02:**
    - Integrated the KEK unlock sequence. When the CLI is invoked, it checks for the `KMS_ADMIN_PASSWORD` environment variable. If missing, it uses `click.prompt` to securely request the admin password before initializing the `ClientService`.

### 3.5 User Interface (Streamlit)

- **Location**: `src/secure_cloud_storage/ui/app.py`
- **Implemented Changes with respect to Version 02:**
    - Added a lock screen state. If the KMS is locked, the regular login/register forms are hidden, and an Admin unlock form is presented to the user to initialize the system securely.