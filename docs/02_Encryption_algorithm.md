# 02 — Encryption algorithm implementation

This document describes the **encryption algorithm implementation** of the Secure Cloud Storage system (second version): requirements, types of algorithms, implementation and how it is chosen by the user.

## 1. Requirements covered

### 1.1 Lab and product requirements

| Requirement |
|-------------|
| **Use Fernet AE encryption**: it is implemented using the Fernet algorithm option |
| **Use an AEAD encryption** : This was partially implemented in the previous version of the program. The AAD is incorporated into the original AES-GCM encryption process |
| **Allow 3 different crypto algorithm**: In addition to the other two algorithms mentioned, ChaCha20-poly1305 has been added. The `--alg` option has also been added to the CLI, as well as its equivalent in the web interface. |  


## 2. Encryption Algorithm

| Types | Real Name | Key size | Nonce size | ¿AEAD? | returned blob |
|--------------------------------------------------------|
| `fernet` | Fernet / AES-CBC+HMAC | 32 bytes in base 64 safe url | NO | NO | `fernet|aad|ciphertext` |
| `aesgcm` | AES-GCM | 32 bytes | 12 bytes | Yes | `aesgcm|aad|<nonce>ciphertext` |
| `chacha20` | ChaCha20-poly1305 | 32 bytes | 12 bytes | Yes | `chacha20|aad|<nonce>ciphertext` |

The metadata employed for the AAD consists of two fields: `algorithm` and `encryption_mode`.

## 3. Implementation

### 3.1 Cryptographic Functions

- **Role**: It provides the tools required by the other system components to carry out encryption and decryption across the entire system.
- **Location**: `src/secure_cloud_storage/crypto/`
- **Main operations:** 
    - `secure_zero(buf)`: Overwrite a buffer with zeros to avoid leaving key material in memory.
    - `secure_overwrite_file(path)`: Overwrite file contents with random data before deletion (secure delete).
    - `encrypt_bytes(key, plaintext, algorithm, metadata)`: Encrypt plaintext using the specified algorithm. For AESGCM it will used the metadata to encrypt too. The rest of the algorithm, metadata is used only for blob file. 
    - `decrypt_bytes(key, blob)`: Decrypt a blob produced by encrypt_bytes using the algorithm specified on it.
- **Implemented Changes respect the 01 version:**
    - `algorithm` and `metadata` inputs has been added in `encrypt_bytes`. Depending on the chosen algorithm among the three available types, the corresponding encryption algorithm will be executed. In the case of Fernet, the key will first be converted to the correct format. 
    - The structure of the returned blob varies according to the algorithm, as indicated in the previous section.
    - When the `decrypt_bytes` function is executed, it uses the algorithm stored at the start of the binary file to determine the decryption method. Likewise, if Fernet is used, the key is first converted to the correct type.
    - Now, `decrypt_bytes` returns the data and its metadata. 

### 3.2 Client (application layer)

- **Location**: `src/secure_cloud_storage/client/`
- **Implemented Changes respect the 01 version:**
    - Use of `aesgcm` as the default algorithm for uploading files. This algorithm is sent to the storage to encrypt its files using the same method.

### 3.3 Storage (storage backend)

- **Location**: `src/secure_cloud_storage/storage/`
- **Implemented Changes respect the 01 version:**
    - Use of `aesgcm` as the default algorithm for uploading files.

### 3.4 KMS (Key Management Service)

- **Location**: `src/secure_cloud_storage/kms/`
- **Implemented Changes respect the 01 version:**
    - Use of `fernet` as the default algorithm to encrypt master keys and folder keys.

### 3.5 CLI (Click)

- **Entry:** `uv run python -m secure_cloud_storage`
- **Added Option:** `--alg aesgcm | chacha20 | fernet` (default: aesgcm) for **upload**; download ignores this and uses the algorithm stored in file.

### 3.6 UI (Streamlit)

- **Entry:** `uv run python -m secure_cloud_storage --ui`.  
- **New behaviour:** The encryption algorithm used for file uploads can be selected in the same manner as the SSE and CSE modes. By default, it is selected `aesgcm`.

