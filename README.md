# Secure Cloud Storage

A Python project for secure cloud storage.

## Prerequisites

- [UV](https://docs.astral.sh/uv/) — fast Python package installer and resolver

Install UV (if not already installed):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or with pip:

```bash
pip install uv
```

## Managing dependencies with UV

### Create a virtual environment and install dependencies

From the project root:

```bash
uv sync
```

This creates a `.venv`, installs dependencies from `pyproject.toml`, and updates `uv.lock`.

### Add a dependency

```bash
# Production dependency
uv add <package-name>

# Development dependency (e.g. ruff)
uv add --dev <package-name>
```

Example:

```bash
uv add requests
uv add --dev ruff
```

### Remove a dependency

```bash
uv remove <package-name>
```

### Update dependencies

```bash
# Update all packages
uv lock --upgrade

# Then sync the environment
uv sync
```

### Install without modifying lock file

To install exactly what's in `uv.lock` (e.g. in CI):

```bash
uv sync --frozen
```

### Run commands inside the virtual environment

UV can run commands using the project's venv without activating it:

```bash
uv run python -m secure_cloud_storage --help
uv run ruff check .
```

## Development

### Run the application

**CLI (default):**

```bash
uv run python -m secure_cloud_storage --help
uv run python -m secure_cloud_storage register <username> -p <password>
uv run python -m secure_cloud_storage login <username> -p <password>
uv run python -m secure_cloud_storage list
uv run python -m secure_cloud_storage upload <path> [--folder <folder_id>]
uv run python -m secure_cloud_storage download <file_id> [-o <path>]
uv run python -m secure_cloud_storage delete <file_id>
uv run python -m secure_cloud_storage shared create [--name <name>]
uv run python -m secure_cloud_storage shared list
uv run python -m secure_cloud_storage shared set-name <folder_id> <name>
uv run python -m secure_cloud_storage shared invite <folder_id> <username>
uv run python -m secure_cloud_storage shared accept <folder_id>
uv run python -m secure_cloud_storage shared pending
uv run python -m secure_cloud_storage shared members <folder_id>
uv run python -m secure_cloud_storage shared remove-member <folder_id> <username>
uv run python -m secure_cloud_storage help
```

Use `--mode cse` or `--mode sse` for encryption mode (default: cse). Shared folders: only the creator can invite and remove members; invitees accept from **shared pending** to get access.

**Streamlit UI:**

```bash
uv run python -m secure_cloud_storage --ui
```

Each browser tab has its own session, so you can run multiple users at once (e.g. one tab per user to test shared folders).

Or use the installed script (after `uv sync`):

```bash
uv run secure-cloud-storage --help
uv run secure-cloud-storage --ui
```

### Lint and format

```bash
uv run ruff check .
uv run ruff format .
```

## Environment variables

Scripts load variables from a `.env` file (copy `example.env` to `.env` and adjust).

| Variable | Description |
|----------|-------------|
| `SECURE_STORAGE_DATA_ROOT` | Base directory for data (default: project root / `data`) |
| `SECURE_STORAGE_KMS_DIR` | KMS store directory (default: `$DATA_ROOT/kms_store`) |
| `SECURE_STORAGE_FILE_BIN` | File storage directory (default: `$DATA_ROOT/file_bin`) |
| `SECURE_STORAGE_SESSION_FILE` | Session token file path (CLI only; UI uses per-tab session) |
| `SECURE_STORAGE_APP_KEY` | **Required for shared folders.** 64 hex chars (32 bytes). Used so invitees can accept without the creator online. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SECURE_STORAGE_KDF_ITERATIONS` | PBKDF2 iterations for key derivation (default: 600000) |

## Documentation

- [Design and basic implementation](docs/01_Design_and_basic_implementation.md) — architecture, key usage (MK, FK, APP_KEY), CSE/SSE, shared folder flow and security.
- [Encryption algorithm](docs/02_Encryption_algorithm.md) — algorithm and metadata details.

## Python version

The project uses Python 3.11+ (see `pyproject.toml`). UV will use this version when creating the environment.
