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
uv run python src/secure_cloud_storage/main.py
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
uv run python -m secure_cloud_storage shared create
uv run python -m secure_cloud_storage shared list
uv run python -m secure_cloud_storage help
```

Use `--mode cse` or `--mode sse` for encryption mode (default: cse).

**Streamlit UI:**

```bash
uv run python -m secure_cloud_storage --ui
```

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
| `SECURE_STORAGE_SESSION_FILE` | Session token file path |
| `SECURE_STORAGE_KDF_ITERATIONS` | PBKDF2 iterations for key derivation (default: 600000) |

## Documentation

Project documentation will go in the [`docs/`](docs/) folder as the project is developed.

## Python version

The project uses Python 3.11+ (see `pyproject.toml`). UV will use this version when creating the environment.
