"""Click CLI: login, register, list, upload, download, delete, shared, help."""

from pathlib import Path

import click

from secure_cloud_storage.client import ClientService
from secure_cloud_storage.config import FILE_BIN_DIR, KMS_STORE_DIR, SESSION_FILE
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.storage import StorageBackend
from secure_cloud_storage.storage.backend import StorageError

EncryptionMode = str  # "cse" | "sse"
EncAlgMode = str # "aesgcm" | "chacha20" | "fernet"


def _get_app() -> ClientService:
    """Build KMS + Storage + ClientService (same process, no network)."""
    kms = KMS(store_dir=KMS_STORE_DIR)
    storage = StorageBackend(file_bin_dir=FILE_BIN_DIR, kms=kms)
    return ClientService(kms=kms, storage=storage)


def _read_token() -> str | None:
    """Read session token from file. Returns None if not logged in."""
    if not SESSION_FILE.is_file():
        return None
    try:
        return SESSION_FILE.read_text().strip() or None
    except OSError:
        return None


def _write_token(token: str) -> None:
    """Persist session token to file."""
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(token)


def _clear_token() -> None:
    """Remove session file."""
    if SESSION_FILE.is_file():
        SESSION_FILE.unlink()


def _require_token(ctx: click.Context) -> str:
    """Get current token or fail with a message."""
    token = _read_token()
    if not token:
        raise click.ClickException("Not logged in. Run: login <username> <password>")
    return token


def _get_ctx_obj(ctx: click.Context) -> dict:
    """Get the root context obj (app, mode) for use in subcommands."""
    root = ctx.find_root()
    return root.obj or {}


@click.group()
@click.option(
    "--mode",
    type=click.Choice(["cse", "sse"], case_sensitive=False),
    default="cse",
    help="Encryption mode: cse (client-side) or sse (server-side).",
)
@click.option(
    "--alg",
    type=click.Choice(["aesgcm", "chacha20", "fernet"], case_sensitive=False),
    default="aesgcm",
    help="Encryption algorithm: aesgcm, chacha20 or fernet",
)
@click.pass_context
def cli(ctx: click.Context, mode: str, alg: str) -> None:
    """Secure Cloud Storage — list, upload, download, delete; CSE/SSE; AES-GCM/ChaCha20/fernet; shared folders."""
    ctx.ensure_object(dict)
    ctx.obj["mode"] = mode.lower()
    ctx.obj["alg"] = alg.lower()
    ctx.obj["app"] = _get_app()


@cli.command()
@click.argument("username", type=str)
@click.option("--password", "-p", prompt=True, hide_input=True, help="User password.")
def register(username: str, password: str) -> None:
    """Register a new user and log in. Stores session token."""
    app = _get_app()
    try:
        token = app.register(username, password)
        _write_token(token)
        click.echo("Registered and logged in.")
    except KMSError as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("username", type=str)
@click.option("--password", "-p", prompt=True, hide_input=True, help="User password.")
def login(username: str, password: str) -> None:
    """Log in and store session token for subsequent commands."""
    app = _get_app()
    try:
        token = app.login(username, password)
        _write_token(token)
        click.echo("Logged in.")
    except KMSError as e:
        raise click.ClickException(str(e))


@cli.command()
def logout() -> None:
    """Clear the stored session token."""
    _clear_token()
    click.echo("Logged out.")


@cli.command("list")
@click.option("--folder", "folder_id", default=None, help="Shared folder ID to list.")
@click.pass_context
def list_files(ctx: click.Context, folder_id: str | None) -> None:
    """List files (personal or in a shared folder)."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        files = app.list_files(token, folder_id=folder_id)
        if not files:
            click.echo("No files.")
            return
        for f in files:
            click.echo(f"{f['file_id']}  {f['filename']}")
    except (KMSError, StorageError) as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("path", type=click.Path(path_type=Path, exists=True, file_okay=True, dir_okay=False))
@click.option("--folder", "folder_id", default=None, help="Shared folder ID to upload into.")
@click.pass_context
def upload(ctx: click.Context, path: Path, folder_id: str | None) -> None:
    """Upload a file. Returns the assigned file_id."""
    token = _require_token(ctx)
    obj = _get_ctx_obj(ctx)
    mode: EncryptionMode = obj["mode"]
    alg: EncAlgMode = obj["alg"]
    app: ClientService = obj["app"]
    try:
        file_id = app.upload_file(token, path, folder_id=folder_id, encryption_mode=mode, algorithm=alg)
        click.echo(f"Uploaded: {file_id}")
    except (KMSError, StorageError, FileNotFoundError) as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("file_id", type=str)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None, help="Output path.")
@click.option("--folder", "folder_id", default=None, help="Shared folder ID.")
@click.pass_context
def download(ctx: click.Context, file_id: str, output: Path | None, folder_id: str | None) -> None:
    """Download a file by file_id. Uses the mode stored when the file was uploaded."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    out = output or Path(file_id)
    try:
        mode = app.download_file(token, file_id, out, folder_id=folder_id)
        click.echo(f"Downloaded to {out}")
        click.echo(f"File downloaded correctly using {mode.upper()}")
    except (KMSError, StorageError) as e:
        raise click.ClickException(str(e))


@cli.command()
@click.argument("file_id", type=str)
@click.option("--folder", "folder_id", default=None, help="Shared folder ID.")
@click.pass_context
def delete(ctx: click.Context, file_id: str, folder_id: str | None) -> None:
    """Delete a file by file_id."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        app.delete_file(token, file_id, folder_id=folder_id)
        click.echo("Deleted.")
    except (KMSError, StorageError) as e:
        raise click.ClickException(str(e))


@cli.group()
def shared() -> None:
    """Shared folder commands: create, list, invite."""
    pass


@shared.command("create")
@click.option("--name", "-n", default=None, help="Display name for the folder.")
@click.pass_context
def shared_create(ctx: click.Context, name: str | None) -> None:
    """Create a shared folder. Prints folder_id for sharing."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        folder_id = app.create_shared_folder(token, name=name)
        click.echo(f"Created shared folder: {folder_id}" + (f" ({name})" if name else ""))
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("list")
@click.pass_context
def shared_list(ctx: click.Context) -> None:
    """List shared folders you are a member of (folder_id and name)."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        folders = app.list_shared_folders(token)
        if not folders:
            click.echo("No shared folders.")
            return
        for f in folders:
            click.echo(f"{f['folder_id']}  {f['name']}")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("set-name")
@click.argument("folder_id", type=str)
@click.argument("name", type=str)
@click.pass_context
def shared_set_name(ctx: click.Context, folder_id: str, name: str) -> None:
    """Set or change the display name of a shared folder."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        app.set_folder_name(token, folder_id, name)
        click.echo("Name updated.")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("invite")
@click.argument("folder_id", type=str)
@click.argument("username", type=str)
@click.pass_context
def shared_invite(ctx: click.Context, folder_id: str, username: str) -> None:
    """Invite a user to the shared folder by username. They must run 'shared accept' to get access."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        app.invite_to_shared_folder(token, folder_id, username)
        click.echo(f"Invite sent to {username}. They must accept to get access.")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("accept")
@click.argument("folder_id", type=str)
@click.pass_context
def shared_accept(ctx: click.Context, folder_id: str) -> None:
    """Accept a shared folder invite. You get access immediately."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        app.accept_invite(token, folder_id)
        click.echo("Accepted. You now have access to the folder.")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("pending")
@click.pass_context
def shared_pending(ctx: click.Context) -> None:
    """List shared folders you are invited to but have not accepted yet."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        pending = app.list_pending_invites(token)
        if not pending:
            click.echo("No pending invites.")
            return
        for p in pending:
            click.echo(f"{p['folder_id']}  {p['name']}")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("members")
@click.argument("folder_id", type=str)
@click.pass_context
def shared_members(ctx: click.Context, folder_id: str) -> None:
    """List members of a shared folder."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        data = app.list_members(token, folder_id)
        for m in data["members"]:
            click.echo(f"{m['user_id']}  {m['username']}")
    except KMSError as e:
        raise click.ClickException(str(e))


@shared.command("remove-member")
@click.argument("folder_id", type=str)
@click.argument("username", type=str)
@click.pass_context
def shared_remove_member(ctx: click.Context, folder_id: str, username: str) -> None:
    """Remove a member from the shared folder (creator only)."""
    token = _require_token(ctx)
    app: ClientService = _get_ctx_obj(ctx)["app"]
    try:
        app.remove_member(token, folder_id, username)
        click.echo("Member removed.")
    except KMSError as e:
        raise click.ClickException(str(e))


@cli.command()
def help_cmd() -> None:
    """Show help: commands, CSE/SSE mode, and usage."""
    click.echo("Secure Cloud Storage — CLI")
    click.echo("  --mode cse | sse   Encryption mode (default: cse)")
    click.echo("  --alg aesgcm | chacha20 | fernet   Encryption algorithm (default: aesgcm)")
    click.echo("  register <user> <pass>   Register and log in")
    click.echo("  login <user> <pass>       Log in")
    click.echo("  logout                   Clear session")
    click.echo("  list [--folder <id>]      List files")
    click.echo("  upload <path> [--folder <id>]   Upload file")
    click.echo("  download <file_id> [-o <path>] [--folder <id>]   Download file")
    click.echo("  delete <file_id> [--folder <id>]   Delete file")
    click.echo("  shared create [--name <name>]   Create shared folder (optional name)")
    click.echo("  shared list                    List your shared folders (id + name)")
    click.echo("  shared set-name <folder_id> <name>   Rename a shared folder")
    click.echo("  shared invite <folder_id> <username>   Invite user by username")
    click.echo("  shared accept <folder_id>              Accept an invite (immediate access)")
    click.echo("  shared pending                         List pending invites")
    click.echo("  shared members <folder_id>            List folder members")
    click.echo("  shared remove-member <folder_id> <username>   Remove member (creator only)")
    click.echo("  help                     This message")


# Alias "help" to the command (Click reserves "help" for --help)
cli.add_command(help_cmd, "help")
