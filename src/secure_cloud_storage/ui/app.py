"""Streamlit app: login, list, upload, download, delete, CSE/SSE mode, shared folders."""

import tempfile
from pathlib import Path

import streamlit as st

from secure_cloud_storage.client import ClientService
from secure_cloud_storage.config import FILE_BIN_DIR, KMS_STORE_DIR, SESSION_FILE
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.storage import StorageBackend
from secure_cloud_storage.storage.backend import StorageError


def _get_app() -> ClientService:
    """Build KMS + Storage + ClientService (same process)."""
    kms = KMS(store_dir=KMS_STORE_DIR)
    storage = StorageBackend(file_bin_dir=FILE_BIN_DIR, kms=kms)
    return ClientService(kms=kms, storage=storage)


def _read_token() -> str | None:
    """Read session token from file (shared with CLI)."""
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


def _init_session() -> None:
    if "token" not in st.session_state:
        st.session_state.token = _read_token()
    if "mode" not in st.session_state:
        st.session_state.mode = "cse"
    if "folder_id" not in st.session_state:
        st.session_state.folder_id = None


def _render_login(app: ClientService) -> bool:
    """Show login/register form. Returns True if user is now logged in."""
    tab_login, tab_register = st.tabs(["Login", "Register"])
    with tab_login:
        with st.form("login"):
            user = st.text_input("Username")
            pwd = st.text_input("Password", type="password")
            if st.form_submit_button("Log in"):
                if user and pwd:
                    try:
                        token = app.login(user, pwd)
                        st.session_state.token = token
                        _write_token(token)
                        st.rerun()
                    except KMSError as e:
                        st.error(str(e))
    with tab_register:
        with st.form("register"):
            r_user = st.text_input("Username", key="reg_user")
            r_pwd = st.text_input("Password", type="password", key="reg_pwd")
            if st.form_submit_button("Register"):
                if r_user and r_pwd:
                    try:
                        token = app.register(r_user, r_pwd)
                        st.session_state.token = token
                        _write_token(token)
                        st.rerun()
                    except KMSError as e:
                        st.error(str(e))
    return False


def _render_main(app: ClientService) -> None:
    """Main view: list files, upload, download, delete, shared folders."""
    token = st.session_state.token
    mode = st.session_state.mode
    folder_id = st.session_state.get("folder_id")

    st.sidebar.title("Secure Cloud Storage")
    try:
        username = app.get_username(token)
        if username:
            st.sidebar.caption(f"Logged in as **{username}**")
    except Exception:
        pass
    st.sidebar.radio(
        "Encryption mode", ["cse", "sse"], key="mode", format_func=lambda x: x.upper()
    )
    if st.sidebar.button("Log out"):
        _clear_token()
        st.session_state.token = None
        st.rerun()

    # Shared folder selector
    try:
        shared_folders = app.list_shared_folders(token)
    except KMSError:
        shared_folders = []
    options = ["(Personal files)"] + [f["name"] for f in shared_folders]
    folder_ids = [None] + [f["folder_id"] for f in shared_folders]
    idx = (
        0
        if folder_id is None
        else next(
            (i for i, f in enumerate(shared_folders) if f["folder_id"] == folder_id), 0
        )
        + 1
    )
    sel = st.sidebar.selectbox("Folder", options, index=min(idx, len(options) - 1))
    if sel == "(Personal files)":
        st.session_state.folder_id = None
    else:
        st.session_state.folder_id = folder_ids[options.index(sel)]

    folder_id = st.session_state.folder_id

    # Your token (so you can copy it and give it to someone who wants to invite you to a folder)
    with st.sidebar.expander("Your token (for invites)"):
        st.caption(
            "Copy this and send it to the folder creator so they can invite you."
        )
        st.code(token, language=None)

    try:
        files = app.list_files(token, folder_id=folder_id)
    except (KMSError, StorageError) as e:
        st.error(str(e))
        return

    st.subheader("Files" + (f" (shared: {folder_id})" if folder_id else " (personal)"))
    if not files:
        st.info("No files. Upload one below.")
    else:
        st.caption(
            "Downloads use the encryption mode stored with each file (shown in brackets)."
        )
        for f in files:
            file_mode = f.get("encryption_mode", "cse")
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.text(f"{f['filename']} ({f['file_id']}) [{file_mode.upper()}]")
            with col2:
                try:
                    data, used_mode = app.get_file_bytes(
                        token, f["file_id"], folder_id=folder_id
                    )
                    st.download_button(
                        "Download",
                        data=data,
                        file_name=f["filename"],
                        key=f"dl_{f['file_id']}",
                    )
                    st.caption(f"File downloaded correctly using {used_mode.upper()}")
                except Exception as e:
                    st.error(str(e))
            with col3:
                if st.button("Delete", key=f"del_{f['file_id']}"):
                    try:
                        app.delete_file(token, f["file_id"], folder_id=folder_id)
                        st.rerun()
                    except (KMSError, StorageError) as e:
                        st.error(str(e))

    st.divider()
    st.subheader("Upload")
    uploaded = st.file_uploader("Choose a file")
    if uploaded and st.button("Upload"):
        try:
            data = uploaded.getvalue()
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=Path(uploaded.name).suffix
            ) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)
            try:
                file_id = app.upload_file(
                    token,
                    tmp_path,
                    filename=uploaded.name,
                    folder_id=folder_id,
                    encryption_mode=mode,
                )
                st.success(f"Uploaded: {file_id}")
                st.rerun()
            finally:
                tmp_path.unlink(missing_ok=True)
        except Exception as e:
            st.error(str(e))

    st.sidebar.divider()
    st.sidebar.subheader("Shared folders")
    # Create shared folder: optional name
    create_name = st.sidebar.text_input(
        "New folder name (optional)",
        key="create_folder_name",
        placeholder="e.g. Proyecto X",
    )
    if st.sidebar.button("Create shared folder"):
        try:
            fid = app.create_shared_folder(token, name=create_name or None)
            label = create_name or fid
            st.sidebar.success(f"Created: {label}")
            st.rerun()
        except KMSError as e:
            st.sidebar.error(str(e))
    for f in shared_folders:
        st.sidebar.text(f"{f['name']} ({f['folder_id'][:8]}…)")
    with st.sidebar.expander("Invite to folder"):
        st.caption(
            "Select the folder and paste the invitee's token. They can copy it from 'Your token (for invites)' in their sidebar."
        )
        inv_folder_options = [f["name"] for f in shared_folders]
        inv_folder_ids = [f["folder_id"] for f in shared_folders]
        if not inv_folder_options:
            st.info("You have no shared folders.")
        else:
            inv_sel = st.selectbox("Folder", inv_folder_options, key="inv_folder_sel")
            inv_folder = (
                inv_folder_ids[inv_folder_options.index(inv_sel)] if inv_sel else None
            )
            inv_token = st.text_input(
                "Invitee token",
                key="inv_token",
                placeholder="Paste the token they sent you",
            )
            if st.button("Invite", key="inv_btn"):
                if inv_folder and inv_token:
                    try:
                        app.invite_to_shared_folder(token, inv_folder, inv_token)
                        st.success("Invite sent.")
                    except KMSError as e:
                        st.error(str(e))
    with st.sidebar.expander("Rename shared folder"):
        if not shared_folders:
            st.caption("No shared folders.")
        else:
            rename_sel = st.selectbox(
                "Folder", [f["name"] for f in shared_folders], key="rename_sel"
            )
            rename_fid = shared_folders[
                [f["name"] for f in shared_folders].index(rename_sel)
            ]["folder_id"]
            new_name = st.text_input("New name", value=rename_sel, key="rename_input")
            if st.button("Update name", key="rename_btn") and new_name.strip():
                try:
                    app.set_folder_name(token, rename_fid, new_name.strip())
                    st.success("Name updated.")
                    st.rerun()
                except KMSError as e:
                    st.error(str(e))


def main() -> None:
    """Entry point for Streamlit app."""
    _init_session()
    app = _get_app()

    if not st.session_state.token:
        _render_login(app)
        return

    _render_main(app)


if __name__ == "__main__":
    main()
