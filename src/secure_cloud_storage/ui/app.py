"""Streamlit app: login, list, upload, download, delete, CSE/SSE mode, shared folders."""

import os
import tempfile
from pathlib import Path

import streamlit as st

from secure_cloud_storage.client import ClientService
from secure_cloud_storage.config import FILE_BIN_DIR, KMS_STORE_DIR
from secure_cloud_storage.kms import KMS
from secure_cloud_storage.kms.store import KMSError
from secure_cloud_storage.storage import StorageBackend
from secure_cloud_storage.storage.backend import StorageError


def _get_app(admin_password: str | None = None) -> ClientService:
    """Build KMS + Storage + ClientService and unlock KEK."""
    kms = KMS(store_dir=KMS_STORE_DIR)
    
    # Unlock the KMS with the provided password.
    if admin_password:
        kms.unlock_kek(admin_password)
        
    storage = StorageBackend(file_bin_dir=FILE_BIN_DIR, kms=kms)
    return ClientService(kms=kms, storage=storage)


def _init_session() -> None:
    # Token only in session_state (no file): each browser tab has its own user; multiple sessions allowed.
    if "token" not in st.session_state:
        st.session_state.token = None
    if "mode" not in st.session_state:
        st.session_state.mode = "cse"
    if "alg" not in st.session_state:
        st.session_state.alg = "aesgcm"
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
                        st.rerun()
                    except KMSError as e:
                        st.error(str(e))
    return False


def _render_main(app: ClientService) -> None:
    """Main view: list files, upload, download, delete, shared folders."""
    token = st.session_state.token
    mode = st.session_state.mode
    alg = st.session_state.alg
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
    st.sidebar.radio(
        "Encryption algorithm",
        ["aesgcm", "chacha20", "fernet"],
        key="alg",
        format_func=lambda x: x.upper(),
    )
    if st.sidebar.button("Log out"):
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

    try:
        files = app.list_files(token, folder_id=folder_id)
    except (KMSError, StorageError) as e:
        st.error(str(e))
        return

    st.subheader("Files")
    if "error_msg" in st.session_state:
        st.error(st.session_state["error_msg"])
        del st.session_state["error_msg"]

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
                if st.button("Prepare download", key=f"predl_{f['file_id']}"):
                    # It is created the button after touch it, because you can download fine a file although is has been changed
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
                        st.caption(
                            f"File downloaded correctly using {used_mode.upper()}"
                        )
                    except Exception as e:
                        st.session_state["error_msg"] = str(e)
                        st.error(str(e))
                        st.rerun()
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
                    algorithm=alg,
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
            "Select the folder and enter the username to invite. They must accept to get access."
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
            inv_username = st.text_input(
                "Username to invite",
                key="inv_username",
                placeholder="e.g. alice",
            )
            if st.button("Invite", key="inv_btn"):
                if inv_folder and inv_username:
                    try:
                        app.invite_to_shared_folder(
                            token, inv_folder, inv_username.strip()
                        )
                        st.success(f"Invite sent to {inv_username}. They must accept.")
                        st.rerun()
                    except KMSError as e:
                        st.error(str(e))

    with st.sidebar.expander("Pending invites"):
        try:
            pending = app.list_pending_invites(token)
        except KMSError:
            pending = []
        if not pending:
            st.caption("No pending invites.")
        else:
            for p in pending:
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.caption(f"{p['name']} ({p['folder_id'][:8]}…)")
                with col2:
                    if st.button("Accept", key=f"accept_{p['folder_id']}"):
                        try:
                            app.accept_invite(token, p["folder_id"])
                            st.success("Accepted.")
                            st.rerun()
                        except KMSError as e:
                            st.error(str(e))

    with st.sidebar.expander("Members / Remove"):
        if not shared_folders:
            st.caption("No shared folders.")
        else:
            mem_sel = st.selectbox(
                "Folder",
                [f["name"] for f in shared_folders],
                key="members_folder_sel",
            )
            mem_fid = shared_folders[
                [f["name"] for f in shared_folders].index(mem_sel)
            ]["folder_id"]
            try:
                data = app.list_members(token, mem_fid)
                members = data["members"]
                you_are_creator = data["you_are_creator"]
            except KMSError:
                members = []
                you_are_creator = False
            for m in members:
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.caption(f"{m['username']} ({m['user_id'][:8]}…)")
                with col2:
                    if you_are_creator and st.button(
                        "Remove", key=f"remove_{mem_fid}_{m['user_id']}"
                    ):
                        try:
                            app.remove_member(token, mem_fid, m["username"])
                            st.success("Removed.")
                            st.rerun()
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
    
   # 1. Look for admin password in environment variables
    admin_password = os.environ.get("KMS_ADMIN_PASSWORD")
    
    # 2. If not in env, look in session_state
    if not admin_password and "admin_pwd" in st.session_state:
        admin_password = st.session_state.admin_pwd

    # 3. Lock screen if no password is provided.
    if not admin_password:
        st.title("🔒 KMS Locked")
        st.warning("The system is locked. Only the administrator can initialize the KMS.")
        pwd = st.text_input("Admin Password (KEK Unlock)", type="password")
        if st.button("Unlock System"):
            st.session_state.admin_pwd = pwd
            st.rerun()
        return

    # 4. Attempt to start the application.
    try:
        app = _get_app(admin_password)
    except KMSError as e:
        st.error(f"Critical failure unlocking KMS: {e}")
        st.session_state.pop("admin_pwd", None)
        return

    # 5. Normal flow if unlocked.
    if not st.session_state.token:
        _render_login(app)
        return

    _render_main(app)


if __name__ == "__main__":
    main()