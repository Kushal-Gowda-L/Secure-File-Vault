# secure_vault_gui.py
# Final cleaned Streamlit GUI with Share (inline) + Integrity check (SHA-256)
# Assumes these project modules exist and are importable:
# crypto.py, cloud.py, roles.py, generate_keys.py

import streamlit as st
import os
from dotenv import load_dotenv
load_dotenv()
import json
import hashlib
import uuid

# project modules (must exist)
from crypto import aes_encrypt, aes_decrypt, rsa_wrap_key, rsa_unwrap_key, get_sha256
from cloud import upload_bytes, download_bytes, make_folder, delete_path, dbx, ensure_path
from roles import load_roles, save_roles
from generate_keys import generate_keys_for_email

# -------------------------
# Config / helpers
# -------------------------
USERS_DB = "users_local.json"
FILES_ROOT = "/vault/files"
KEYS_DIR = "keys"

def hash_pw(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()

def ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)

def load_users():
    if not os.path.exists(USERS_DB):
        with open(USERS_DB, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=4)
    with open(USERS_DB, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_users(u):
    with open(USERS_DB, "w", encoding="utf-8") as f:
        json.dump(u, f, indent=4)

def clear_session_and_rerun():
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()

# -------------------------
# Share helper (safe)
# -------------------------
def perform_share(file_id: str, owner: str, recipient: str):
    """
    Re-wrap AES key for recipient and update metadata.
    Returns (success: bool, message: str)
    """
    recipient = recipient.strip()
    if recipient == "":
        return False, "Enter a valid recipient email."

    users = load_users()
    if recipient not in users:
        return False, "Recipient not found."

    roles = load_roles()
    files = roles.get("files", {})
    if file_id not in files:
        return False, "File metadata missing."

    # ensure recipient public key locally (generate if not)
    pub_path = f"{KEYS_DIR}/{recipient}_public.pem"
    if not os.path.exists(pub_path):
        generate_keys_for_email(recipient)

    # download owner's wrapped AES key
    wrapped_owner_path = f"{FILES_ROOT}/{file_id}/wrapped_{owner}.bin"
    try:
        wrapped_owner = download_bytes(wrapped_owner_path)
    except Exception:
        return False, "Owner wrapped key missing / download failed."

    owner_priv = f"{KEYS_DIR}/{owner}_private.pem"
    if not os.path.exists(owner_priv):
        return False, "Owner private key missing on server."

    try:
        aes_key = rsa_unwrap_key(wrapped_owner, owner_priv)
    except Exception:
        return False, "Failed to unwrap AES key with owner's private key."

    try:
        wrapped_rec = rsa_wrap_key(aes_key, pub_path)
        upload_bytes(wrapped_rec, f"{FILES_ROOT}/{file_id}/wrapped_{recipient}.bin")
    except Exception as e:
        return False, f"Failed to wrap/upload for recipient: {e}"

    # update metadata recipients
    meta = files[file_id]
    if recipient not in meta.get("recipients", []):
        meta.setdefault("recipients", []).append(recipient)
        roles["files"][file_id] = meta
        save_roles(roles)

    return True, f"Shared with {recipient}."

# -------------------------
# Streamlit UI setup
# -------------------------
st.set_page_config(layout="wide", page_title="Secure File Vault", page_icon="🔐")
st.markdown("""
<style>
body { background: #f6f9fb; }
.card { background: #fff; border-radius:12px; padding:18px; box-shadow:0 8px 18px rgba(15,23,42,0.06); margin-bottom:16px; }
.small { color:#475569; font-size:0.95rem; }
.muted { color:#64748b; font-size:0.9rem; }
.title { font-size:22px; color:#0f172a; margin-bottom:6px; }
</style>
""", unsafe_allow_html=True)

# session defaults
if "email" not in st.session_state:
    st.session_state.email = None
if "view" not in st.session_state:
    st.session_state.view = "login"
if "show_pw_change" not in st.session_state:
    st.session_state.show_pw_change = False

# -------------------------
# Login / Signup (sidebar)
# -------------------------
def login_sidebar():
    st.sidebar.markdown("### 🔑 Login")
    email = st.sidebar.text_input("Email", key="login_email")
    pw = st.sidebar.text_input("Password", type="password", key="login_pw")
    if st.sidebar.button("Login"):
        users = load_users()
        if email not in users:
            st.sidebar.error("User not found")
            return
        u = users[email]
        if u.get("status") != "approved":
            st.sidebar.warning("Account pending approval")
            return
        if u.get("password") != hash_pw(pw):
            st.sidebar.error("Incorrect password")
            return
        st.session_state.email = email
        st.session_state.view = "app"
        st.rerun()
    if st.sidebar.button("Signup"):
        st.session_state.view = "signup"
        st.rerun()

def signup_sidebar():
    st.sidebar.markdown("### 📝 Signup")
    email = st.sidebar.text_input("Email", key="su_email")
    p1 = st.sidebar.text_input("Password", type="password", key="su_pw1")
    p2 = st.sidebar.text_input("Confirm", type="password", key="su_pw2")
    role = st.sidebar.selectbox("Requested role", ["viewer", "editor"], key="su_role")
    if st.sidebar.button("Submit request"):
        if p1 != p2:
            st.sidebar.error("Passwords do not match")
            return
        users = load_users()
        if email in users:
            st.sidebar.error("User exists")
            return
        users[email] = {
            "password": hash_pw(p1),
            "status": "pending",
            "requested_role": role,
            "approved_role": None
        }
        save_users(users)
        st.sidebar.success("Signup request submitted.")
        st.session_state.view = "login"
        st.rerun()
    if st.sidebar.button("Back to login"):
        st.session_state.view = "login"
        st.rerun()

# if not logged in
if st.session_state.email is None:
    if st.session_state.view == "signup":
        signup_sidebar()
    else:
        login_sidebar()
    st.markdown('<div class="card"><div class="title">🔐 Secure File Vault</div><div class="small">Hybrid AES-GCM + RSA demo.</div></div>', unsafe_allow_html=True)
    st.stop()

# -------------------------
# Authenticated UI
# -------------------------
current_user = st.session_state.email
roles_data = load_roles()
user_role = roles_data.get("users", {}).get(current_user, {}).get("role", "viewer")

with st.sidebar:
    st.markdown("👋 **Logged in as**")
    st.markdown(f"**{current_user}**")
    st.markdown(f"Role: **{user_role}**")
    st.markdown("---")
    if st.button("Logout"):
        clear_session_and_rerun()
    if st.button("🛡️ Change my password"):
        st.session_state.show_pw_change = True

# password change
if st.session_state.show_pw_change:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### 🛡️ Change your password")
    old = st.text_input("Old password", type="password", key="cp_old")
    new1 = st.text_input("New password", type="password", key="cp_new1")
    new2 = st.text_input("Confirm new password", type="password", key="cp_new2")
    if st.button("Update password", key="update_pw"):
        users = load_users()
        u = users.get(current_user)
        if not u:
            st.error("User missing")
        elif u.get("password") != hash_pw(old):
            st.error("Old password incorrect")
        elif new1 != new2:
            st.error("New passwords do not match")
        else:
            u["password"] = hash_pw(new1)
            save_users(users)
            st.success("Password changed successfully")
            st.session_state.show_pw_change = False
            st.rerun()
    if st.button("Cancel", key="cancel_pw"):
        st.session_state.show_pw_change = False
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

# header
st.markdown('<div class="card"><div class="title">📂 Dashboard</div><div class="muted">Upload, share, download with role-based access.</div></div>', unsafe_allow_html=True)

col_left, col_right = st.columns([2,3])

# -------------------------
# Left column — Upload & My Files
# -------------------------
with col_left:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### ⬆️ Upload")
    if user_role not in ["admin", "editor"]:
        st.markdown("<div class='small'>You do not have permission to upload files.</div>", unsafe_allow_html=True)
    else:
        upload_file = st.file_uploader("Choose a file to upload", key="file_upload")
        if upload_file and st.button("⬆️ Upload file", key="do_upload"):
            try:
                data = upload_file.read()
                enc = aes_encrypt(data)  # expects dict with aes_key,ciphertext,nonce,tag
                fid = str(uuid.uuid4())
                folder = f"{FILES_ROOT}/{fid}"
                make_folder(folder)
                upload_bytes(enc["ciphertext"], f"{folder}/ciphertext.bin")
                upload_bytes(enc["nonce"], f"{folder}/nonce.bin")
                upload_bytes(enc["tag"], f"{folder}/tag.bin")
                # store sha256 hex
                upload_bytes(get_sha256(data).encode(), f"{folder}/hash.txt")
                ensure_keys_dir()
                pub = f"{KEYS_DIR}/{current_user}_public.pem"
                if not os.path.exists(pub):
                    generate_keys_for_email(current_user)
                wrapped_owner = rsa_wrap_key(enc["aes_key"], pub)
                upload_bytes(wrapped_owner, f"{folder}/wrapped_{current_user}.bin")
                roles = load_roles()
                roles.setdefault("files", {})[fid] = {
                    "filename": upload_file.name,
                    "owner": current_user,
                    "recipients": [current_user]
                }
                save_roles(roles)
                st.success("File uploaded successfully ✅")
                st.rerun()
            except Exception as e:
                st.error(f"Upload failed: {e}")
    st.markdown('</div>', unsafe_allow_html=True)

    # My Files
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### 🗂 My Files")
    roles2 = load_roles()
    files = roles2.get("files", {})
    visible = False
    for fid, meta in files.items():
        if current_user == meta.get("owner") or current_user in meta.get("recipients", []):
            visible = True
            st.markdown(f"**{meta.get('filename')}**")
            st.markdown(f"*Owner:* {meta.get('owner')}  •  *Recipients:* {', '.join(meta.get('recipients', []))}")
            bcol1, bcol2, bcol3, bcol4 = st.columns([1,1,1,1])

            # Encrypted download
            if bcol1.button("🔐 Encrypted DL", key=f"encdl_{fid}"):
                try:
                    ct = download_bytes(f"{FILES_ROOT}/{fid}/ciphertext.bin")
                    st.download_button("Save encrypted", ct, file_name=f"{meta.get('filename')}.enc", key=f"save_enc_{fid}")
                except Exception as e:
                    st.error(f"Encrypted download failed: {e}")

            # Decrypted download with integrity check
            if bcol2.button("📄 Download", key=f"pdld_{fid}"):
                try:
                    wrapped_path = f"{FILES_ROOT}/{fid}/wrapped_{current_user}.bin"
                    wrapped = download_bytes(wrapped_path)
                    priv_path = f"{KEYS_DIR}/{current_user}_private.pem"
                    if not os.path.exists(priv_path):
                        st.error("Private key not available on server. Cannot decrypt.")
                    else:
                        aes_key = rsa_unwrap_key(wrapped, priv_path)
                        ct = download_bytes(f"{FILES_ROOT}/{fid}/ciphertext.bin")
                        nonce = download_bytes(f"{FILES_ROOT}/{fid}/nonce.bin")
                        tag = download_bytes(f"{FILES_ROOT}/{fid}/tag.bin")
                        # AES decrypt (may raise on auth fail)
                        try:
                            pt = aes_decrypt(ct, nonce, tag, aes_key)
                        except Exception:
                            st.error("Decryption failed (ciphertext tampered or wrong key).")
                            continue

                        # Integrity verification
                        try:
                            stored_hash = download_bytes(f"{FILES_ROOT}/{fid}/hash.txt").decode().strip()
                        except Exception:
                            st.warning("No stored hash found — cannot verify integrity.")
                            stored_hash = None

                        computed_hash = hashlib.sha256(pt).hexdigest()
                        if stored_hash is not None and stored_hash != computed_hash:
                            st.error("❌ Integrity check failed — file may have been tampered with.")
                        else:
                            if stored_hash is not None:
                                st.success("✔ Integrity verified.")
                            st.download_button("Save file", pt, file_name=meta.get("filename"), key=f"save_plain_{fid}")

                except Exception as e:
                    st.error(f"Decrypt/download failed: {e}")

            # SHARE (fixed inline expander)
            if bcol3.button("🤝 Share", key=f"sharebtn_{fid}"):
                # open the share expander for this file
                st.session_state[f"share_open_{fid}"] = True

            if st.session_state.get(f"share_open_{fid}", False):
                with st.expander(f"Share file: {meta.get('filename')}", expanded=True):
                    target_key = f"share_target_{fid}"
                    target = st.text_input("Share with (email):", key=target_key)
                    if st.button("Share file", key=f"share_submit_{fid}"):
                        ok, msg = perform_share(fid, meta.get("owner"), target)
                        if ok:
                            st.success(msg)
                            st.session_state[f"share_open_{fid}"] = False
                            st.rerun()
                        else:
                            st.error(msg)

            # Delete (owner only)
            if bcol4.button("🗑️ Delete", key=f"delbtn_{fid}"):
                if current_user != meta.get("owner"):
                    st.warning("Only the owner may delete this file.")
                else:
                    try:
                        # try cloud delete
                        try:
                            delete_path(f"{FILES_ROOT}/{fid}")
                        except Exception:
                            try:
                                if dbx is not None:
                                    dbx.files_delete_v2(ensure_path(f"{FILES_ROOT}/{fid}"))
                            except Exception as ex:
                                st.warning(f"Dropbox deletion warning: {ex}")
                        roles3 = load_roles()
                        if fid in roles3.get("files", {}):
                            del roles3["files"][fid]
                            save_roles(roles3)
                        st.success("File deleted (metadata removed and cloud purged if available).")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e}")

            st.markdown("---")
    if not visible:
        st.markdown("You have no accessible files yet.")
    st.markdown('</div>', unsafe_allow_html=True)

# -------------------------
# Right column — Admin panel
# -------------------------
with col_right:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### 🧩 Admin Panel & Info")
    if user_role != "admin":
        st.markdown("<div class='small'>Admin panel hidden. You need admin role to manage signups.</div>", unsafe_allow_html=True)
    else:
        st.markdown("#### 📨 Pending Signups")
        users = load_users()
        pending = [e for e, d in users.items() if d.get("status") == "pending"]
        if not pending:
            st.markdown("<div class='muted'>No pending signups.</div>", unsafe_allow_html=True)
        else:
            for p in pending:
                st.markdown(f"**{p}**  •  requested role: {users[p].get('requested_role')}")
                col_a, col_b = st.columns([1, 1])
                if col_a.button("Approve", key=f"approve_{p}"):
                    try:
                        users = load_users()
                        users[p]["status"] = "approved"
                        users[p]["approved_role"] = users[p].get("requested_role", "viewer")
                        save_users(users)
                        roles3 = load_roles()
                        roles3.setdefault("users", {})[p] = {"role": users[p]["approved_role"]}
                        save_roles(roles3)
                        ensure_keys_dir()
                        generate_keys_for_email(p)
                        try:
                            with open(f"{KEYS_DIR}/{p}_public.pem", "rb") as f:
                                upload_bytes(f.read(), f"/vault/users/{p}_pub.pem")
                        except Exception:
                            st.info("Public key upload to cloud failed (token?).")
                        st.success(f"Approved {p}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Approve failed: {e}")
                if col_b.button("Reject", key=f"reject_{p}"):
                    try:
                        users = load_users()
                        del users[p]
                        save_users(users)
                        st.success(f"Rejected and removed {p}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Reject failed: {e}")

        st.markdown("---")
        st.markdown("#### ➕ Create admin (local)")
        newadm = st.text_input("Admin email", key="newadm")
        if st.button("Create Admin"):
            if not newadm:
                st.warning("Enter an email")
            else:
                users = load_users()
                if newadm in users:
                    st.error("User already exists")
                else:
                    users[newadm] = {
                        "password": hash_pw("admin123"),
                        "status": "approved",
                        "requested_role": "admin",
                        "approved_role": "admin"
                    }
                    save_users(users)
                    roles3 = load_roles()
                    roles3.setdefault("users", {})[newadm] = {"role": "admin"}
                    save_roles(roles3)
                    ensure_keys_dir()
                    generate_keys_for_email(newadm)
                    try:
                        with open(f"{KEYS_DIR}/{newadm}_public.pem", "rb") as f:
                            upload_bytes(f.read(), f"/vault/users/{newadm}_pub.pem")
                    except Exception:
                        st.info("Public key upload failed (Dropbox token may be missing).")
                    st.success("Admin created with default password admin123")
    st.markdown('</div>', unsafe_allow_html=True)

# footer
st.markdown('<div style="margin-top:12px" />', unsafe_allow_html=True)
st.markdown('<div class="card"><div class="muted">Tip: Owners must explicitly share files to grant access. Admins cannot access files unless shared.</div></div>', unsafe_allow_html=True)
