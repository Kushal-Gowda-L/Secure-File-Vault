# backend/main.py
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn
import os, json, io, hashlib, uuid

# Import your existing modules (adjust import paths if needed)
from crypto import aes_encrypt, aes_decrypt, rsa_wrap_key, rsa_unwrap_key, get_sha256
from cloud import upload_bytes, download_bytes, make_folder, upload_json, download_json
from roles import load_roles, save_roles, has_permission
from generate_keys import generate_keys_for_email  # function added earlier

# --- config ---
FILES_ROOT = "/vault/files"  # same as used in GUI/config; ensure consistency
USERS_DB = "users_local.json"
KEYS_DIR = "keys"

# --- helpers for user DB (lightweight) ---
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def _load_users():
    if not os.path.exists(USERS_DB):
        with open(USERS_DB, "w", encoding="utf-8") as f:
            json.dump({}, f)
    with open(USERS_DB, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return {}

def _save_users(d):
    with open(USERS_DB, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=4)

def verify_credentials(email: str, password: str):
    users = _load_users()
    if email not in users:
        return False, "User not found"
    u = users[email]
    if u.get("status") != "approved":
        return False, "User not approved"
    if u.get("password") != hash_pw(password):
        return False, "Incorrect password"
    return True, u

# --- rewrap helper for new admin (same logic as GUI) ---
def rewrap_for_new_admin(new_admin_email: str):
    roles = load_roles()
    files = roles.get("files", {})
    if not files:
        return {"rewrapped": 0}

    pub_path = os.path.join(KEYS_DIR, f"{new_admin_email}_public.pem")
    if not os.path.exists(pub_path):
        return {"rewrapped": 0, "note": "public key not present locally"}

    rewrapped_count = 0
    for fid, meta in files.items():
        folder = f"{FILES_ROOT}/{fid}"

        # skip existing wrapped for this admin
        try:
            _ = download_bytes(f"{folder}/wrapped_{new_admin_email}.bin")
            continue
        except Exception:
            pass

        recovered_key = None
        candidates = [meta.get("owner")] + meta.get("recipients", [])
        for u in candidates:
            if not u:
                continue
            try:
                wrapped_bytes = download_bytes(f"{folder}/wrapped_{u}.bin")
                priv_path = os.path.join(KEYS_DIR, f"{u}_private.pem")
                if not os.path.exists(priv_path):
                    continue
                aes_key = rsa_unwrap_key(wrapped_bytes, priv_path)
                if aes_key:
                    recovered_key = aes_key
                    break
            except Exception:
                continue

        if not recovered_key:
            continue

        try:
            new_wrapped = rsa_wrap_key(recovered_key, pub_path)
            upload_bytes(new_wrapped, f"{folder}/wrapped_{new_admin_email}.bin")

            if new_admin_email not in meta.get("recipients", []):
                meta.setdefault("recipients", []).append(new_admin_email)
                roles["files"][fid] = meta
                save_roles(roles)
            rewrapped_count += 1
        except Exception:
            continue

    return {"rewrapped": rewrapped_count}

# --- FastAPI app ---
app = FastAPI(title="Secure File Vault API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Endpoints ---

@app.get("/api/ping")
def ping():
    return {"ok": True}

@app.post("/api/login")
def api_login(email: str = Form(...), password: str = Form(...)):
    ok, info = verify_credentials(email, password)
    if not ok:
        raise HTTPException(status_code=401, detail=info)
    # return role and flags
    users = _load_users()
    u = users[email]
    return {"ok": True, "email": email, "role": u.get("approved_role") or u.get("role"), "force_pw_change": u.get("force_pw_change", False)}

@app.post("/api/signup")
def api_signup(email: str = Form(...), password: str = Form(...), requested_role: str = Form("viewer")):
    users = _load_users()
    if email in users:
        return {"ok": False, "error": "User exists"}
    users[email] = {
        "password": hash_pw(password),
        "status": "pending",
        "requested_role": requested_role,
        "approved_role": None
    }
    _save_users(users)
    return {"ok": True, "msg": "Signup request submitted"}

@app.post("/api/approve_user")
def api_approve_user(admin_email: str = Form(...), admin_password: str = Form(...), email_to_approve: str = Form(...)):
    ok, res = verify_credentials(admin_email, admin_password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    # check admin privilege in access control
    role_map = load_roles().get("users", {})
    if role_map.get(admin_email, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")

    users = _load_users()
    if email_to_approve not in users:
        raise HTTPException(status_code=404, detail="User not found")

    # approve locally
    users[email_to_approve]["status"] = "approved"
    users[email_to_approve]["approved_role"] = users[email_to_approve].get("requested_role", "viewer")
    _save_users(users)

    # add to access_control.json
    roles = load_roles()
    roles.setdefault("users", {})[email_to_approve] = {"role": users[email_to_approve]["approved_role"]}
    save_roles(roles)

    # generate keys locally and upload pubkey to Dropbox
    priv, pub = generate_keys_for_email(email_to_approve)
    try:
        with open(pub, "rb") as f:
            upload_bytes(f.read(), f"/vault/users/{email_to_approve}_pub.pem")
    except Exception as e:
        # continue, but inform
        return {"ok": True, "warning": f"approved but failed to upload public key: {e}"}

    # Rewrap existing files for this new user if they are admin (if admin flow used)
    if users[email_to_approve].get("approved_role") == "admin":
        rewrap_result = rewrap_for_new_admin(email_to_approve)
    else:
        rewrap_result = {"rewrapped": 0}

    return {"ok": True, "rewrap_result": rewrap_result}

@app.post("/api/create_admin")
def api_create_admin(super_admin_email: str = Form(...), super_admin_password: str = Form(...), new_admin_email: str = Form(...)):
    ok, res = verify_credentials(super_admin_email, super_admin_password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    role_map = load_roles().get("users", {})
    if role_map.get(super_admin_email, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")

    users = _load_users()
    users[new_admin_email] = {
        "password": hash_pw("admin123"),
        "status": "approved",
        "requested_role": "admin",
        "approved_role": "admin"
    }
    _save_users(users)

    roles = load_roles()
    roles.setdefault("users", {})[new_admin_email] = {"role": "admin"}
    save_roles(roles)

    priv, pub = generate_keys_for_email(new_admin_email)
    try:
        with open(pub, "rb") as f:
            upload_bytes(f.read(), f"/vault/users/{new_admin_email}_pub.pem")
    except Exception as e:
        return {"ok": True, "warning": f"created admin but failed to upload pubkey: {e}"}

    # Rewrap all existing files for this admin
    rewrap_result = rewrap_for_new_admin(new_admin_email)
    return {"ok": True, "rewrap_result": rewrap_result}

@app.post("/api/upload")
async def api_upload(email: str = Form(...), password: str = Form(...), file: UploadFile = File(...)):
    ok, res = verify_credentials(email, password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)

    # role check
    user_role = (load_roles().get("users", {}).get(email, {}) or {}).get("role") or ( _load_users().get(email,{}).get("approved_role") )
    if user_role not in ["admin", "editor"]:
        raise HTTPException(status_code=403, detail="No permission to upload")

    data = await file.read()
    enc = aes_encrypt(data)

    file_id = str(uuid.uuid4())
    folder = f"{FILES_ROOT}/{file_id}"
    try:
        make_folder(folder)
    except Exception:
        pass

    # upload cipher parts
    upload_bytes(enc["ciphertext"], f"{folder}/ciphertext.bin")
    upload_bytes(enc["nonce"], f"{folder}/nonce.bin")
    upload_bytes(enc["tag"], f"{folder}/tag.bin")
    upload_bytes(get_sha256(data).encode(), f"{folder}/hash.txt")

    # wrap for uploader
    upload_bytes(rsa_wrap_key(enc["aes_key"], os.path.join(KEYS_DIR, f"{email}_public.pem")), f"{folder}/wrapped_{email}.bin")

    # wrap for all admins (if their public key available locally)
    roles_map = load_roles().get("users", {})
    recipients = [email]
    for u, info in roles_map.items():
        if info.get("role") == "admin":
            pub_path = os.path.join(KEYS_DIR, f"{u}_public.pem")
            if os.path.exists(pub_path):
                try:
                    wrapped_admin = rsa_wrap_key(enc["aes_key"], pub_path)
                    upload_bytes(wrapped_admin, f"{folder}/wrapped_{u}.bin")
                    if u not in recipients:
                        recipients.append(u)
                except Exception:
                    continue

    # save meta to roles["files"]
    roles2 = load_roles()
    roles2.setdefault("files", {})[file_id] = {
        "filename": file.filename,
        "owner": email,
        "recipients": recipients
    }
    save_roles(roles2)

    return {"ok": True, "file_id": file_id}

@app.get("/api/list_files")
def api_list_files(email: str, password: str):
    ok, res = verify_credentials(email, password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    roles = load_roles()
    out = []
    for fid, meta in roles.get("files", {}).items():
        # show file if user is owner or recipient or admin
        if meta.get("owner") == email or email in meta.get("recipients", []) or load_roles().get("users", {}).get(email, {}).get("role") == "admin":
            out.append({"file_id": fid, "filename": meta.get("filename"), "owner": meta.get("owner"), "recipients": meta.get("recipients")})
    return {"ok": True, "files": out}

@app.get("/api/download_encrypted/{file_id}")
def api_download_encrypted(file_id: str, email: str, password: str):
    ok, res = verify_credentials(email, password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    # check permission
    if not has_permission(email, file_id, "read"):
        raise HTTPException(status_code=403, detail="Access denied")
    folder = f"{FILES_ROOT}/{file_id}"
    try:
        ct = download_bytes(f"{folder}/ciphertext.bin")
        nonce = download_bytes(f"{folder}/nonce.bin")
        tag = download_bytes(f"{folder}/tag.bin")
        wrapped = download_bytes(f"{folder}/wrapped_{email}.bin")
        sha = download_bytes(f"{folder}/hash.txt")
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"missing components: {e}")

    # Return a JSON with base64? For simplicity return bytes as multipart-like json fields (binary)
    return JSONResponse(content={
        "filename": load_roles()["files"][file_id]["filename"],
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "wrapped_key": wrapped.hex(),
        "sha": sha.decode()
    })

@app.get("/api/read_decrypted/{file_id}")
def api_read_decrypted(file_id: str, email: str, password: str):
    # This endpoint will attempt to decrypt server-side using local private key.
    ok, res = verify_credentials(email, password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    if not has_permission(email, file_id, "read"):
        raise HTTPException(status_code=403, detail="Access denied")

    folder = f"{FILES_ROOT}/{file_id}"
    try:
        ct = download_bytes(f"{folder}/ciphertext.bin")
        nonce = download_bytes(f"{folder}/nonce.bin")
        tag = download_bytes(f"{folder}/tag.bin")
        wrapped = download_bytes(f"{folder}/wrapped_{email}.bin")
        sha = download_bytes(f"{folder}/hash.txt").decode()
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"missing components: {e}")

    priv_path = os.path.join(KEYS_DIR, f"{email}_private.pem")
    if not os.path.exists(priv_path):
        raise HTTPException(status_code=404, detail="Private key not available on server. Use /download_encrypted and decrypt client-side.")

    try:
        aes_key = rsa_unwrap_key(wrapped, priv_path)
        pt = aes_decrypt(ct, nonce, tag, aes_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {e}")

    if get_sha256(pt) != sha:
        raise HTTPException(status_code=400, detail="Integrity check failed")

    # stream file bytes
    return StreamingResponse(io.BytesIO(pt), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={load_roles()['files'][file_id]['filename']}"})

# Admin endpoint: rewrap all files for a given admin (force)
@app.post("/api/rewrap_admin")
def api_rewrap_admin(admin_email: str = Form(...), admin_password: str = Form(...), target_admin: str = Form(...)):
    ok, res = verify_credentials(admin_email, admin_password)
    if not ok:
        raise HTTPException(status_code=401, detail=res)
    if load_roles().get("users", {}).get(admin_email, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not an admin")
    # ensure target admin public key exists locally
    result = rewrap_for_new_admin(target_admin)
    return {"ok": True, "result": result}

# Run
if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
