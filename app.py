print("✅ app.py is running")
import argparse, os, json, uuid
from crypto import *
from cloud import *
import datetime
from roles import load_roles, save_roles, has_permission
from config import FILES_ROOT

def init_admin(email):
    roles = load_roles()
    roles["users"][email] = {"role": "admin"}
    save_roles(roles)
    print("✅ Admin created:", email)


def add_user(email, role, pubkey_path):
    roles = load_roles()

    # 1) Save role in vault
    roles["users"][email] = {"role": role}
    save_roles(roles)

    # 2) Upload public key to Dropbox
    upload_bytes(open(pubkey_path, "rb").read(), f"/vault/users/{email}_pub.pem")
    print(f"✅ Public key uploaded for: {email}")

    # 3) If new admin -> AUTO REWRAP ALL OLD FILES
    if role == "admin":
        print("🔄 New admin detected — Auto-Rewrapping all files...")
        auto_rewrap_for_new_admin(email)

    print(f"✅ User {email} added as {role}")



def upload_file(file_path, user_email):
    roles = load_roles()

    # Role check
    if roles["users"][user_email]["role"] not in ["admin", "editor"]:
        print("❌ No permission to upload")
        return

    # Read file
    data = open(file_path, "rb").read()

    # Encrypt AES
    enc = aes_encrypt(data)

    # Wrap AES key for uploader
    wrapped_uploader = rsa_wrap_key(enc["aes_key"], f"keys/{user_email}_public.pem")

    # Wrap AES key for admin
    wrapped_admin = rsa_wrap_key(enc["aes_key"], "keys/admin@example.com_public.pem")

    # Hash
    sha = get_sha256(data)

    file_id = str(uuid.uuid4())
    folder = f"{FILES_ROOT}/{file_id}"
    make_folder(folder)

    # Upload encrypted pieces
    upload_bytes(enc["ciphertext"], f"{folder}/ciphertext.bin")
    upload_bytes(enc["nonce"], f"{folder}/nonce.bin")
    upload_bytes(enc["tag"], f"{folder}/tag.bin")

    # Upload AES wrapped keys
    upload_bytes(wrapped_uploader, f"{folder}/wrapped_{user_email}.bin")
    upload_bytes(wrapped_admin,    f"{folder}/wrapped_admin@example.com.bin")

    # Upload hash
    upload_bytes(sha.encode(), f"{folder}/hash.txt")

    # Metadata
    meta = {
        "filename": os.path.basename(file_path),
        "owner": user_email,
        "recipients": [user_email, "admin@example.com"],
        "version": 1
    }
    upload_json(json.dumps(meta, indent=4), f"{folder}/meta.json")

    # Update access control
    roles["files"][file_id] = meta
    save_roles(roles)

    print("✅ File uploaded with ID:", file_id)



def read_file(file_id, user_email, outpath):
    roles = load_roles()

    # Permission check
    if not has_permission(user_email, file_id, "read"):
        print("❌ Access denied")
        return

    folder = f"{FILES_ROOT}/{file_id}"

    # Try to download wrapped key for this user
    wrapped_path = f"{folder}/wrapped_{user_email}.bin"

    try:
        wrapped = download_bytes(wrapped_path)
        print(f"✅ Found wrapped key for {user_email}")
    except:
        print(f"⚠️ No wrapped key found for {user_email}")
        print("🔄 Attempting AUTO-REWRAP using existing users...")

        meta = roles["files"][file_id]
        candidates = [meta["owner"]] + meta["recipients"]

        existing_user = None
        recovered_key = None

        # Try to recover AES key from ANY existing user
        for u in candidates:
            try:
                print(f"🔍 Checking wrapped key for {u}")
                data = download_bytes(f"{folder}/wrapped_{u}.bin")
                recovered_key = rsa_unwrap_key(data, f"keys/{u}_private.pem")
                existing_user = u
                print(f"✅ AES key recovered using {u}")
                break
            except:
                pass

        if not recovered_key:
            print("❌ Unable to recover AES key. No valid wrapped keys found.")
            return

        # Rewrap AES key for current user
        print(f"🔑 Rewrapping AES key for {user_email}...")
        new_wrapped = rsa_wrap_key(recovered_key, f"keys/{user_email}_public.pem")
        
        upload_bytes(new_wrapped, wrapped_path)

        # Also add user to recipients list if missing
        if user_email not in meta["recipients"]:
            meta["recipients"].append(user_email)
            save_roles(roles)

        wrapped = new_wrapped
        print(f"✅ AUTO-REWRAP SUCCESS for {user_email}. Proceeding to decrypt...")

    # Load ciphertext components
    try:
        ct = download_bytes(f"{folder}/ciphertext.bin")
        nonce = download_bytes(f"{folder}/nonce.bin")
        tag = download_bytes(f"{folder}/tag.bin")
        sha_stored = download_bytes(f"{folder}/hash.txt").decode()
    except Exception as e:
        print("❌ Missing ciphertext components:", e)
        return

    # Unwrap AES key
    try:
        aes_key = rsa_unwrap_key(wrapped, f"keys/{user_email}_private.pem")
        print(f"✅ AES key unwrapped successfully for {user_email}")
    except Exception as e:
        print("❌ Failed to unwrap AES key:", e)
        return

    # Decrypt
    try:
        plaintext = aes_decrypt(ct, nonce, tag, aes_key)
    except:
        print("❌ Decryption failed. Integrity compromised.")
        return

    # Check integrity
    if get_sha256(plaintext) != sha_stored:
        print("❌ Integrity check failed (hash mismatch).")
        return

    # Write output file
    with open(outpath, "wb") as f:
        f.write(plaintext)

    print("✅ File decrypted successfully →", outpath)


def write_file(file_id, file_path, user_email, backup=True):
    roles = load_roles()

    # Permission check
    if not has_permission(user_email, file_id, "write"):
        print("❌ You do not have write permission for this file")
        return

    folder = f"{FILES_ROOT}/{file_id}"

    # Load meta.json
    meta_json = download_json(f"{folder}/meta.json")
    if not meta_json:
        print("❌ Missing meta.json for this file")
        return

    meta = json.loads(meta_json)
    recipients = meta.get("recipients", [])
    owner = meta.get("owner")

    # Read the new updated file
    new_plain_data = open(file_path, "rb").read()

    # ENCRYPT NEW CONTENT
    enc = aes_encrypt(new_plain_data)
    sha = get_sha256(new_plain_data)

    # OPTIONAL: BACKUP OLD VERSION
    if backup:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        backup_folder = f"{folder}_backup_{timestamp}"
        try:
            dbx.files_copy_v2(folder, backup_folder)
            print("✅ Backup created:", backup_folder)
        except:
            print("⚠️ Backup could not be created. Continuing...")

    # Wrap AES key for all recipients
    for rec in recipients:
        try:
            wrapped = rsa_wrap_key(enc["aes_key"], f"keys/{rec}_public.pem")
            upload_bytes(wrapped, f"{folder}/wrapped_{rec}.bin")
        except:
            print(f"⚠️ Warning: could not wrap key for {rec}")

    # Upload encrypted new data
    upload_bytes(enc["ciphertext"], f"{folder}/ciphertext.bin")
    upload_bytes(enc["nonce"], f"{folder}/nonce.bin")
    upload_bytes(enc["tag"], f"{folder}/tag.bin")
    upload_bytes(sha.encode(), f"{folder}/hash.txt")

    # Update metadata
    meta["version"] = meta.get("version", 1) + 1
    meta["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    upload_json(json.dumps(meta, indent=4), f"{folder}/meta.json")

    roles["files"][file_id] = meta
    save_roles(roles)

    print("✅ File successfully rewritten with new version:", meta["version"])

def auto_rewrap_for_new_admin(admin_email):
    roles = load_roles()
    files = roles["files"]

    for fid, meta in files.items():
        folder = f"{FILES_ROOT}/{fid}"

        # Try to find ANY existing wrapped key from owner or old admins
        candidates = [meta["owner"]] + meta["recipients"]

        existing_user = None
        wrapped_key = None

        for u in candidates:
            try:
                wrapped_key = download_bytes(f"{folder}/wrapped_{u}.bin")
                existing_user = u
                break
            except:
                pass

        if not wrapped_key:
            print(f"❌ File {fid}: No existing wrapped keys, cannot rewrap")
            continue

        # Decrypt AES key
        try:
            aes_key = rsa_unwrap_key(wrapped_key, f"keys/{existing_user}_private.pem")
        except:
            print(f"❌ Failed to unwrap AES key for {existing_user}")
            continue

        # Rewrap for new admin
        new_wrapped = rsa_wrap_key(aes_key, f"keys/{admin_email}_public.pem")
        upload_bytes(new_wrapped, f"{folder}/wrapped_{admin_email}.bin")

        # Add admin to recipients if needed
        if admin_email not in meta["recipients"]:
            meta["recipients"].append(admin_email)

        print(f"✅ File {fid}: Rewrapped for new admin {admin_email}")

    save_roles(roles)
    print("✅✅ Auto-Rewrap complete for all files")


def main():
    print("✅ app.py is running")
    import argparse

    p = argparse.ArgumentParser(description="Secure File Vault CLI")

    # Supported actions
    p.add_argument("action", choices=[
        "init-admin",
        "add-user",
        "upload",
        "read",
        "write"
    ], help="Action to perform")

    # Optional flags used by different commands
    p.add_argument("--email", help="User email performing the action")
    p.add_argument("--role", help="Role for add-user (admin/editor/viewer)")
    p.add_argument("--pubkey", help="Public key path for add-user")
    p.add_argument("--file", help="Path to file for upload/write")
    p.add_argument("--id", help="File ID for read/write operations")
    p.add_argument("--out", help="Output path for read")

    args = p.parse_args()
    print("✅ main() reached")

    # ------------------------------
    # ACTION HANDLERS
    # ------------------------------

    if args.action == "init-admin":
        if not args.email:
            print("❌ Missing --email")
            return
        init_admin(args.email)

    elif args.action == "add-user":
        if not args.email or not args.role or not args.pubkey:
            print("❌ Missing arguments. Required: --email --role --pubkey")
            return
        add_user(args.email, args.role, args.pubkey)

    elif args.action == "upload":
        if not args.file or not args.email:
            print("❌ Missing arguments. Required: --file --email")
            return
        upload_file(args.file, args.email)

    elif args.action == "read":
        if not args.id or not args.email or not args.out:
            print("❌ Missing arguments. Required: --id --email --out")
            return
        read_file(args.id, args.email, args.out)

    elif args.action == "write":
        if not args.id or not args.email or not args.file:
            print("❌ Missing arguments. Required: --id --email --file")
            return
        write_file(args.id, args.file, args.email)

    else:
        print("❌ Unknown action")

if __name__ == "__main__":
    main()
