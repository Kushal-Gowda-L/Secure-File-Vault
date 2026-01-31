import sys
from roles import load_roles, save_roles, has_permission
from cloud import upload_bytes, download_bytes
from crypto import rsa_wrap_key
from config import FILES_ROOT

# -----------------------------------
# 1) Input details
# -----------------------------------

file_id = input("Enter file ID to share: ").strip()
admin_email = input("Enter admin email: ").strip()
recipient_email = input("Enter recipient email: ").strip()

# -----------------------------------
# 2) Permission check (admin only)
# -----------------------------------

roles = load_roles()

if roles["users"][admin_email]["role"] != "admin":
    print("❌ Only admin can share files.")
    sys.exit(1)

# -----------------------------------
# 3) Wrap AES key for the recipient
# -----------------------------------

folder = f"{FILES_ROOT}/{file_id}"
wrapped_uploader = download_bytes(f"{folder}/wrapped_uploader.bin")

if not wrapped_uploader:
    print("❌ File not found in Dropbox")
    sys.exit(1)

# Unwrap uploader key (AES key)
from crypto import rsa_unwrap_key
aes_key = rsa_unwrap_key(wrapped_uploader, f"keys/{roles['files'][file_id]['owner']}_private.pem")

# Wrap AES key with recipient public key
wrapped_recipient = rsa_wrap_key(aes_key, f"keys/{recipient_email}_public.pem")

# Upload wrapped key
upload_bytes(wrapped_recipient, f"{folder}/wrapped_{recipient_email}.bin")

# -----------------------------------
# 4) Update metadata
# -----------------------------------

roles["files"][file_id]["recipients"].append(recipient_email)
save_roles(roles)

print(f"✅ File {file_id} shared with {recipient_email}")
