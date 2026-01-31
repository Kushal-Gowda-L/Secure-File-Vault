import subprocess
from Crypto.PublicKey import RSA
import json
import os
import sys

# -------------------------------------------
# 1) Admin authentication
# -------------------------------------------

admin_email = input("Enter ADMIN email: ").strip()
admin_key_path = f"keys/{admin_email}_private.pem"

if not os.path.exists(admin_key_path):
    print("❌ Admin private key not found!")
    sys.exit(1)

try:
    RSA.import_key(open(admin_key_path, "rb").read())
    print("✅ Admin authenticated successfully")
except Exception as e:
    print("❌ Invalid admin private key")
    sys.exit(1)

# -------------------------------------------
# 2) Ask for new user details
# -------------------------------------------

email = input("Enter NEW user email: ").strip()
role = input("Enter role for new user (admin/editor/viewer): ").strip()

if role not in ["admin", "editor", "viewer"]:
    print("❌ Invalid role. Choose admin / editor / viewer")
    sys.exit(1)

# -------------------------------------------
# 3) Generate RSA keys for new user
# -------------------------------------------

if not os.path.exists("keys"):
    os.makedirs("keys")

key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

private_path = f"keys/{email}_private.pem"
public_path  = f"keys/{email}_public.pem"

with open(private_path, "wb") as f:
    f.write(private_key)

with open(public_path, "wb") as f:
    f.write(public_key)

print(f"✅ Generated RSA keys for: {email}")

# -------------------------------------------
# 4) Call app.py add-user THROUGH admin identity
# -------------------------------------------

cmd = [
    sys.executable,
    "app.py",
    "add-user",
    "--email", email,
    "--role", role,
    "--pubkey", public_path
]

print("✅ Adding user to system...")
result = subprocess.run(cmd)

print("✅ User successfully added!")
print("✅ Public key uploaded to Dropbox")
print("📌 Private key stored at:", private_path)
