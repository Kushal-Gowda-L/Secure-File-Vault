import sys
from roles import load_roles, save_roles
from cloud import dbx
from config import FILES_ROOT

file_id = input("Enter file ID to delete: ").strip()
admin_email = input("Enter admin email: ").strip()

roles = load_roles()

if roles["users"][admin_email]["role"] != "admin":
    print("❌ Only admin can delete files.")
    sys.exit(1)

folder = f"{FILES_ROOT}/{file_id}"

try:
    dbx.files_delete_v2(folder)
    print(f"✅ Deleted file folder from Dropbox: {folder}")
except Exception as e:
    print("❌ Dropbox delete failed:", e)
    sys.exit(1)

# Remove metadata reference
if file_id in roles["files"]:
    del roles["files"][file_id]
    save_roles(roles)
    print("✅ Metadata updated")

print("✅ File deleted successfully")
