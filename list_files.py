import json
from roles import load_roles

roles = load_roles()

print("\n✅ FILE LIST\n")

if len(roles["files"]) == 0:
    print("No files found in the vault.")
else:
    for file_id, meta in roles["files"].items():
        print("📌 File ID       :", file_id)
        print("📄 Filename      :", meta["filename"])
        print("👤 Owner         :", meta["owner"])
        print("👥 Recipients    :", ", ".join(meta["recipients"]))
        print("-" * 40)
