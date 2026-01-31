# roles.py
import os, json

ACCESS_CONTROL = "vault_cache/access_control.json"

def ensure_cache():
    os.makedirs("vault_cache", exist_ok=True)
    if not os.path.exists(ACCESS_CONTROL):
        with open(ACCESS_CONTROL, "w", encoding="utf-8") as f:
            json.dump({"users": {}, "files": {}}, f, indent=4)

def load_roles():
    ensure_cache()
    with open(ACCESS_CONTROL, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            # reset on corruption
            d = {"users": {}, "files": {}}
            with open(ACCESS_CONTROL, "w", encoding="utf-8") as w:
                json.dump(d, w, indent=4)
            return d

def save_roles(d):
    ensure_cache()
    with open(ACCESS_CONTROL, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=4)

def has_permission(email: str, file_id: str, action: str) -> bool:
    """
    action: "read", "delete", etc.
    Owner can delete; recipients can read.
    Admins DO NOT auto-have permission unless in recipients.
    """
    roles = load_roles()
    files = roles.get("files", {})
    if file_id not in files:
        return False
    meta = files[file_id]
    if action == "read":
        return email == meta.get("owner") or email in meta.get("recipients", [])
    if action == "delete":
        return email == meta.get("owner")
    return False
