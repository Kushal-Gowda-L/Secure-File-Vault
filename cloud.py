# cloud.py
import os
import json
from dotenv import load_dotenv
import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import AuthError, ApiError

load_dotenv()

# Load env
APP_KEY = os.getenv("DROPBOX_APP_KEY")
APP_SECRET = os.getenv("DROPBOX_APP_SECRET")
ACCESS_TOKEN = os.getenv("DROPBOX_ACCESS_TOKEN")
REFRESH_TOKEN = os.getenv("DROPBOX_REFRESH_TOKEN")

# Global client
dbx = None


# -----------------------------
# Save refreshed access token
# -----------------------------
def update_access_token(new_token: str):
    env_path = ".env"
    if not os.path.exists(env_path):
        return

    new_lines = []
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("DROPBOX_ACCESS_TOKEN="):
                new_lines.append(f"DROPBOX_ACCESS_TOKEN={new_token}\n")
            else:
                new_lines.append(line)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print("🔐 Updated access token in .env")


# -----------------------------
# Initialize Dropbox client
# -----------------------------
def init_dbx():
    global dbx

    # No credentials → local mode
    if not (APP_KEY and APP_SECRET and REFRESH_TOKEN):
        print("⚠️ Missing Dropbox info → LOCAL MODE")
        dbx = None
        return

    try:
        # client with refresh token
        dbx = dropbox.Dropbox(
            oauth2_access_token=ACCESS_TOKEN,
            oauth2_refresh_token=REFRESH_TOKEN,
            app_key=APP_KEY,
            app_secret=APP_SECRET,
            oauth2_access_token_expiration=None
        )

        # trigger refresh if expired
        dbx.users_get_current_account()

        print("✅ Dropbox connected with auto-refresh.")
        return

    except AuthError:
        print("⚠️ Token expired → refreshing...")

        # Create client without ACCESS_TOKEN; refresh only from refresh token
        dbx = dropbox.Dropbox(
            oauth2_refresh_token=REFRESH_TOKEN,
            app_key=APP_KEY,
            app_secret=APP_SECRET
        )

        # force refresh by calling account
        dbx.users_get_current_account()

        # SDK stores new token internally
        new_token = dbx._oauth2_access_token
        update_access_token(new_token)

        print("🔄 Token refreshed OK")
        return

    except Exception as e:
        print("❌ Dropbox init error:", e)
        dbx = None


# Init client
init_dbx()


# -----------------------------
# Helpers
# -----------------------------
def ensure_path(p: str) -> str:
    return p if p.startswith("/") else "/" + p


# -----------------------------
# Upload file bytes
# -----------------------------
def upload_bytes(data: bytes, dropbox_path: str):
    path = ensure_path(dropbox_path)

    if dbx:
        try:
            dbx.files_upload(data, path, mode=WriteMode("overwrite"))
            return True
        except Exception as e:
            print("❌ Dropbox upload failed:", e)

    # Local fallback
    local = "." + path
    os.makedirs(os.path.dirname(local), exist_ok=True)
    with open(local, "wb") as f:
        f.write(data)
    return True


# -----------------------------
# Download file
# -----------------------------
def download_bytes(dropbox_path: str) -> bytes:
    path = ensure_path(dropbox_path)

    if dbx:
        try:
            md, res = dbx.files_download(path)
            return res.content
        except Exception as e:
            print("❌ Dropbox download failed:", e)

    # fallback
    local = "." + path
    return open(local, "rb").read()


# -----------------------------
# Create folder
# -----------------------------
def make_folder(dropbox_path: str):
    path = ensure_path(dropbox_path)

    if dbx:
        try:
            dbx.files_create_folder_v2(path)
            return True
        except ApiError:
            return True
        except Exception as e:
            print("⚠ folder creation error:", e)

    # fallback
    local = "." + path
    os.makedirs(local, exist_ok=True)
    return True


# -----------------------------
# JSON upload
# -----------------------------
def upload_json(text: str, dropbox_path: str):
    return upload_bytes(text.encode(), dropbox_path)


# -----------------------------
# JSON download
# -----------------------------
def download_json(dropbox_path: str):
    data = download_bytes(dropbox_path)
    try:
        return data.decode()
    except:
        return data


# -----------------------------
# Delete file/folder
# -----------------------------
def delete_path(dropbox_path: str):
    path = ensure_path(dropbox_path)

    if dbx:
        try:
            dbx.files_delete_v2(path)
            return True
        except Exception as e:
            print("⚠ Dropbox delete failed:", e)

    # fallback
    local = "." + path
    if os.path.isdir(local):
        import shutil
        shutil.rmtree(local)
        return True
    if os.path.exists(local):
        os.remove(local)
        return True
    return False
