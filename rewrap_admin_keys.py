import json
from cloud import download_bytes, upload_bytes
from crypto import rsa_wrap_key, rsa_unwrap_key
from roles import load_roles
from config import FILES_ROOT


def find_existing_wrapped_key(folder, users):
    """Return (email, wrapped_key_bytes) of the first user who has a wrapped AES key."""
    for user in users:
        path = f"{folder}/wrapped_{user}.bin"
        try:
            data = download_bytes(path)
            print(f"✅ Found wrapped key for: {user}")
            return user, data
        except:
            pass

    print("❌ No wrapped keys found for ANY user")
    return None, None


def rewrap_for_admins(file_id, roles):
    folder = f"{FILES_ROOT}/{file_id}"

    file_meta = roles["files"][file_id]
    owner = file_meta["owner"]
    recipients = file_meta["recipients"]

    # All users that might already have wrapped keys
    possible_wrapped_users = [owner] + recipients

    print(f"\n🔍 Searching wrapped keys for file {file_id}")
    print("Possible existing users:", possible_wrapped_users)

    # Find first available wrapped key
    existing_user, wrapped_key = find_existing_wrapped_key(folder, possible_wrapped_users)
    if not existing_user:
        print(f"❌ Cannot rewrap file {file_id}, no wrapped keys found.")
        return

    # Decrypt AES key using the existing user's private key
    try:
        aes_key = rsa_unwrap_key(wrapped_key, f"keys/{existing_user}_private.pem")
        print(f"✅ Decrypted AES key using {existing_user}'s private key")
    except Exception as e:
        print(f"❌ Failed to decrypt AES key using {existing_user}: {e}")
        return

    # Rewrap for ALL admins
    admins = [email for email, info in roles["users"].items() if info["role"] == "admin"]

    print("🔐 Rewrapping AES key for admins:", admins)

    for admin in admins:
        pubkey_path = f"keys/{admin}_public.pem"
        try:
            new_wrapped = rsa_wrap_key(aes_key, pubkey_path)
            upload_bytes(new_wrapped, f"{folder}/wrapped_{admin}.bin")
            print(f"✅ Added wrapped key for admin: {admin}")
        except Exception as e:
            print(f"❌ Failed to wrap key for {admin}: {e}")

    print(f"✅ FINISHED rewrapping for file: {file_id}\n")


def main():
    roles = load_roles()

    all_files = list(roles["files"].keys())

    if not all_files:
        print("❌ No files found in vault.")
        return

    print("✅ Starting rewrap process for all files...")
    for fid in all_files:
        rewrap_for_admins(fid, roles)

    print("\n✅✅ All files processed successfully ✅✅")


if __name__ == "__main__":
    main()
