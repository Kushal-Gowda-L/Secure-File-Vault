# generate_keys.py
import os
from Crypto.PublicKey import RSA

def generate_keys_for_email(email: str):
    os.makedirs("keys", exist_ok=True)
    priv_path = f"keys/{email}_private.pem"
    pub_path = f"keys/{email}_public.pem"

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return priv_path, pub_path

    key = RSA.generate(2048)
    with open(priv_path, "wb") as f:
        f.write(key.export_key())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    return priv_path, pub_path

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--email", required=True)
    args = p.parse_args()
    generate_keys_for_email(args.email)
    print("keys created for", args.email)
