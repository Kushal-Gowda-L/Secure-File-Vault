from Crypto.PublicKey import RSA

email = "alice@example.com"

key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

with open(f"keys/{email}_private.pem", "wb") as f:
    f.write(private_key)

with open(f"keys/{email}_public.pem", "wb") as f:
    f.write(public_key)

print("✅ Keys generated for:", email)
