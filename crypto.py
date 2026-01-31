# crypto.py
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib

def get_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def aes_encrypt(data: bytes):
    key = get_random_bytes(32)  # AES-256
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return {
        "ciphertext": ct,
        "nonce": cipher.nonce,
        "tag": tag,
        "aes_key": key
    }

def aes_decrypt(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    return pt

def rsa_wrap_key(aes_key: bytes, public_key_path: str) -> bytes:
    # read public key and wrap AES key using RSA OAEP
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(public_key_path)
    pub = RSA.import_key(open(public_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(pub)
    return cipher_rsa.encrypt(aes_key)

def rsa_unwrap_key(wrapped: bytes, private_key_path: str) -> bytes:
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(private_key_path)
    priv = RSA.import_key(open(private_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(priv)
    return cipher_rsa.decrypt(wrapped)
