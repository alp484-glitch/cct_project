# AES-GCM Example (requires cryptography library: pip install cryptography)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_key():
    # Generate a 256-bit AES key
    return AESGCM.generate_key(bit_length=256)

def encrypt(plaintext: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": nonce, "ciphertext": ct}

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

# Example Usage
if __name__ == "__main__":
    key = generate_key()
    data = b"I like CCT college"
    print(f"plaintext: {data.decode()}")
    enc = encrypt(data, key)
    print(f"key: {key.hex()}")
    print(f"nonce: {enc['nonce'].hex()}")
    print(f"ciphertext: {enc['ciphertext'].hex()}")
    pt = decrypt(enc["nonce"], enc["ciphertext"], key)
    print("Decrypted:", pt.decode())
