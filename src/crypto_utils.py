import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CS1"  # header simple pour identifier notre format

def aes_encrypt_file(in_path: str, out_path: str, key: bytes | None = None) -> bytes:
    """
    Chiffre un fichier avec AES-GCM.
    Format: MAGIC(3) | nonce(12) | ciphertext+tag
    Retourne la clé AES utilisée.
    """
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    if len(key) != 32:
        raise ValueError("Clé AES doit faire 32 octets (AES-256).")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    with open(in_path, "rb") as f:
        data = f.read()

    ct = aesgcm.encrypt(nonce, data, associated_data=None)

    with open(out_path, "wb") as f:
        f.write(MAGIC + nonce + ct)

    return key


def aes_decrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    with open(in_path, "rb") as f:
        blob = f.read()

    if len(blob) < 3 + 12 + 16:
        raise ValueError("Fichier chiffré invalide (trop court).")
    if blob[:3] != MAGIC:
        raise ValueError("Header MAGIC invalide (pas un fichier CS1).")

    nonce = blob[3:15]
    ct = blob[15:]

    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)

    with open(out_path, "wb") as f:
        f.write(pt)
