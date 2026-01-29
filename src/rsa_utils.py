from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_keypair(priv_path: str, pub_path: str, password: str | None = None) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    enc = serialization.NoEncryption()
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)


def load_public_key(pub_path: str):
    from cryptography.hazmat.primitives import serialization
    with open(pub_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(priv_path: str, password: str | None = None):
    from cryptography.hazmat.primitives import serialization
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password.encode("utf-8") if password else None
        )


def rsa_encrypt_key(aes_key: bytes, pub_path: str) -> bytes:
    pub = load_public_key(pub_path)
    return pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )


def rsa_decrypt_key(enc_key: bytes, priv_path: str, password: str | None = None) -> bytes:
    priv = load_private_key(priv_path, password=password)
    return priv.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
