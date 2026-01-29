import argparse
from crypto_utils import aes_encrypt_file, aes_decrypt_file
from rsa_utils import generate_rsa_keypair, rsa_encrypt_key, rsa_decrypt_key
from steg_lsb import hide_bytes_in_image, extract_bytes_from_image

def cmd_keygen(args):
    generate_rsa_keypair(args.private, args.public, password=args.password)
    print(" Clés RSA générées.")

def cmd_aes_encrypt(args):
    key = aes_encrypt_file(args.input, args.output, key=None)
    with open(args.key_out, "wb") as f:
        f.write(key)
    print(" Fichier chiffré AES-GCM.")
    print(f" Clé AES sauvegardée dans: {args.key_out}")

def cmd_aes_decrypt(args):
    with open(args.key, "rb") as f:
        key = f.read()
    aes_decrypt_file(args.input, args.output, key=key)
    print(" Fichier déchiffré AES-GCM.")

def cmd_wrap_key(args):
    with open(args.aes_key, "rb") as f:
        key = f.read()
    enc = rsa_encrypt_key(key, args.public)
    with open(args.out, "wb") as f:
        f.write(enc)
    print(" Clé AES chiffrée avec RSA (OAEP).")

def cmd_unwrap_key(args):
    with open(args.enc_key, "rb") as f:
        enc = f.read()
    key = rsa_decrypt_key(enc, args.private, password=args.password)
    with open(args.out, "wb") as f:
        f.write(key)
    print(" Clé AES déchiffrée avec RSA (OAEP).")

def cmd_steg_hide(args):
    payload = args.message.encode("utf-8")
    hide_bytes_in_image(args.input, args.output, payload)
    print(" Message caché dans l’image (PNG).")

def cmd_steg_extract(args):
    payload = extract_bytes_from_image(args.input)
    print(payload.decode("utf-8", errors="replace"))

def build_parser():
    p = argparse.ArgumentParser(prog="crypto-steg", description="Outil Crypto + Stéganographie (AES/RSA + LSB)")
    sub = p.add_subparsers(required=True)

    s = sub.add_parser("keygen", help="Générer une paire RSA")
    s.add_argument("--private", default="private.pem")
    s.add_argument("--public", default="public.pem")
    s.add_argument("--password", default=None, help="Mot de passe pour chiffrer la clé privée (optionnel)")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("aes-encrypt", help="Chiffrer un fichier avec AES-GCM")
    s.add_argument("-i", "--input", required=True)
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--key-out", default="aes.key", help="Fichier où stocker la clé AES")
    s.set_defaults(func=cmd_aes_encrypt)

    s = sub.add_parser("aes-decrypt", help="Déchiffrer un fichier AES-GCM")
    s.add_argument("-i", "--input", required=True)
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--key", required=True, help="Fichier contenant la clé AES")
    s.set_defaults(func=cmd_aes_decrypt)

    s = sub.add_parser("wrap-key", help="Chiffrer une clé AES avec la clé publique RSA")
    s.add_argument("--aes-key", required=True)
    s.add_argument("--public", required=True)
    s.add_argument("-o", "--out", default="aes.key.rsa")
    s.set_defaults(func=cmd_wrap_key)

    s = sub.add_parser("unwrap-key", help="Déchiffrer une clé AES avec la clé privée RSA")
    s.add_argument("--enc-key", required=True)
    s.add_argument("--private", required=True)
    s.add_argument("--password", default=None)
    s.add_argument("-o", "--out", default="aes.key")
    s.set_defaults(func=cmd_unwrap_key)

    s = sub.add_parser("steg-hide", help="Cacher un message texte dans une image PNG (LSB)")
    s.add_argument("-i", "--input", required=True, help="Image source (PNG recommandé)")
    s.add_argument("-o", "--output", required=True, help="Image sortie (PNG)")
    s.add_argument("-m", "--message", required=True)
    s.set_defaults(func=cmd_steg_hide)

    s = sub.add_parser("steg-extract", help="Extraire un message caché d'une image")
    s.add_argument("-i", "--input", required=True)
    s.set_defaults(func=cmd_steg_extract)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
