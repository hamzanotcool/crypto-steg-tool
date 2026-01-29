# 🔐 Crypto & Steganography Tool

> Educational cybersecurity project implementing AES-256-GCM encryption, RSA key wrapping,
> and LSB steganography in a Python CLI tool.

---

## 📌 Description

This project is a command-line tool (CLI) written in Python that allows:

- Secure file encryption and decryption using AES-256-GCM
- Hybrid cryptography using RSA-2048 (OAEP) to protect AES keys
- Hiding secret messages inside images using LSB steganography

The goal of this project is educational, to demonstrate practical skills in
modern cryptography, key management, and secure software development.

---

## 🧠 Security Concepts Used

Symmetric encryption: AES-256-GCM  
Asymmetric encryption: RSA-2048 with OAEP  
Hybrid cryptography: RSA protects AES keys  
Integrity: GCM authentication tag  
Steganography: LSB (Least Significant Bit)  
Platform: Linux CLI  

---

## 📁 Project Structure

crypto-steg-tool/
├── src/
│   ├── main.py            # Main CLI entry point
│   ├── crypto_utils.py    # AES-GCM implementation
│   ├── rsa_utils.py       # RSA key management
│   └── steg_lsb.py        # LSB steganography
├── samples/               # Sample images for steganography demo
├── requirements.txt
└── README.md

---

## ⚙ Installation (Linux)

git clone https://github.com/hamzanotcool/crypto-steg-tool.git  
cd crypto-steg-tool  

python3 -m venv .venv  
source .venv/bin/activate  
pip install -r requirements.txt  

---

## 🔑 Generate RSA Keys

Generate a RSA-2048 key pair (private key protected with a password):

python src/main.py keygen --password "test123"

This will create:
- private.pem → RSA private key (encrypted)
- public.pem → RSA public key

---

## 🔐 Encrypt a File (AES-GCM)

Create a test file:

echo "top secret" > secret.txt

Encrypt it using AES-256-GCM:

python src/main.py aes-encrypt -i secret.txt -o secret.enc --key-out aes.key

---

## 🔑 Hybrid Encryption (RSA + AES)

Encrypt the AES key using the RSA public key:

python src/main.py wrap-key --aes-key aes.key --public public.pem -o aes.key.rsa

For security reasons, the AES key can then be securely deleted:

shred -u aes.key

---

## 🔓 Decrypt the File

Decrypt the AES key using the RSA private key:

python src/main.py unwrap-key --enc-key aes.key.rsa --private private.pem --password "test123" -o aes.key

Decrypt the encrypted file:

python src/main.py aes-decrypt -i secret.enc -o out.txt --key aes.key

Verify the result:

cat out.txt

---

## 🖼 Steganography (LSB)

Hide a secret message inside an image:

python src/main.py steg-hide -i samples/image.png -o image_steg.png -m "Hidden secret message"

Extract the hidden message:

python src/main.py steg-extract -i image_steg.png

PNG format is required.  
JPEG compression destroys hidden LSB data.

---

## ⚠ Limitations & Security Notes

- LSB steganography is detectable via statistical analysis
- This tool is not intended for production use
- Private RSA keys must be stored securely
- Images should not be recompressed after embedding data

---

## 🎓 What This Project Demonstrates

- Understanding of modern cryptography (AES-GCM, RSA-OAEP)
- Hybrid encryption and key management
- Practical steganography techniques
- Secure coding practices
- Linux command-line usage
- Git and GitHub workflow

---

## 📜 License

This project is provided for educational purposes only.
