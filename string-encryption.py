#!/usr/bin/env python3
import argparse
import hashlib
import base64
import secrets
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.backends import default_backend

# Function to encrypt data using AES-256 GCM
def encrypt_with_aes_gcm(data: bytes, aes_key: bytes) -> (bytes, bytes):
    aesgcm = aead.AESGCM(aes_key)
    iv = secrets.token_bytes(12)  # GCM standard uses a 12-byte nonce/IV
    encrypted_data = aesgcm.encrypt(iv, data, None)
    return encrypted_data, iv

# Function to decrypt data using AES-256 GCM
def decrypt_with_aes_gcm(encrypted_data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    aesgcm = aead.AESGCM(aes_key)
    return aesgcm.decrypt(iv, encrypted_data, None)

# Function to encrypt the AES key using ECDH shared secret
def encrypt_aes_key_with_ecc(aes_key: bytes, public_key_path: str) -> (bytes, bytes):
    # Load the ECC public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Generate a new private key for ECDH
    ephemeral_private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key from the shared key using HKDF with a salt
    salt = secrets.token_bytes(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption",
        backend=default_backend()
    ).derive(shared_key)

    # Encrypt the AES key using the derived symmetric key
    encrypted_aes_key, iv = encrypt_with_aes_gcm(aes_key, derived_key)

    # Return the ephemeral public key, encrypted AES key, salt, and IV
    ephemeral_public_key = ephemeral_private_key.public_key()
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ephemeral_public_bytes, encrypted_aes_key, iv, salt

# Function to decrypt the AES key using ECDH shared secret
def decrypt_aes_key_with_ecc(encrypted_aes_key: bytes, ephemeral_public_bytes: bytes, private_key_path: str, iv: bytes, salt: bytes) -> bytes:
    # Load the ECC private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Load the ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes, backend=default_backend())

    # Perform ECDH to derive the shared key
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive the symmetric key using HKDF with the provided salt
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption",
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt the AES key using the derived symmetric key
    aes_key = decrypt_with_aes_gcm(encrypted_aes_key, derived_key, iv)
    return aes_key

# Function to generate HMAC for the data
def generate_hmac(data: bytes, key: bytes) -> bytes:
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a message.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="String to encrypt")
    group.add_argument("-d", "--decrypt", help="String to decrypt (base64 encoded)")
    parser.add_argument("--public-key", default="ecc_public_key.pem", help="Path to the ECC public key file")
    parser.add_argument("--private-key", default="ecc_private_key.pem", help="Path to the ECC private key file")

    args = parser.parse_args()

    if args.encrypt:
        # Encrypt the message
        aes_key = secrets.token_bytes(32)  # Generate a new AES-256 key
        encrypted_data, iv_data = encrypt_with_aes_gcm(args.encrypt.encode(), aes_key)
        ephemeral_public, encrypted_aes_key, iv_key, salt = encrypt_aes_key_with_ecc(aes_key, args.public_key)

        # Generate HMAC for integrity verification
        hmac_key = secrets.token_bytes(32)
        hmac_value = generate_hmac(encrypted_data + iv_data, hmac_key)

        # Concatenate all components and encode as base64
        combined_data = b"".join([
            base64.b64encode(ephemeral_public) + b"|",
            base64.b64encode(encrypted_aes_key) + b"|",
            base64.b64encode(iv_key) + b"|",
            base64.b64encode(salt) + b"|",
            base64.b64encode(iv_data) + b"|",
            base64.b64encode(encrypted_data) + b"|",
            base64.b64encode(hmac_key) + b"|",
            base64.b64encode(hmac_value)
        ])
        print("Encrypted output:", combined_data.decode())

    elif args.decrypt:
        # Split the combined input into components
        parts = args.decrypt.encode().split(b"|")
        if len(parts) != 8:
            raise ValueError("Invalid input format for decryption.")

        # Decode each component from base64
        ephemeral_public = base64.b64decode(parts[0])
        encrypted_aes_key = base64.b64decode(parts[1])
        iv_key = base64.b64decode(parts[2])
        salt = base64.b64decode(parts[3])
        iv_data = base64.b64decode(parts[4])
        encrypted_data = base64.b64decode(parts[5])
        hmac_key = base64.b64decode(parts[6])
        hmac_value = base64.b64decode(parts[7])

        # Verify HMAC before proceeding
        expected_hmac = generate_hmac(encrypted_data + iv_data, hmac_key)
        if not hmac.compare_digest(expected_hmac, hmac_value):
            raise ValueError("HMAC verification failed. Data integrity check failed.")

        # Decrypt the AES key and then the data
        aes_key = decrypt_aes_key_with_ecc(encrypted_aes_key, ephemeral_public, args.private_key, iv_key, salt)
        decrypted_data = decrypt_with_aes_gcm(encrypted_data, aes_key, iv_data)
        print("Decrypted message:", decrypted_data.decode())

if __name__ == "__main__":
    main()
