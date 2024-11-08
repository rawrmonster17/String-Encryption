#!/usr/bin/env python3
import argparse
import base64
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.backends import default_backend

# Define key file names
RSA_PUBLIC_KEY = "rsa_public_key.pem"
RSA_PRIVATE_KEY = "rsa_private_key.pem"
ECC_PUBLIC_KEY = "ecc_public_key.pem"
ECC_PRIVATE_KEY = "ecc_private_key.pem"


def encrypt_data_with_ecc(data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    with open(ECC_PUBLIC_KEY, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Expected ECC key.")

    ephemeral_private_key = ec.generate_private_key(
        ec.SECP521R1(), default_backend()
    )
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    salt = secrets.token_bytes(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption",
        backend=default_backend()
    ).derive(shared_key)
    ephemeral_public_key = ephemeral_private_key.public_key()
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encrypt data using AES-GCM with the derived key
    aesgcm = aead.AESGCM(derived_key)
    iv = secrets.token_bytes(12)  # GCM standard uses a 12-byte IV
    encrypted_data = aesgcm.encrypt(iv, data, None)

    return ephemeral_public_bytes, encrypted_data, salt, iv


# RSA encryption
def encrypt_data_with_rsa(data: bytes) -> bytes:
    with open(RSA_PUBLIC_KEY, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Expected RSA key.")

    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


# RSA decryption
def decrypt_data_with_rsa(encrypted_data: bytes) -> bytes:
    with open(RSA_PRIVATE_KEY, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data


# ECC-based decryption with AEAD
def decrypt_data_with_ecc(
    ephemeral_public_bytes: bytes,
    encrypted_data: bytes,
    salt: bytes,
    iv: bytes
) -> bytes:
    with open(ECC_PRIVATE_KEY, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    ephemeral_public_key = serialization.load_pem_public_key(
        ephemeral_public_bytes
    )
    if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Ephemeral public key is not an ECC key.")

    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"encryption",
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt data using AES-GCM with the derived key
    aesgcm = aead.AESGCM(derived_key)
    decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)
    return decrypted_data


# Main command-line interface
def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a message."
    )
    group = parser.add_mutually_exclusive_group(
        required=True
    )
    group.add_argument("-e", "--encrypt", help="String to encrypt")
    group.add_argument(
        "-d",
        "--decrypt",
        help="String to decrypt (base64 encoded)"
    )
    args = parser.parse_args()

    if args.encrypt:
        # First, encrypt with ECC
        ephemeral_public, ecc_encrypted_data, salt, iv = encrypt_data_with_ecc(
            args.encrypt.encode()
        )
        print("First layer ECC encryption completed.")

        # Then, encrypt the ECC output with RSA
        rsa_encrypted_data = encrypt_data_with_rsa(ecc_encrypted_data)
        print("Second layer RSA encryption completed.")

        # Prepare the output with all necessary components
        components = [
            base64.b64encode(ephemeral_public).decode(),
            base64.b64encode(rsa_encrypted_data).decode(),
            base64.b64encode(salt).decode(),
            base64.b64encode(iv).decode()
        ]
        combined_data = "|".join(components)
        print("Encrypted output:", combined_data)

    elif args.decrypt:
        # Split and decode the input into components
        parts = args.decrypt.split("|")
        if len(parts) != 4:
            raise ValueError("Invalid input format for decryption.")

        ephemeral_public = base64.b64decode(parts[0])
        rsa_encrypted_data = base64.b64decode(parts[1])
        salt = base64.b64decode(parts[2])
        iv = base64.b64decode(parts[3])

        # First, decrypt the RSA layer to retrieve the ECC-encrypted data
        ecc_encrypted_data = decrypt_data_with_rsa(rsa_encrypted_data)
        print("First layer RSA decryption completed.")

        # Then, decrypt the ECC layer to retrieve the original data
        decrypted_data = decrypt_data_with_ecc(
            ephemeral_public, ecc_encrypted_data, salt, iv
        )
        print("Second layer ECC decryption completed.")
        print("Decrypted message:", decrypted_data.decode())


if __name__ == "__main__":
    main()
