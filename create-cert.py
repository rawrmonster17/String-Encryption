#!/usr/bin/env python3
import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization


def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP521R1())
    private_key_path = "ecc_private_key.pem"
    public_key_path = "ecc_public_key.pem"

    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_key_path, 0o600)

    with open(public_key_path, "wb") as public_file:
        public_file.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"ECC key pair saved as '{private_key_path}' and '{public_key_path}'")


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_path = "rsa_private_key.pem"
    public_key_path = "rsa_public_key.pem"

    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_key_path, 0o600)

    with open(public_key_path, "wb") as public_file:
        public_file.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"RSA key pair saved as '{private_key_path}' and '{public_key_path}'")


def main():
    generate_ecc_key_pair()
    generate_rsa_key_pair()


if __name__ == "__main__":
    main()
