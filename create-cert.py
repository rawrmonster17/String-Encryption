#!/usr/bin/env python3
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ecc_key_pair():
    # Generate private key with SECP521R1 curve
    private_key = ec.generate_private_key(
        ec.SECP521R1()  # Use SECP521R1 for stronger security
    )

    # Generate public key
    public_key = private_key.public_key()

    # Save private key to file with restricted permissions
    private_key_path = "ecc_private_key.pem"
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_key_path, 0o600)  # Set file permissions to read/write for the owner only

    # Save public key to file
    public_key_path = "ecc_public_key.pem"
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"ECC key pair generated and saved as '{private_key_path}' and '{public_key_path}'")

# Main function to generate the ECC key pair
def main():
    generate_ecc_key_pair()

if __name__ == "__main__":
    main()
