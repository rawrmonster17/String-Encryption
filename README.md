# String-Encryption

This project provides a Python-based solution for encrypting and decrypting strings using a combination of ECC (Elliptic Curve Cryptography) and AES (Advanced Encryption Standard). The encryption process ensures both the confidentiality and integrity of the data.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Encrypting a String](#encrypting-a-string)
  - [Decrypting a String](#decrypting-a-string)
- [File Structure](#file-structure)
- [License](#license)

## Features

- **ECC Key Generation**: Generate ECC key pairs for secure encryption.
- **AES Encryption**: Encrypt data using AES-256 GCM for confidentiality.
- **ECDH Key Exchange**: Securely exchange AES keys using ECDH.
- **HMAC**: Ensure data integrity with HMAC.

## Requirements

- Python 3.10+
- `cryptography` library

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/string-encryption.git
    cd string-encryption
    ```

2. Create a virtual environment and activate it:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Encrypting a String

To encrypt a string, use the `-e` option followed by the string you want to encrypt:

```sh
python3 ./string-encryption.py -e "Your secret message"
```

### Decryption a String
```sh
To decrypt a string, use the '-d' option followed by the string you want to decrypt:

python3 ./string-encryption.py -d "Your encrypted string"
```
