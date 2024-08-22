# File Encryption Utility

## Overview

- This project is a file encryption utility that provides encryption and decryption capabilities. It is implemented in Python using the `cryptography` library.

- The utility stores the metadata necessary for encryption and decryption in a `Config.json` file. This metadata includes details such as the algorithms used during the encryption process, which are essential for successful decryption.

- The encryption and decryption operations are managed within the same Python script but are triggered through different command-line arguments. The code has been tested with `.txt` and `.jpg` files.

- Upon encryption, the utility generates a new file with a `.enc` extension in the same directory as the original file. The decryption function restores the file to its original format and content. HMAC verification will fail if the encrypted file is tampered with.


## Requirements

- Python 3.x
- `cryptography` library

To install the `cryptography` library, run:

```bash
pip install cryptography


Usage:

To Encrypt a File:

```bash
python EncryptionTool.py encrypt --input_file ./test.txt --password [password] --encryption_algorithm aes-256 --hashing_algorithm sha512 --iterations 10000


To Decrypt a file:

```bash
python EncryptionTool.py decrypt --input_file ./test.txt.enc --password [password]
