from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json , mmap
import os
import time
import base64
import argparse, sys

# Function to generate a master key
def generate_master_key(password, iterations, hash_alg, salt,len):
    kdf = PBKDF2HMAC(
        algorithm=hash_alg,
        length=len,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

# Function to generate an encryption key
def generate_encryption_key(master_key, hash_alg, len):
    return PBKDF2HMAC(
        algorithm=hash_alg,
        length=len,
        salt=b'Encryption key',
        iterations=1,
        backend=default_backend()
    ).derive(master_key)

# Function to generate an HMAC key
def generate_hmac_key(master_key, hash_alg):
    if isinstance(hash_alg, hashes.SHA256):
        len = 32
    elif isinstance(hash_alg, hashes.SHA512):
        len = 64
    return PBKDF2HMAC(
        algorithm=hash_alg,
        length=len,
        salt=b'HMAC key',
        iterations=1,
        backend=default_backend()
    ).derive(master_key)

# Function to create an HMAC
def create_hmac(algo, data, key):
    h = hmac.HMAC(key, algo, backend=default_backend())
    h.update(data)
    return h.finalize()

#Read Config_File
def read_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def verify_hmac(hmac_value, data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(hmac_value)


def encrypt_data(input_file, password, encryption_algorithm, hashing_algorithm, iterations, key_len_byte, JSON_hash_algo, JSON_Encrypt_algo):

    # Read the input file
    with open(input_file, 'rb') as f:
        data = f.read()

    # Generate a random salt
    salt = os.urandom(16)

    # Generate master key
    master_key = generate_master_key(password.encode(), iterations, hashing_algorithm, salt,key_len_byte)

    # Generate encryption and HMAC keys
    encryption_key = generate_encryption_key(master_key, hashing_algorithm, key_len_byte)
    hmac_key = generate_hmac_key(master_key, hashing_algorithm)

    # Generate a random IV
    iv = os.urandom(encryption_algorithm.block_size // 8)

    # Encrypt the data
    algo = encryption_algorithm(encryption_key)
  
    cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    #Create a PKCS7 padderr instance 
    padder = padding.PKCS7(algo.block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Create an HMAC
    hmac_value = create_hmac(hashing_algorithm,iv + encrypted_data, hmac_key)


    # Write the encrypted data to a file
    output_file_name = input_file + '.enc'
    with open(input_file + '.enc', 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)
        f.write(hmac_value)

    metadata = {
        'salt_base64' : base64.b64encode(salt).decode('utf-8'),
        'iterations' : iterations,
        'hash_algorithm': JSON_hash_algo ,
        'encryption_algoritm' : JSON_Encrypt_algo ,
        'iv_base64' :  base64.b64encode(iv).decode('utf-8')
    }

    with open('config.json', 'w') as f:
        json.dump(metadata, f, indent =4)

    print('Encryption complete. The encrypted file is saved as:', output_file_name)

def decrypt_data(encrypted_file, password):

    #Read the config file
    #get absolute path to current directory
    current_directory = os.path.dirname(os.path.abspath(__file__))
    config_file_path = os.path.join(current_directory,'config.json')
    config = read_config(config_file_path)
    hash_algorithm = config.get('hash_algorithm')
    encryption_algo = config.get('encryption_algoritm')
    iterations = config.get('iterations')
    salt_base64 = config.get('salt_base64')
    # iv_base64 = config.get('iv_base64')
    salt = base64.b64decode(salt_base64)  

    if encryption_algo == '3DES':
        key_len_byte = 24
        encryption_algorithm = algorithms.TripleDES
    elif encryption_algo == 'AES128':
        key_len_byte = 16
        encryption_algorithm = algorithms.AES
    elif encryption_algo == 'AES256':
        key_len_byte = 32
        encryption_algorithm = algorithms.AES

    if hash_algorithm == 'SHA256':
        hmac_value_len = 32
        hashing_algorithm = hashes.SHA256()
    elif hash_algorithm == 'SHA512':
        hmac_value_len = 64
        hashing_algorithm = hashes.SHA512()

    iv = os.urandom(encryption_algorithm.block_size // 8)   
    iv_len = len(iv)

    # Read the encrypted file
    with open(encrypted_file, 'rb') as f:
        file_size = os.path.getsize(encrypted_file)
            # Map the entire file into memory
        mmapped_file = mmap.mmap(f.fileno(), file_size, access=mmap.ACCESS_READ)
            
            # Read the IV 
        iv = mmapped_file[:iv_len]
            # Read the encrypted data (excluding IV and HMAC)
        encrypted_data = mmapped_file[iv_len:-hmac_value_len]
            
            # Read the HMAC value (last 32 bytes)
        hmac_value = mmapped_file[-hmac_value_len:]
            
            # Clean up: unmap the file
        mmapped_file.close() 

    # Generate master key
    master_key = generate_master_key(password.encode(), iterations, hashing_algorithm, salt,key_len_byte)
    
    # Generate encryption and HMAC keys
    encryption_key = generate_encryption_key(master_key, hashing_algorithm, key_len_byte)
    hmac_key = generate_hmac_key(master_key, hashing_algorithm)

    # Verify HMAC before decrypting to ensure data integrity
    try:
        h = hmac.HMAC(hmac_key, hashing_algorithm, backend=default_backend())
        h.update(iv+encrypted_data)
        h.verify(hmac_value)
        print('HMAC verification succeeded.')
    except Exception as e:
        print('HMAC verification failed:', str(e))
        return
    
    #Decrypt data
    algo = encryption_algorithm(encryption_key)
    cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algo.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data)
    decrypted_data += unpadder.finalize()

    # Write the decrypted data to a file
    output_file_name = encrypted_file
    output_file_name_without_extension = output_file_name.replace(".enc", "")
    with open(output_file_name_without_extension, 'wb') as f:
        f.write(decrypted_data)

    print('Decryption complete. The decrypted file is saved as:', output_file_name_without_extension)

# Main function
def main():
    parser = argparse.ArgumentParser(description='File Encryption Tool')
    parser.add_argument('operation', choices=['encrypt', 'decrypt'], help='Operation: encrypt or decrypt')
    parser.add_argument('input_file', help='Input file path')
    parser.add_argument('password', help='Password for encryption/decryption')
    parser.add_argument('encryption_algo', nargs = '?', choices=['3DES','AES256','AES128'], help='Encryption algorithm (e.g., AES)')
    parser.add_argument('hash_algo',nargs = '?', choices=['SHA256','SHA512'], help='Hash algorithm (e.g., SHA256)')
    parser.add_argument('iteration_count',nargs ='?', type=int, help='Number of iterations for key derivation')
    args = parser.parse_args(sys.argv[1:])


    if args.hash_algo == 'SHA256':
        hashing_algorithm = hashes.SHA256()
    elif args.hash_algo == 'SHA512':
        hashing_algorithm = hashes.SHA512()

    if args.encryption_algo == '3DES':
        key_len_byte = 24
        encryption_algorithm = algorithms.TripleDES
    elif args.encryption_algo == 'AES128':
        key_len_byte = 16
        encryption_algorithm = algorithms.AES
    elif args.encryption_algo == 'AES256':
        key_len_byte = 32
        encryption_algorithm = algorithms.AES

    iterations = args.iteration_count

    if args.operation not in ['encrypt', 'decrypt']:
        print("Operation has to be 'encrypt' or 'decrypt'")

    if args.operation == 'encrypt':
        encrypt_data(args.input_file, args.password, encryption_algorithm, hashing_algorithm, iterations, key_len_byte, args.hash_algo, args.encryption_algo )
    elif args.operation == 'decrypt':
        decrypt_data(args.input_file, args.password)

if __name__ == '__main__':
    main()
