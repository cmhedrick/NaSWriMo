# Day 03 of NaSWriMo
# Description: In this example, an interface is used to generate an RSA keypair 
# protected by a password. This is an improvement of the gen-keypair.py (Day 02)
# as it provides an extra layer of security. A part of the encryption for the
# new RSA key, the code will use AES128 encryption with the CBC (Cipher Block
# Chaining). CBC is used by many SSL/TLS cipher suites, and is often the most
# recommended Modes of Operation for security (as long as it's implemented 
# properly).
# 
# Packages: Cryptodome

import os
from Cryptodome.PublicKey import RSA

def create_keys_dir():
    # create dir to store keys in
    if not os.path.exists('keys'):
        os.makedirs('keys')

def gen_encrypted_key(passphrase):
    key = RSA.generate(2048)
    encrypted_key = key.export_key(
        passphrase=passphrase, 
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )
    with open("keys/encrypted_private.key", 'wb') as content_file:
        content_file.write(encrypted_key)

    print(key.publickey().export_key())

def decrypt_key(passphrase):
    try:
        with open("keys/encrypted_private.key", 'rb') as content_file:
            encoded_key = content_file.read()

        key = RSA.import_key(encoded_key, passphrase=passphrase)

        print(key.publickey().export_key())
    except ValueError:
        print("[X] INCORRECT PASSPHRASE")

if __name__ == "__main__":
    create_keys_dir()
    passphrase = input("Passphrase==> ")
    # check if file exists
    if not os.path.isfile("keys/encrypted_private.key"):
        # gen encrypted RSA key
        gen_encrypted_key(passphrase)
    else:
        print("[!] File exists")
    input("Decrypt (Press any key)")
    decrypt_key(passphrase)