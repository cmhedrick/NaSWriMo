# Day 02 of NaSWriMo
# Descrption: This is a simple example of creating a keypairs
# Packages: os, pycryptodomex
#
# Day 05 of NaSWriMo
# Descrption: Making this module more modular by putting code into functions!
# TBH gen-rsa-key.py is much better...
# Packages: os, pycryptodomex

import os
from Cryptodome.PublicKey import RSA

def gen_keypair():
    # generate generic key
    key = RSA.generate(2048)

    # set public key
    pubkey = key.publickey()

    # create dir to store keys in
    if not os.path.exists('keys'):
        os.makedirs('keys')

    # write keys to respective files in keys/ dir
    with open("keys/private.key", 'wb') as content_file:
        # using PEM (Privacy Enhanced Mail Format)
        content_file.write(key.exportKey('PEM'))

    with open("keys/public.key", 'wb') as content_file:
        content_file.write(pubkey.exportKey('PEM'))

if __name__ == "__main__":
    print("[-] Creating Keypair...")
    gen_keypair()
    print("[+] Keypairs generation complete!")