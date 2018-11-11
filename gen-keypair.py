# Day 2 of NaSWriMo
# This is a simple example of creating a keypairs
# Packages: os, pycryptodomex
#

import os
from Cryptodome.PublicKey import RSA

# generate generic key
key = RSA.generate(2048)

# set public key
pubkey = key.publickey()

# create dir to store keys in
if not os.path.exists('keys'):
    os.makedirs('keys')

# write keys to respective files in keys/ dir
with open("keys/private.key", 'wb') as content_file:
    content_file.write(key.exportKey('PEM'))

with open("keys/public.key", 'wb') as content_file:
    content_file.write(pubkey.exportKey('PEM'))
