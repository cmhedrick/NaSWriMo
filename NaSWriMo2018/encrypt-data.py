# Day 04 of NaSWriMo
# Description: Learning how to Encrypt and decrypt data with RSA Keypairs
# Packages: Cryptodome
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

def encrypt_data(file_path = False):
    if not file_path:
        # create dir to store keys in
        if not os.path.exists('demo'):
            os.makedirs('demo')

        # check if public key exists
        if os.path.isfile("keys/public.key"):
            with open("keys/public.key", 'rb') as content_file:
                recipient_key = RSA.import_key(content_file.read())
        else:
            # should terminate script
            print("[!] Please Gen Keypair (i.e:gen-keypair.py)")
            return

        # example data
        data = "Super secret original text of secrets".encode("utf-8")
        
        # create session key for encryption and decryption
        session_key = get_random_bytes(16)

        # encrypt the session key with the public RSA key w/ asymmetric encrypt
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # encrypt the data with the AES session key and EAX mode of ops to
        # detect unauthorized modifications
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        with open("demo/encrypted.bin", 'wb') as content_file:
            [ 
                content_file.write(x) for x in (
                    enc_session_key,
                    cipher_aes.nonce,
                    tag,
                    ciphertext
                )
            ]        

def decrypt_data(file_path = False):
    # read in private key from file
    with open("keys/private.key", 'rb') as private_key_file:
        private_key = RSA.import_key(private_key_file.read())

    # open up encrypted file
    with open("demo/encrypted_data.bin", "rb") as content_file:
        enc_session_key, nonce, tag, ciphertext = [ 
            content_file.read(x) 
            for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print(data.decode("utf-8"))

if __name__ == "__main__":
    print("[-] Encrypting Data First...")
    encrypt_data()
    print("[+] Encryption complete...")
    print("[-] Attempting decryption...")
    decrypt_data()