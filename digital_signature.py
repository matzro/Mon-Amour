import hashlib

from Crypto.PublicKey import RSA
from Crypto.Util import Counter

import file_management as fm

from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

BLOCK_SIZE = 16  # 128 bits


def generate_signature(message, username, secret_for_private):
    with open(f'private_key_{username}.pem', 'rb') as f:
        private_key = f.read()
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(secret_for_private, AES.MODE_CTR, counter=counter)
    decrypted_private = cipher.decrypt(private_key)

    # Convert decrypted private key to RSA object
    decrypted_private = RSA.import_key(decrypted_private)

    # Hash message
    hash_value = SHA256.new(message.encode("utf-8"))
    # Generate digital signature
    signature = PKCS1_v1_5.new(decrypted_private).sign(hash_value)
    return signature


def verify_signature(message, signature, username):
    # Get public key
    public_key = fm.import_public_key(username)
    # Hash message
    hash_value = SHA256.new(message.encode("utf-8"))
    # Verify digital signature
    verification = PKCS1_v1_5.new(public_key).verify(hash_value, signature)
    return verification
