import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter

import account_management as am


BLOCK_SIZE = 16  # 128 bits


def generate_key_pair(username, password):
    # Generate a new RSA key pair
    key = RSA.generate(2048)

    # Serialize the public and private keys to PEM files
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    encrypted_private_key = encrypt_private_key_AES(private_key, password)

    return public_key, encrypted_private_key


def encrypt_private_key_AES(private_key, password):
    """Encrypts the private key with AES.
    :param private_key: Private key to be encrypted
    :param password: Encryption key for the private key
    :return: AES-encrypted private key
    """
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CTR, counter=counter)
    encrypted_private_key = cipher.encrypt(private_key)

    return encrypted_private_key


def decrypt_private_key_AES(encrypted_private_key, password):
    """Decrypts the private key with AES.
    :param encrypted_private_key: Private key to be decrypted
    :param password: Encryption key for the private key
    :return: AES-decrypted private key
    """
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CTR, counter=counter)
    decrypted_private_key = cipher.decrypt(encrypted_private_key)

    return decrypted_private_key
