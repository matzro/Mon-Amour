import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter

import account_management as am


BLOCK_SIZE = 16  # in bytes


def generate_key_pair(username: str, password: str) -> tuple[bytes, bytes]:
    """Generates a pair of RSA keys for the user, then serializes both and encrypts the private key.

    Args:
        username (str): Username of the keys' user.
        password (str): Password for the private key's AES encryption.

    Returns:
        tuple[bytes, bytes]: A tuple containing the user's public key and encrypted private key.
    """
    key = RSA.generate(2048)
    public_key: bytes = key.publickey().export_key()
    private_key: bytes = key.export_key()
    encrypted_private_key: bytes = encrypt_private_key_AES(private_key, password)

    return public_key, encrypted_private_key


def encrypt_private_key_AES(private_key: bytes, password: str) -> bytes:
    """Encrypts the private key with AES.

    Args:
        private_key (bytes): Private key to be encrypted.
        password (str): Encryption key for the private key.
    
    Returns:
        bytes: AES-encrypted private key.
    """
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CTR, counter=counter)
    encrypted_private_key: bytes = cipher.encrypt(private_key)

    return encrypted_private_key


def decrypt_private_key_AES(encrypted_private_key: bytes, password: str) -> bytes:
    """Decrypts the private key with AES.

    Args:
        encrypted_private_key (bytes): Private key to be decrypted.
        password (str): Encryption key for the private key.
    
    Returns:    
        bytes: AES-decrypted private key.
    """
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CTR, counter=counter)
    decrypted_private_key: bytes = cipher.decrypt(encrypted_private_key)

    return decrypted_private_key
