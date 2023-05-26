from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import account_management as am
import file_management as fm
import rsa_functions as rf


BLOCK_SIZE = 16  # in bytes


def generate_signature(message: str, username: str, password: str) -> bytes:
    """This function generates a digital signature of the message, using the private key of the sender. 
    
    The sender's private key is read from a file, then it is decrypted with the secret key of the user and lastly,
    the message is hashed and the digital signature is generated.

    Args:
        message (str): The message to be signed.
        username (str): The username of the sender.
        password (str): Encryption key for the private key.

    Returns: 
        bytes: Sender's digital signature of the message.
    """
    with open(am.get_private_key_path(username), 'rb') as f:
        private_key = f.read()

    decrypted_private_key: bytes = rf.decrypt_private_key_AES(private_key, password)
    decrypted_private_key: RSA.RsaKey = RSA.import_key(decrypted_private_key)

    hash_value = SHA256.new(message.encode("utf-8"))
    signature: bytes = PKCS1_v1_5.new(decrypted_private_key).sign(hash_value)

    return signature


def verify_signature(message: str, signature: bytes, username: str) -> bool:
    """This function verifies the digital signature of the message, using the public key of the sender. 
    
    The sender's public key is read from a file, then the message is hashed and the digital signature is verified.

    Args:
        message (str): The message to be verified.
        signature (bytes): The digital signature of the message.
        username (str): The username of the message's sender.

    Returns:
        bool: True if the signature is valid, False if not.
    """
    public_key: RSA.RsaKey = fm.import_public_key(username)
    hash_value = SHA256.new(message.encode("utf-8"))
    verification: bool = PKCS1_v1_5.new(public_key).verify(hash_value, signature)

    return verification
