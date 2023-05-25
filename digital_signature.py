from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import account_management as am
import file_management as fm
import rsa_functions as rf

BLOCK_SIZE = 16  # 128 bits


def generate_signature(message, username, password):
    """This function generates a digital signature of the message, using the private key of the sender. First, we read
    the private key from a file. Then, we decrypt the private key with the secret key of the user. Then, we hash the
    message and generate the digital signature.
    :param message: The message to be signed
    :param username: The username of the sender
    :param password: Encryption key for the private key
    :return: signature
    """
    with open(am.get_private_key_path(username), 'rb') as f:
        private_key = f.read()

    decrypted_private_key = rf.decrypt_private_key_AES(private_key, password)
    decrypted_private_key = RSA.import_key(decrypted_private_key)

    hash_value = SHA256.new(message.encode("utf-8"))
    signature = PKCS1_v1_5.new(decrypted_private_key).sign(hash_value)

    return signature


def verify_signature(message, signature, username):
    """This function verifies the digital signature of the message, using the public key of the sender. First, we read
    the public key from a file. Then, we hash the message and verify the digital signature. If the signature is valid,
    it returns True. If not, it returns False.
    :param message: The message to be verified
    :param signature: The digital signature of the message
    :param username: The username of the sender
    :return: verification
    """
    public_key = fm.import_public_key(username)
    hash_value = SHA256.new(message.encode("utf-8"))
    verification = PKCS1_v1_5.new(public_key).verify(hash_value, signature)

    return verification
