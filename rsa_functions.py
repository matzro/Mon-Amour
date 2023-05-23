from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES  # para que serve isto?
from Crypto.Util import Counter

import file_management as fm

BLOCK_SIZE = 16  # 128 bits


def generate_key_pair(username, secret_key):
    """Generates a RSA key pair, then encrypts the private key with AES and saves both keys to files.
    :param username: To generate the key pair for the username
    :param secret_key: Encryption key for the private key
    :return: private_key, public_key
    """
    key = RSA.generate(2048)

    private_key = key.export_key()
    encrypted_private = encrypt_private_key_AES(private_key, secret_key)
    with open(f'private_key_{username}.pem', 'wb') as f:
        f.write(encrypted_private)

    public_key = key.publickey().export_key()
    with open(f'public_key_{username}.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


def encrypt_private_key_AES(private_key_str, secret_key):
    """Encrypts the private key with AES.
    :param private_key_str: Private key to be encrypted
    :param secret_key: Encryption key for the private key
    :return: ciphertext
    """
    counter = Counter.new(nbits=BLOCK_SIZE * 8)

    cipher = AES.new(secret_key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(private_key_str)

    return ciphertext


def encrypt_secret_key(secret_for_private, username):
    """Encrypts the secret key with the public key of the user.
    :param secret_for_private: Secret key to be encrypted
    :param username: To get the public key of the user
    :return: encrypted_secret_key
    """
    public_key = fm.import_public_key(username)
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_secret_key = cipher_rsa.encrypt(secret_for_private)
    return encrypted_secret_key


def decrypt_secret_key(encrypted_secret_key, username, secret_for_private):
    """Decrypts the secret key with the private key of the user.
    :param encrypted_secret_key: Secret key to be decrypted
    :param username: To get the private key of the user
    :param secret_for_private: Encryption key for the private key
    :return: decrypted_secret_key
    """
    with open(f'private_key_{username}.pem', 'rb') as f:
        private_key = f.read()
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(secret_for_private, AES.MODE_CTR, counter=counter)
    decrypted_private = cipher.decrypt(private_key)

    decrypted_private = RSA.import_key(decrypted_private)

    cipher_rsa = PKCS1_v1_5.new(decrypted_private)
    decrypted_secret_key = cipher_rsa.decrypt(encrypted_secret_key, None)
    return decrypted_secret_key
