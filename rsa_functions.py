from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5  # para que serve isto?
import file_management as fm


def generate_key_pair(username):
    # Generate a new RSA key pair
    key = RSA.generate(2048)

    # Serialize the private key to a PEM file
    private_key = key.export_key()
    with open(f'private_key_{username}.pem', 'wb') as f:
        f.write(private_key)

    # Serialize the public key to a PEM file
    public_key = key.publickey().export_key()
    with open(f'public_key_{username}.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


def encrypt_secret_key(secret_key, username):
    # load public key
    public_key = fm.import_public_key(username)
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_secret_key = cipher_rsa.encrypt(secret_key)
    return encrypted_secret_key


def decrypt_secret_key(encrypted_secret_key, username):
    # load private key
    private_key = fm.import_private_key(username)
    cipher_rsa = PKCS1_v1_5.new(private_key)
    decrypted_secret_key = cipher_rsa.decrypt(encrypted_secret_key, None)
    return decrypted_secret_key
