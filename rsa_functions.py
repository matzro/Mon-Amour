from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES  # para que serve isto?
from Crypto.Util import Counter

import file_management as fm

BLOCK_SIZE = 16  # 128 bits

def generate_key_pair(username, secret_key):
    # Generate a new RSA key pair
    key = RSA.generate(2048)

    # Serialize the private key to a PEM file
    private_key = key.export_key()

    encrypted_private = encrypt_private_key_AES(private_key, secret_key)
    with open(f'private_key_{username}.pem', 'wb') as f:
        f.write(encrypted_private)

    # Serialize the public key to a PEM file
    public_key = key.publickey().export_key()
    with open(f'public_key_{username}.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


def encrypt_secret_key(secret_for_private, username):
    # load public key
    public_key = fm.import_public_key(username)
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_secret_key = cipher_rsa.encrypt(secret_for_private)
    return encrypted_secret_key


def decrypt_secret_key(encrypted_secret_key, username, secret_for_private):
    # load ciphered private key
    with open(f'private_key_{username}.pem', 'rb') as f:
        private_key = f.read()
    counter = Counter.new(nbits=BLOCK_SIZE * 8)
    cipher = AES.new(secret_for_private, AES.MODE_CTR, counter=counter)
    decrypted_private = cipher.decrypt(private_key)

    # Convert decrypted private key to RSA object
    decrypted_private = RSA.import_key(decrypted_private)

    cipher_rsa = PKCS1_v1_5.new(decrypted_private)
    decrypted_secret_key = cipher_rsa.decrypt(encrypted_secret_key, None)
    return decrypted_secret_key


#chave privada, uma senha para criptografar a chave e um caminho para o arquivo que deve conter a chave privada criptografada
def encrypt_private_key_AES(private_key_str, secret_key):
    counter = Counter.new(nbits=BLOCK_SIZE * 8)

    cipher = AES.new(secret_key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(private_key_str)

    return ciphertext


#A função agora recebe um caminho para o arquivo contendo a chave privada criptografada, uma senha para descriptografar
#a chave e um caminho para o arquivo que deve conter a chave privada descriptografada.
def decrypt_private_key_AES(encrypted_private_key_file, password_aes, private_key_file):
    with open(encrypted_private_key_file, 'rb') as f:
        encrypted_private_key = f.read()

    iv = encrypted_private_key[:BLOCK_SIZE]
    cipher = AES.new(password_aes, AES.MODE_CBC, iv)
    private_key = cipher.decrypt(encrypted_private_key[BLOCK_SIZE:])

    with open(private_key_file, 'wb') as f:
        f.write(private_key)

    #print("sucesso")
    return private_key
