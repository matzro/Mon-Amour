from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP #para que serve isto?

def generate_key_pair():
    # Generate a new RSA key pair
    key = RSA.generate(2048)

    # Serialize the private key to a PEM file
    private_key = key.export_key()
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    # Serialize the public key to a PEM file
    public_key = key.publickey().export_key()
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


def import_private_key():
    # Deserialize the PEM file to a private key object
    with open('private_key.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())

    return private_key


def import_public_key():
    # Deserialize the PEM file to a public key object
    with open('public_key.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())

    return public_key


def encrypt_secret_key(secret_key, public_key):
    #load public key
    public_key = RSA.import_key(open("public_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_secret_key = cipher_rsa.encrypt(secret_key)
    return encrypted_secret_key

def decrypt_secret_key(encrypted_secret_key, private_key):
    #load private key
    private_key = RSA.import_key(open("private_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_secret_key = cipher_rsa.decrypt(encrypted_secret_key)
    return decrypted_secret_key


generate_key_pair()
private_key = import_private_key()
public_key = import_public_key()
secret_key = 'abcdefg'.encode() ## teste
encrypted_secret_key = encrypt_secret_key(secret_key, public_key)
print(encrypted_secret_key)
decrypted_secret_key = decrypt_secret_key(encrypted_secret_key, private_key)
print(decrypted_secret_key)