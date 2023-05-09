import hashlib

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_signature(message):
    # Calculate SHA256 value
    hash_value = hashlib.sha256(message.encode("utf-8")).hexdigest()
    # Get private key
    private_key = RSA.import_key(open("private_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    # Encrypt hash value with private key
    signature = cipher_rsa.encrypt(hash_value.encode("utf-8"))
    return signature


def verify_signature(message, signature):
    # Calculate SHA256 value
    hash_value = hashlib.sha256(message.encode("utf-8")).hexdigest()
    # Get public key
    public_key = RSA.import_key(open("public_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    # Decrypt signature with public key
    decrypted_hash = cipher_rsa.decrypt(signature)
    return decrypted_hash.decode("utf-8") == hash_value
