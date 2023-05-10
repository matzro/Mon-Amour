import hashlib
import file_management as fm

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def generate_signature(message, username):
    # Get private key
    private_key = fm.import_private_key(username)
    # Hash message
    hash_value = SHA256.new(message.encode("utf-8"))
    # Generate digital signature
    signature = PKCS1_v1_5.new(private_key).sign(hash_value)
    return signature


def verify_signature(message, signature, username):
    # Get public key
    public_key = fm.import_public_key(username)
    # Hash message
    hash_value = SHA256.new(message.encode("utf-8"))
    # Verify digital signature
    verification = PKCS1_v1_5.new(public_key).verify(hash_value, signature)
    return verification
