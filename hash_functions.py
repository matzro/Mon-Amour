import hashlib
import time
from Crypto.Random import get_random_bytes

ID_LENGTH = 8
TIME_IN_SECONDS = 2
BLOCK_SIZE = 16

def generate_salt() -> bytes:
    """Generates a random salt value of 16 bytes.

    Returns:
        bytes: 16 byte generated salt value.
    """
    return get_random_bytes(BLOCK_SIZE)


# https://stackoverflow.com/questions/3566176/salting-passwords-101
def generate_hash(password):
    """Generates a hash value from a password using the SHA256 algorithm and 

    Args:
        password (_type_): _description_

    Returns:
        _type_: _description_
    """
    password_bytes = password.encode('utf-8')
    salt = generate_salt()
    key = b''.join([password_bytes, salt])
    hash_value = b''

    start_time = time.time()
    iter_counter = 0

    # Calculate SHA256 value
    while time.time() - start_time <= TIME_IN_SECONDS:
        if iter_counter == 0:
            hash_value = hashlib.sha256(key).digest()
            iter_counter += 1
        hash_value = hashlib.sha256(hash_value).digest()
        iter_counter += 1
    return iter_counter, salt, hash_value


def find_hash(iter_counter, salt, password):
    i = 0
    key = b''.join([password.encode('utf-8'), salt])
    hash_value = b''

    while i < iter_counter:
        if i == 0:
            hash_value = hashlib.sha256(key).digest()
            i += 1
        hash_value = hashlib.sha256(hash_value).digest()
        i += 1
    return hash_value


def short_hash(string: str) -> str:
    """Generates an 8-byte hash of a given string.

    Args:
        string (str): String to be hashed.

    Returns:
        str: 8-byte hash value of the string.
    """
    hash: str = hashlib.sha256(string.encode('utf-8')).digest()[:ID_LENGTH].hex().upper()
    
    return hash