import hashlib
import time

from Crypto.Random import get_random_bytes


BLOCK_SIZE = 16 # in bytes
ID_LENGTH = 8
TIME = 2 # in seconds


def generate_salt() -> bytes:
    """Generates a random salt value of 16 bytes.

    Returns:
        bytes: 16 byte generated salt value.
    """
    return get_random_bytes(BLOCK_SIZE)


def generate_hash(password: str) -> tuple[int, bytes, bytes]:
    """Generates a hash value of the secret key by iterating through the SHA256 hashing algorithm for a specific time.

    Args:
        password (str): Secret key to be hashed.

    Returns:
        tuple[int, bytes, bytes]: Tuple containing the number of hashing iterations, salt, and hash value of the secret key.
    """
    password_bytes: bytes = password.encode('utf-8')
    salt: bytes = generate_salt()
    key: bytes = b''.join([password_bytes, salt])
    hash_value: bytes = b''

    start_time: float = time.time()
    iter_counter: int = 0

    while time.time() - start_time <= TIME:
        if iter_counter == 0:
            hash_value = hashlib.sha256(key).digest()
            iter_counter += 1
        hash_value = hashlib.sha256(hash_value).digest()
        iter_counter += 1

    return iter_counter, salt, hash_value


def find_hash(iter_counter: int, salt: bytes, secret_key: str) -> bytes:
    """Finds the hash value of the secret key by iterating through the SHA256 hashing algorithm `iter_counter` times.
    
    Args:
        iter_counter (int): Value to iterate through the SHA256 hashing algorithm
        salt (bytes): Salt value to be used in the SHA256 hashing algorithm
        secret_key (str): Secret key to be hashed

    Returns:
        bytes: Hash value of the secret key.
    """
    key: bytes = b''.join([secret_key.encode('utf-8'), salt])
    hash_value: bytes = b''

    i: int = 0
    while i < iter_counter:
        if i == 0:
            hash_value = hashlib.sha256(key).digest()
            i += 1
        hash_value = hashlib.sha256(hash_value).digest()
        i += 1

    return hash_value


def short_hash(username: str) -> str:
    """Generates an 8-byte hash of a given username.

    This function is used throughout the program to generate pseudo-random unique identifiers for each user in the database.

    Args:
        username (str): Username to be hashed.

    Returns:
        str: 8-byte hash value of the username.
    """
    hash: str = hashlib.sha256(username.encode('utf-8')).digest()[:ID_LENGTH].hex().upper()
    
    return hash
