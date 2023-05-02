import hashlib
import time
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def generate_salt():
    return get_random_bytes(BLOCK_SIZE)


# https://stackoverflow.com/questions/3566176/salting-passwords-101
def generate_hash(password):
    password_bytes = password.encode('utf-8')
    salt = generate_salt()
    key = b''.join([password_bytes, salt])
    hash_value = b''

    start_time = time.time()
    iter_counter = 0

    # Calculate SHA256 value
    while time.time() - start_time <= 1:
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