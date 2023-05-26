from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

import hash_functions as hf
import print_info as pi
import mac_functions as mf


BLOCK_SIZE = 16  # in bytes
HMAC_SIZE = 32  # in bytes


def encrypt_message(message: str, secret_key: str) -> tuple[int, bytes, bytes]:
    """Encrypts the message using the AES algorithm in CTR mode.

    Args:
        message (str): Message to be encrypted.
        secret_key (str): Secret key to encrypt the message.

    Returns:
        tuple[int, bytes, bytes]: A tuple containing the number of hashing iterations, the salt and the encrypted ciphertext.
    """
    iter_counter, salt, key = hf.generate_hash(secret_key)
    counter = Counter.new(nbits=BLOCK_SIZE*8)
    
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ciphertext: bytes = cipher.encrypt(message.encode())
    
    return iter_counter, salt, ciphertext


def decrypt_message(password: str, input: list[str]) -> tuple[bytes, bool]:
    """_summary_

    Args:
        password (str): _description_
        input (list[str]): _description_

    Returns:
        tuple[bytes, bool]: _description_
    """
    iter_counter: int = int(input[0])
    salt: bytes = bytes.fromhex(input[2])
    ciphertext: bytes = bytes.fromhex(input[3])[HMAC_SIZE:]

    counter = Counter.new(nbits=BLOCK_SIZE*8)
    key: bytes = hf.find_hash(iter_counter, salt, password)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    hmac_received: str = input[3][:HMAC_SIZE]
    hmac_value: str = mf.calculate_hmac(ciphertext, password)[:HMAC_SIZE]
    print(f"HMAC R: {hmac_received}")
    print(f"HMAC C: {hmac_value}")

    hmac_validity: bool = (hmac_received == hmac_value)
    decrypted_msg: bytes = cipher.decrypt(ciphertext)

    try:
        print(f"Decrypted message: {decrypted_msg.decode()}")
    except:
        print("Decryption failed. Wrong password.")
    
    return decrypted_msg, hmac_validity

