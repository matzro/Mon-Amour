import file_management as fm
import hash_functions as hf
import print_info as pi

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16  # 128 bits
HMAC_SIZE = 32  # 256 bits


# https://onboardbase.com/blog/aes-encryption-decryption/
def encrypt_message(message, secret_key):
    iter_counter, salt, key = hf.generate_hash(secret_key)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Cria um objeto AES com a chave
    ciphertext = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))  # Cifra a mensagem
    ciphertext_iv = iv + ciphertext
    return iter_counter, salt, ciphertext_iv


def decrypt_message(password, input):
    iter_counter = int(input[0])
    salt = bytes.fromhex(input[2])
    hmac_received = bytes.fromhex(input[3])[:HMAC_SIZE]
    iv = bytes.fromhex(input[3])[HMAC_SIZE: HMAC_SIZE + BLOCK_SIZE]
    ciphertext = bytes.fromhex(input[3])[HMAC_SIZE + BLOCK_SIZE:]

    key = hf.find_hash(iter_counter, salt, password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Exception handling
    try:
        decrypted_msg = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except ValueError:
        return None, None

    pi.print_properties(input, hmac_received, iv, ciphertext, decrypted_msg)
    
    return decrypted_msg, hmac_received