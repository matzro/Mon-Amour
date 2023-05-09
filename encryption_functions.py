import hash_functions as hf
import print_info as pi
import mac_functions as mf

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16  # 128 bits
HMAC_SIZE = 32  # 256 bits


def encrypt_message(message, secret_key):
    iter_counter, salt, key = hf.generate_hash(secret_key)
    counter = Counter.new(nbits=BLOCK_SIZE*8)
    
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(message.encode())
    
    return iter_counter, salt, ciphertext


def decrypt_message(password, input):
    iter_counter = int(input[0])
    salt = bytes.fromhex(input[2])
    ciphertext = bytes.fromhex(input[3])[HMAC_SIZE:]

    counter = Counter.new(nbits=BLOCK_SIZE*8)
    key = hf.find_hash(iter_counter, salt, password)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    hmac_received = bytes.fromhex(input[3])[:HMAC_SIZE]
    hmac_value = mf.calculate_hmac(ciphertext, password)
    print(f"HMAC R: {hmac_received.hex()}")
    print(f"HMAC C: {hmac_value}")
    hmac_validity = hmac_received.hex() == hmac_value

    decrypted_msg = cipher.decrypt(ciphertext)

    try: 
        print(f"Decrypted message: {decrypted_msg.decode()}")
    except:
        print("Decryption failed. Wrong password.")

    # pi.print_properties(input, hmac_received, ciphertext, decrypted_msg)
    
    return decrypted_msg, hmac_validity