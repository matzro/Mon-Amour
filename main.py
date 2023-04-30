import hashlib
import hmac

# https://www.pycryptodome.org/
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

import encryption_functions as ef
import file_management as fm
import hash_functions as hf
import mac_functions as mf
import print_info as pi


# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
HMAC_SIZE = 32  # 256 bits


def main():
    print("Welcome to Mon-Amour messaging app")
    question = "A resposta e password"
    message = "Adoro as tuas batatas fritas"
    password = "password"

    hmac_value = mf.hmac_sender(message, password.encode("utf-8"))

    iter_counter, salt, ciphertext_iv = ef.encrypt_message(message)
    fm.write_file(iter_counter, question, salt, ciphertext_iv, hmac_value)

    decrypted_message, hmac_received = ef.decrypt_message("password", "ciphertext.txt")

    if mf.hmac_receiver(decrypted_message, password.encode("utf-8"), hmac_received):
        print("HMAC is valid")
    else:
        print("HMAC is invalid")


if __name__ == "__main__":
    main()