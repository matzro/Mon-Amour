from sys import exit

import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi
import hash_functions as hf


# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits


def main():
    while True:
        pi.print_menu()
        option = input("Option: ")

        if option == "1":
            print("\n")
            question = input("Question: ")
            secret_key = input("Password: ").lower()
            message = input("Message: ")

            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
            hmac_value = mf.calculate_hmac(ciphertext, secret_key)
            print(f"HMAC: {hmac_value}")
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

        elif option == "2":
            ciphertext = fm.read_file(FILE_NAME)
            question = ciphertext[1]

            print("\n")
            print(f"Question: {question}")
            secret_key = input("Password: ").lower()
            
            decrypted_message, hmac_validity = ef.decrypt_message(secret_key, ciphertext)

            print(f"hmac: {hmac_validity}")

        elif option == "0":
            exit(0)


if __name__ == "__main__":
    main()