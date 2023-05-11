from sys import exit

import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi
import hash_functions as hf

import rsa_functions as rf

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits
USER1 = "user1"
USER2 = "user2"


def main():
    rf.generate_key_pair(USER1)
    rf.generate_key_pair(USER2)

    while True:
        pi.print_menu()
        option = input("Option: ")

        # ---- ENCRYPT ----
        if option == "1":
            print("\n")
            question = input("Question: ")
            secret_key = input("Password: ").lower()

            # ------------ RSA (encrypt) --------------
            # ---- USER1 encrypts the secret key with USER2 public key
            encrypted_secret_key = rf.encrypt_secret_key(secret_key.encode(), USER2)
            fm.write_rsa_cipher(encrypted_secret_key, USER1)

            message = input("Message: ")

            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
            hmac_value = mf.calculate_hmac(ciphertext, secret_key)
            print(f"HMAC: {hmac_value}")
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

            # ------------ DIGITAL SIGNATURE --------------
            # ---- USER1 signs the message with USER1 private key
            signature = ds.generate_signature(message, USER1)
            fm.write_signature(signature)

            # -------------- AES (encrypt) --------------
            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)

            # ------------ HMAC -------------
            # ---- It is more secure to encrypt the message first and then calculate the hmac,
            # ---- lastly concatenate the hmac with the ciphertext
            hmac_value = mf.calculate_hmac(ciphertext[BLOCK_SIZE:], secret_key)

            # ---- Write the ciphertext, salt, iv and hmac to a file
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

        # ---- DECRYPT ----
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

            secret_key = input("Password: ")

            # ------------ RSA (decrypt) --------------
            # --- Reads the ciphertext of the secret key that USER1 sent to USER2
            cipher_secretkey = fm.read_rsa_cipher(USER1)
            # --- USER2 decrypts the secret key with USER2 private key
            decrypted_secret_key = rf.decrypt_secret_key(cipher_secretkey, USER2)
            # --- Writes the decrypted secret key to a file (only for testing purposes!!!!!!!)
            fm.write_rsa_decipher(decrypted_secret_key, USER2)

            # ------------ DIGITAL SIGNATURE --------------
            # ---- Reads the signature from the file
            signature = fm.read_signature()
            # ---- USER2 verifies the signature with USER2 public key
            verification = ds.verify_signature(question, signature, USER2)
            if verification:
                print("Signature verified")
            else:
                print("Signature not verified")

            # ------------ AES (decrypt) -------------
            error, decrypted_message = ef.decrypt_message(secret_key, ciphertext)

            # ---- Handle errors
            if error is None:
                print(f"Message: {decrypted_message}")
            else:
                print(f"Error: {error}")



if __name__ == "__main__":
    main()
