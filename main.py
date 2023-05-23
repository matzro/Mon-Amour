from sys import exit

import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi
import hash_functions as hf
import account_management as am

import rsa_functions as rf

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits
BOB = "bob"
ALICE = "alice"


def main():
    if (am.check_if_keys_exist(BOB) and am.check_if_keys_exist(ALICE)) == False:
        print(f"Generating keys for {BOB} and {ALICE}...")
        rf.generate_key_pair(BOB)
        rf.generate_key_pair(ALICE)
    else:
        print(f"Keys for {BOB} and {ALICE} already exist.")

    while True:
        pi.print_menu()
        option = input("Option: ")

        # ---- ENCRYPT ----
        if option == "1":
            print("\n")
            question = input("Question: ")
            secret_key = input("Password: ").lower()

            # ------------ RSA (encrypt) --------------
            # ---- Bob encrypts the secret key with ALICE public key
            encrypted_secret_key = rf.encrypt_secret_key(secret_key.encode(), ALICE)
            fm.write_rsa_cipher(encrypted_secret_key, BOB)

            message = input("Message: ")

            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
            hmac_value = mf.calculate_hmac(ciphertext, secret_key)
            print(f"HMAC: {hmac_value}")
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

            # ------------ DIGITAL SIGNATURE --------------
            # ---- Bob signs the message with his private key
            signature = ds.generate_signature(message, BOB)
            fm.write_signature(signature)

            # -------------- AES (encrypt) --------------
            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)

            # ------------ HMAC -------------
            # ---- It is more secure to encrypt the message first and then calculate the hmac,
            # ---- lastly concatenate the hmac with the ciphertext
            hmac_value = mf.calculate_hmac(ciphertext, secret_key)

            # ---- Write the ciphertext, salt, iv and hmac to a file
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

        # ---- DECRYPT ----
        elif option == "2":
            try:
                ciphertext = fm.read_file(FILE_NAME)
            except: 
                print("No ciphertext found. Please encrypt a message first.")
                continue

            question = ciphertext[1]

            print("\n")
            print(f"Question: {question}")

            secret_key = input("Password: ").lower()

            # ------------ RSA (decrypt) --------------
            # --- Reads the ciphered secret key from the file
            cipher_secretkey = fm.read_rsa_cipher(BOB)
            # --- Alice decrypts the secret key with her private key
            decrypted_secret_key = rf.decrypt_secret_key(cipher_secretkey, ALICE)
            print(decrypted_secret_key)
            # --- Writes the decrypted secret key to a file (only for testing purposes!!!!!!!)
            fm.write_rsa_decipher(decrypted_secret_key.decode(), ALICE)
            
            decrypted_message, hmac_validity = ef.decrypt_message(secret_key, ciphertext)

            # ------------ DIGITAL SIGNATURE --------------
            # ---- Reads the signature from the file
            signature = fm.read_signature()
            # ---- Alice verifies the signature with Bob public key
            verification = ds.verify_signature(decrypted_message.decode(), signature, BOB)

            if verification:
                print("Signature verified")
            else:
                print("Signature not verified")


            print(f"hmac: {hmac_validity}")

        elif option == "0":
            exit(0)



if __name__ == "__main__":
    main()
