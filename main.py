import sys

import account_management as am
import database_management as dbm
import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi
import rsa_functions as rf

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits


def main():
    # Login ---------------------------------------------------------
    dbm.load_database()
    
    while True:
        pi.print_login()
        username = input("Username: ")
        password = input("Password: ").lower()

        if dbm.check_if_user_exists(username):
            # If user exists, check if password is correct
            hashed_password = dbm.get_user_password(username)

            if dbm.password_checking(password, hashed_password):
                print("Login successful.")
                break
            else:
                print("Wrong password. Please try again.")
        else:
            print("User does not exist. Creating new account...")
            dbm.add_user(username, password)
            print("Account created successfully.")

    if (am.check_if_keys_exist(username) == False):
        print(f"Generating keys for {username}...")
        rf.generate_key_pair(username, password)
    else:
        print(f"Keys for {username} already exist.")
    # ----------------------------------------------------------------


    while True:
        pi.print_menu()
        option: str = input("Option: ")

        # ---- ENCRYPT ----
        if option == "1":
            print("\n")
            addressee: str = input("Addressee: ")
            if (am.check_if_keys_exist(addressee) == False):
                print(f"User {addressee} does not exist. Please try again.")
                continue
            
            question: str = input("Question: ")
            secret_key: str = input("Password: ").lower()
            message: str = input("Message: ")

            iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
            hmac_value = mf.calculate_hmac(ciphertext, secret_key)
            signature = ds.generate_signature(message, username, password)
            fm.write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, addressee)

        # ---- DECRYPT ----
        elif option == "2":
            try:
                ciphertext, sender_id = fm.read_file(username)
            except: 
                print("No message for you.")
                continue

            question = ciphertext[1]
            sender_username = dbm.get_username_by_id(sender_id)
            signature = ciphertext[4]

            print("\n")
            print(f"Question: {question}")

            secret_key = input("Password: ").lower()
            
            decrypted_message, hmac_validity = ef.decrypt_message(secret_key, ciphertext)
            
            verification = ds.verify_signature(decrypted_message.decode(), bytes.fromhex(signature), sender_username)

            if verification:
                print("Signature verified")
            else:
                print("Signature not verified")


            print(f"hmac: {hmac_validity}")

        elif option == "0":
            sys.exit(0)



if __name__ == "__main__":
    main()
