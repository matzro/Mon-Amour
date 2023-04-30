import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi


# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits



def main():
    while True:
        pi.print_menu()
        option = input("Option: ")
        
        if option == "1":
            question = input("Question: ")
            secret_key = input("Password: ").lower()
            message = input("Message: ")

            hmac_value = mf.hmac_sender(message, secret_key.encode("utf-8"))
            iter_counter, salt, ciphertext_iv = ef.encrypt_message(message, secret_key)
            fm.write_file(iter_counter, question, salt, ciphertext_iv, hmac_value)

        elif option == "2":
            ciphertext = fm.read_file(FILE_NAME)
            question = ciphertext[1]

            print(f"Question: {question}")
            secret_key = input("Password: ")
            
            decrypted_message, hmac_received = ef.decrypt_message(secret_key, ciphertext)

            if mf.hmac_receiver(decrypted_message, secret_key.encode("utf-8"), hmac_received):
                print("HMAC is valid")
            else:
                print("HMAC is invalid")


if __name__ == "__main__":
    main()