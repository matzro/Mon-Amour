import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import print_info as pi
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

        if option == "1":
            question = input("Question: ")
            secret_key = input("Password: ").lower()


            # User 1 encrypts the secret key with user's 2 public key
            encrypted_secret_key = rf.encrypt_secret_key(secret_key.encode(), USER2)
            fm.write_rsa_cipher(encrypted_secret_key, USER1)

            message = input("Message: ")

            # TODO: hmac needs to be changed, as it receives the ciphertext and not the plaintext message
            # Attention to the fact that it is more secure to encrypt the message first and then calculate the hmac,
            # lastly concatenate the hmac with the ciphertext

            iter_counter, salt, ciphertext_iv = ef.encrypt_message(message, secret_key)
            hmac_value = mf.hmac_sender(ciphertext_iv[BLOCK_SIZE:], secret_key.encode("utf-8"))
            fm.write_file(iter_counter, question, salt, ciphertext_iv, hmac_value)

        elif option == "2":
            ciphertext = fm.read_file(FILE_NAME)
            question = ciphertext[1]

            print(f"Question: {question}")
            secret_key = input("Password: ")

            # Reads the ciphertext of the secret key that user 1 sent to user 2
            cipher_secretkey = fm.read_rsa_cipher(USER1)

            # Decrypts the secret key with user 2 private key
            decrypted_secret_key = rf.decrypt_secret_key(cipher_secretkey, USER2)
            fm.write_rsa_decipher(decrypted_secret_key, USER2)

            error, decrypted_message = ef.decrypt_message(secret_key, ciphertext)

            if error is None:
                print(f"Message: {decrypted_message}")
            else:
                print(f"Error: {error}")


if __name__ == "__main__":
    main()
