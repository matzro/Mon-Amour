import hashlib
import os

import customtkinter

import account_management as am
import database_management as dm
import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import rsa_functions as rf
from gui import *

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits
BOB = "bob"  # This is the username of the receiver
ALICE = "alice"  # This is the username of the sender

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('blue')


"""def cipher():
    This function is called when the user clicks on the "Send" button. It reads the values from the GUI - question,
    secret key and message to send.
    First, the secret key created by the user is encrypted with the public key of the receiver, using RSA. The encrypted
    secret key is written to a file.
    Then, the message is encrypted using AES. The iter_counter, question, salt, ciphertext and hmac are written to a
    file.
    It is needed to generate a digital signature of the message, so the message is signed with the private key of the
    sender. The signature is written to a file.
    :return: None
    question = question_sent.get()
    secret_key = secret_key_c.get().lower()
    message = message_sent.get()

    iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
    hmac_value = mf.calculate_hmac(ciphertext, secret_key)
    signature = ds.generate_signature(message, BOB, hashlib.sha256("key1".encode()).digest())  # !!!!!!!!!! CHANGE THIS
    #fm.write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, addressee)
"""

"""def decipher():
This function is called when the user clicks on the "Receive" button. It reads the value from the GUI - secret
    key.
    First, the secret key received is decrypted with the private key of the receiver, using RSA.
    Then, the ciphertext is read from the file and the message is decrypted using AES.
    The HMAC is calculated and compared with the HMAC received. If they are equal, it is printed "HMAC verified".
    It is needed to verify the digital signature of the message, so the signature is read from the file and verified. If
    the signature is valid, it is printed "Signature verified". If not, it is printed "Signature not verified".
    :return: None
    secret_key = secret_key_d.get().lower()
    ciphertext = fm.read_file(FILE_NAME)

    decrypted_message, hmac_validity = ef.decrypt_message(secret_key, ciphertext)
    print(f"HMAC: {hmac_validity}")
    print(f"Decrypted message: {decrypted_message}")

    if decrypted_message is not None:
        signature = fm.read_signature()
        verification = ds.verify_signature(decrypted_message.decode(), signature, BOB)
        if verification:
            print("Signature verified")
        else:
            print("Signature not verified")"""


"""def update_receive():
    ciphertext_file = fm.read_file(FILE_NAME)
    question = ciphertext_file[1]
    question_received.configure(text=question)


def exit_program():
    This function is called when the user clicks on the "Exit" button. It closes the GUI and deletes the file that
    contains the ciphertext.
    :return: None
    if os.path.isfile(FILE_NAME):
        os.remove(FILE_NAME)
    window.destroy()"""




if __name__ == '__main__':
    """This is the main function. It creates the GUI and calls the functions cipher() and decipher() when the user clicks
    """

    app = LoginWindow()
    app.mainloop()

