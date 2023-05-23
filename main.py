import hashlib
import os

import customtkinter

import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import rsa_functions as rf

# GLOBAL VARIABLES
BLOCK_SIZE = 16  # 128 bits
FILE_NAME = "ciphertext.txt"
HMAC_SIZE = 32  # 256 bits
BOB = "bob"  # This is the username of the receiver
ALICE = "alice"  # This is the username of the sender

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('blue')


def cipher():
    """This function is called when the user clicks on the "Send" button. It reads the values from the GUI - question,
    secret key and message to send.
    First, the secret key created by the user is encrypted with the public key of the receiver, using RSA. The encrypted
    secret key is written to a file.
    Then, the message is encrypted using AES. The iter_counter, question, salt, ciphertext and hmac are written to a
    file.
    It is needed to generate a digital signature of the message, so the message is signed with the private key of the
    sender. The signature is written to a file.
    :return: None
    """
    question = question1.get()
    secret_key = secret_key1.get().lower()
    message = message1.get()

    encrypted_secret_key = rf.encrypt_secret_key(secret_key.encode(), ALICE)
    fm.write_rsa_cipher(encrypted_secret_key, BOB)

    iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
    hmac_value = mf.calculate_hmac(ciphertext, secret_key)
    fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

    signature = ds.generate_signature(message, BOB, hashlib.sha256("key1".encode()).digest())  # !!!!!!!!!! CHANGE THIS
    # secret_key of login
    fm.write_signature(signature)


def decipher():
    """This function is called when the user clicks on the "Receive" button. It reads the value from the GUI - secret
    key.
    First, the secret key received is decrypted with the private key of the receiver, using RSA.
    Then, the ciphertext is read from the file and the message is decrypted using AES.
    The HMAC is calculated and compared with the HMAC received. If they are equal, it is printed "HMAC verified".
    It is needed to verify the digital signature of the message, so the signature is read from the file and verified. If
    the signature is valid, it is printed "Signature verified". If not, it is printed "Signature not verified".
    :return: None
    """
    secret_key3 = secret_key2.get().lower()
    ciphertext1 = fm.read_file(FILE_NAME)

    cipher_secretkey = fm.read_rsa_cipher(BOB)
    decrypted_secret_key = rf.decrypt_secret_key(cipher_secretkey, ALICE,
                                                 hashlib.sha256("key2".encode()).digest())  # !!!!!!!!!! CHANGE THIS
    print(decrypted_secret_key)

    # fm.write_rsa_decipher(decrypted_secret_key.decode(), ALICE)

    decrypted_message, hmac_validity = ef.decrypt_message(secret_key3, ciphertext1)
    print(f"HMAC: {hmac_validity}")
    print(f"Decrypted message: {decrypted_message}")

    signature = fm.read_signature()
    verification = ds.verify_signature(decrypted_message.decode(), signature, BOB)
    if verification:
        print("Signature verified")
    else:
        print("Signature not verified")


if __name__ == '__main__':
    """This is the main function. It creates the GUI and calls the functions cipher() and decipher() when the user clicks
    """

    rf.generate_key_pair(BOB, hashlib.sha256("key1".encode()).digest())  # !!!!!!!!!! CHANGE THIS
    rf.generate_key_pair(ALICE, hashlib.sha256("key2".encode()).digest())  # !!!!!!!!!! CHANGE THIS

    # Main window
    window = customtkinter.CTk()
    window.geometry('650x550')
    window.title('Mon-Amour')

    text = customtkinter.CTkLabel(window, text='Welcome to Mon-Amour messaging app', font=('Calibri', 20))
    text.pack(padx=10, pady=20)

    tabview = customtkinter.CTkTabview(window, width=400, height=350)
    tabview.pack()
    tabview.add('Send message')
    tabview.add('Receive message')
    tabview.add('Help')

    # Tab 1 - Send message
    text = customtkinter.CTkLabel(tabview.tab('Send message'), text='Send message', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

    question1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Question', font=('Calibri', 15))
    question1.pack(padx=10, pady=10)

    secret_key1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Secret Key',
                                         font=('Calibri', 15), show='*')
    secret_key1.pack(padx=10, pady=10)

    message1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Message', font=('Calibri', 15))
    message1.pack(padx=10, pady=10)

    botao_send = customtkinter.CTkButton(tabview.tab('Send message'), text='Send', font=('Calibri', 15), command=cipher)
    botao_send.pack(padx=10, pady=10)

    # Tab 2 - Receive message
    if os.path.getsize(FILE_NAME) != 0:
        text = customtkinter.CTkLabel(tabview.tab('Receive message'), text='Receive message', font=('Calibri', 15))
        text.pack(padx=10, pady=10)

        ciphertext2 = fm.read_file(FILE_NAME)
        question2 = ciphertext2[1]

        pergunta = customtkinter.CTkLabel(tabview.tab('Receive message'), text=question2)
        pergunta.pack(padx=10, pady=10)

        secret_key2 = customtkinter.CTkEntry(tabview.tab('Receive message'), placeholder_text='Secret Key',
                                             font=('Calibri', 15), show='*')
        secret_key2.pack(padx=10, pady=10)

        botao_receive = customtkinter.CTkButton(tabview.tab('Receive message'), text='Receive', font=('Calibri', 15),
                                                command=decipher)
        botao_receive.pack(padx=10, pady=10)

    else:
        text = customtkinter.CTkLabel(tabview.tab('Receive message'), text='No message received', font=('Calibri', 15))
        text.pack(padx=10, pady=10)

    # Tab 3 - Help
    text = customtkinter.CTkLabel(tabview.tab('Help'), text='Help', font=('Calibri', 15))
    text.pack(padx=10, pady=10)




    # Close window
    botao4 = customtkinter.CTkButton(window, text='Exit', font=('Calibri', 15), command=window.destroy)
    botao4.pack(padx=10, pady=10)

    window.mainloop()  # Keep the window open
