import hashlib

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
BOB = "bob"
ALICE = "alice"

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('blue')

def cifrar():
    question = question1.get()
    secret_key = secret_key1.get().lower()
    message = message1.get()
    print("Question: ", question)
    print("Secret Key: ", secret_key)
    print("Message: ", message)

    # ------------ RSA (encrypt) --------------
    # ---- The user that sends messages encrypts the secret key with the public key of the receiver
    # ---- And writes the encrypted secret key to a file
    encrypted_secret_key = rf.encrypt_secret_key(secret_key.encode(), ALICE)
    fm.write_rsa_cipher(encrypted_secret_key, BOB)

    iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)
    hmac_value = mf.calculate_hmac(ciphertext, secret_key)
    print(f"HMAC: {hmac_value}")
    fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)

    # ------------ DIGITAL SIGNATURE --------------
    # ---- Bob signs the message with his private key
    signature = ds.generate_signature(message, BOB, hashlib.sha256("key1".encode()).digest())
    fm.write_signature(signature)

    # -------------- AES (encrypt) --------------
    iter_counter, salt, ciphertext = ef.encrypt_message(message, secret_key)

    # ------------ HMAC -------------
    # ---- It is more secure to encrypt the message first and then calculate the hmac,
    # ---- lastly concatenate the hmac with the ciphertext
    hmac_value = mf.calculate_hmac(ciphertext, secret_key)

    # ---- Write the ciphertext, salt, iv and hmac to a file
    fm.write_file(iter_counter, question, salt, ciphertext, hmac_value)


def decifrar():
    secret_key3 = secret_key2.get().lower()
    ciphertext1 = fm.read_file(FILE_NAME)

    # ------------ RSA (decrypt) --------------
    # --- Reads the ciphered secret key from the file
    cipher_secretkey = fm.read_rsa_cipher(BOB)
    # --- Alice decrypts the secret key with her private key
    decrypted_secret_key = rf.decrypt_secret_key(cipher_secretkey, ALICE, hashlib.sha256("key2".encode()).digest())
    print(decrypted_secret_key)
    # --- Writes the decrypted secret key to a file (only for testing purposes!!!!!!!)
    fm.write_rsa_decipher(decrypted_secret_key.decode(), ALICE)

    decrypted_message, hmac_validity = ef.decrypt_message(secret_key3, ciphertext1)

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


if __name__ == '__main__':
    # Janela principal
    janela = customtkinter.CTk()
    janela.geometry('650x550')
    janela.title('Mon-Amour')


    texto = customtkinter.CTkLabel(janela, text='Welcome to Mon-Amour messaging app', font=('Calibri', 20))
    texto.pack(padx=10, pady=20)

    tabview = customtkinter.CTkTabview(janela, width=400, height=350)
    tabview.pack()
    tabview.add('Send message')
    tabview.add('Receive message')
    tabview.add('Help')

    rf.generate_key_pair(BOB, hashlib.sha256("key1".encode()).digest())
    rf.generate_key_pair(ALICE, hashlib.sha256("key2".encode()).digest())

    # Tab 1
    text = customtkinter.CTkLabel(tabview.tab('Send message'), text='Send message', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

    question1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Question', font=('Calibri', 15))
    question1.pack(padx=10, pady=10)

    secret_key1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Secret Key', font=('Calibri', 15), show='*')
    secret_key1.pack(padx=10, pady=10)

    message1 = customtkinter.CTkEntry(tabview.tab('Send message'), placeholder_text='Message', font=('Calibri', 15))
    message1.pack(padx=10, pady=10)

    botao_send = customtkinter.CTkButton(tabview.tab('Send message'), text='Send', font=('Calibri', 15), command=cifrar)
    botao_send.pack(padx=10, pady=10)

    # Tab 2
    text = customtkinter.CTkLabel(tabview.tab('Receive message'), text='Receive message', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

    ciphertext2 = fm.read_file(FILE_NAME)
    question2 = ciphertext2[1]

    pergunta = customtkinter.CTkLabel(tabview.tab('Receive message'), text=question2)
    pergunta.pack(padx=10, pady=10)

    secret_key2 = customtkinter.CTkEntry(tabview.tab('Receive message'), placeholder_text='Secret Key', font=('Calibri', 15), show='*')
    secret_key2.pack(padx=10, pady=10)

    botao_receive = customtkinter.CTkButton(tabview.tab('Receive message'), text='Receive', font=('Calibri', 15), command=decifrar)
    botao_receive.pack(padx=10, pady=10)

    # Tab 3
    text = customtkinter.CTkLabel(tabview.tab('Help'), text='Help', font=('Calibri', 15))
    text.pack(padx=10, pady=10)


    # Fecha janela
    botao4 = customtkinter.CTkButton(janela, text='Exit', font=('Calibri', 15), command=janela.destroy)
    botao4.pack(padx=10, pady=10)


    janela.mainloop()  # Mantém a janela aberta
