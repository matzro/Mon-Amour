from customtkinter import *

import account_management as am
import database_management as dbm
import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import rsa_functions as rf


set_appearance_mode('dark')
set_default_color_theme('blue')


class LoginWindow(CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.geometry("380x390")

        self.title("Mon-Amour")
        self.resizable(False, False)
        # Login title
        title = CTkLabel(self, text="Welcome to Mon-Amour!", font=("Poppins", 16, "bold"))
        title.pack(pady=20)

        main_frame = CTkFrame(self)
        main_frame.pack(pady=20, padx=40, expand=True, fill="both")

        label = CTkLabel(main_frame, text="Login", font=("Poppins", 20, "bold"))
        label.pack(pady=12, padx=10)

        # Username label
        user_entry = CTkEntry(main_frame, placeholder_text="Username", font=("Poppins", 12))
        user_entry.pack(pady=12, padx=10)

        # Password label
        password_entry = CTkEntry(main_frame, placeholder_text="Password", show="*", font=("Poppins", 12))
        password_entry.pack(pady=12, padx=10)

        self.error_label = CTkLabel(main_frame, text="", font=("Poppins", 12, "bold"))
        self.error_label.pack(pady=12, padx=10)

        # Login button
        login_button = CTkButton(main_frame, text="Login", font=("Poppins", 15),
                                 command=lambda: self.login(user_entry.get(), password_entry.get()))
        login_button.pack(pady=12, padx=10)


    def login(self, username, password):
        dbm.load_database()
        if dbm.check_if_user_exists(username):
            hashed_password = dbm.get_user_password(username)

            if dbm.password_checking(password, hashed_password):
                print("Login successful")

                if not am.check_if_keys_exist(username):
                    print(f"Generating keys for {username}...")
                    public_key, encrypted_private_key = rf.generate_key_pair(username, password)
                    am.store_user_keys(username, public_key, encrypted_private_key)
                else:
                    print(f"Keys for {username} already exist")

                self.withdraw()
                window = MainWindow(username, password)
                window.mainloop()
            else:
                print("Wrong password")
                self.error_label.configure(text="Wrong password", text_color="red")

        else:
            print("User does not exist. Creating new account...")
            dbm.add_user(username, password)
            print("Account created successfully")

            if not am.check_if_keys_exist(username):
                print(f"Generating keys for {username}...")
                public_key, encrypted_private_key = rf.generate_key_pair(username, password)
                am.store_user_keys(username, public_key, encrypted_private_key)
            else:
                print(f"Keys for {username} already exist")

            self.withdraw()
            window = MainWindow(username, password)
            window.mainloop()


class CustomTabView(CTkTabview):
    def __init__(self, master, username, password, **kwargs):
        super().__init__(master, **kwargs)

        self.username = username
        self.password = password

        # Create tabs
        self.add("Send")
        self.add("Receive")
        self.add("Help")


        # Add widgets to Send tab
        # Recipient
        self.entry_recipient = CTkEntry(self.tab("Send"), placeholder_text="Recipient")
        self.entry_recipient.pack(pady=10, anchor="w", padx=30)

        # Question
        self.entry_question_sent = CTkEntry(self.tab("Send"), placeholder_text="Question")
        self.entry_question_sent.configure(width=300)
        self.entry_question_sent.pack(pady=10, anchor="w", padx=30)

        # Answer
        self.entry_answer_sent = CTkEntry(self.tab("Send"), show="*", placeholder_text="Answer")
        self.entry_answer_sent.pack(pady=10, anchor="w", padx=30)

        # Message
        self.label_message_sent = CTkLabel(self.tab("Send"), text="Message", font=("Poppins", 12))
        self.label_message_sent.pack(pady=10, padx=30, anchor="w")
        self.entry_message_sent = CTkTextbox(self.tab("Send"), width=300, height=30)
        self.entry_message_sent.pack(fill="both", expand=True, padx=30, pady=10)

        # Button
        self.button_send = CTkButton(self.tab("Send"), text="Send", command=lambda: self.cipher(
            username,
            password,
            self.entry_question_sent.get(),
            self.entry_answer_sent.get(),
            self.entry_message_sent.get("0.0", "end"),
            self.entry_recipient.get()
        ))
        self.button_send.pack(pady=10, padx=20)

        # Add widgets to Receive tab
        global ciphertext, sender_id
        try:
            ciphertext, sender_id = fm.read_file(username)
            question_received = ciphertext[1]

            # Question
            self.label_question_received = CTkLabel(self.tab("Receive"), text="Question: " + question_received, font=("Poppins", 12, "bold"))
            self.label_question_received.pack(pady=10, padx=20)
            # Answer
            self.entry_answer_guess = CTkEntry(self.tab("Receive"), placeholder_text="Answer", show="*")
            self.entry_answer_guess.pack(pady=10, padx=20)

            # Button
            self.button_receive = CTkButton(self.tab("Receive"), text="Test my love", command=lambda: self.decipher(
                self.entry_answer_guess.get(),
            ))
            self.button_receive.pack(pady=10, padx=20)

        except:
            self.label_no_messages = CTkLabel(self.tab("Receive"), text="No messages")
            self.label_no_messages.pack(pady=10, padx=20)

        # Message
        self.label_message_received = CTkLabel(self.tab("Receive"), text="")
        self.label_message_received.pack(pady=10, padx=20)

        # HMAC Verification
        self.label_hmac_verification = CTkLabel(self.tab("Receive"), text="", font=("Poppins", 12, "bold"))
        self.label_hmac_verification.pack(pady=10, padx=20)

        # Digital Signature Verification
        self.label_digital_signature_verification = CTkLabel(self.tab("Receive"), text="", font=("Poppins", 12, "bold"))
        self.label_digital_signature_verification.pack(pady=10, padx=20)

        help = """
        1. Introdução
        Este programa designado "Mon-Amour Messaging App" tem como objetivo enviar e receber mensagens de amor.
        Para poder utilizar esta aplicação, terá que se registar.
        Ao enviar uma mensagem, esta será encriptada utilizando o algoritmo AES128, no modo CTR. Para realizar a encriptação, será necessária a resposta à questão definida pelo emissor.
        Ao receber uma mensagem, a mesma será desencriptada utilizando o mesmo algoritmo e modo. A pergunta definida pelo emissor será exibida na tela, e é necessário inserir a mesma resposta que o emissor para visualizar o conteúdo da mensagem.


        2. Guia de Utilização
        	2.1. Após iniciar a aplicação será exibida a página do login, onde serão exibidas duas caixas de texto e dois botões. Deverá introduzir um nome de utilizador, na caixa de texto "Username" e uma password na caixa de texto "Password". De seguida, deverá pressionar o botão "Login" para começar a sua experiência com a "Mon-Amor Messaging App".
        	     O botão "Help" serve para abrir o manual de ajuda, onde encontrará todas as informações necessárias para utilizar de maneira correta a aplicação.

        	2.2 Se fizer o registo corretamente, será mostrada no ecrã uma nova página com duas opções: "Send Message", "Receive Message". 
        		1. Send Message: ao pressionar este botão no menu inicial, será reencaminahdo para um novo separador. Nesse separador encontrará três caixas de texto e dois botões. 
        			1.1 Na primeira caixa de texto, "Question", deverá introduzir uma questão. (p. ex. "Qual é a sua cor favorita?").
        			1.2 Na segunda caixa de texto, "Secret Key", deverá introduzir a resposta à questão que introduziu na caixa anterior. (p. ex. "amarelo")
        			1.3 Na terceira caixa de texto, "Message", deve incluir a mensagem que prentende enviar.
        			1.4 O botão "Send" permitirá enviar a sua mensagem.
        			1.5 Caso não pretenda enviar a mensagem, deverá pressionar o botão "Back" e voltará à página inicial. 

        	2.3 Receive Message: este botão quando pressionado redireciona para um novo separador. Nesse separador deverá encontrar uma questão, uma caixa de texto e um botão.
        		2.1 Na caixa de texto, "Secret Key", deverá introduzir a resposta correta à questão que se encontra no ecrã. 
        		2.2 Depois deverá pressionar o botão, "Receive", e se a resposta à questão estiver correta, conseguirá visualizar o conteúdo da mensagem que lhe foi enviada. Caso contrário, deverá aparecerá um pop-up a dizer que a resposta à questão está incorreta.


        """


    def cipher(self, username, password, question, secret_key, message, recipient):
        """This function is called when the user clicks on the "Send" button. It reads the values from the GUI - question,
        secret key and message to send.
        First, the secret key created by the user is encrypted with the public key of the receiver, using RSA. The encrypted
        secret key is written to a file.
        Then, the message is encrypted using AES. The iter_counter, question, salt, ciphertext and hmac are written to a
        file.
        It is needed to generate a digital signature of the message, so the message is signed with the private key of the
        sender. The signature is written to a file.
        :return: None"""
        sk: str = secret_key.lower()

        if not am.check_if_keys_exist(recipient):
            print("Recipient does not exist")
            return

        iter_counter, salt, ciphertext_sent = ef.encrypt_message(message, sk)
        hmac_value = mf.calculate_hmac(ciphertext_sent, sk)
        signature = ds.generate_signature(message, username, password)
        fm.write_file(iter_counter, question, salt, ciphertext_sent, hmac_value, signature, username, recipient)

    def decipher(self, secret_key):
        """This function is called when the user clicks on the "Receive" button. It reads the value from the GUI - secret
        key.
        First, the secret key received is decrypted with the private key of the receiver, using RSA.
        Then, the ciphertext is read from the file and the message is decrypted using AES.
        The HMAC is calculated and compared with the HMAC received. If they are equal, it is printed "HMAC verified".
        It is needed to verify the digital signature of the message, so the signature is read from the file and verified. If
        the signature is valid, it is printed "Signature verified". If not, it is printed "Signature not verified".
        :return: None"""

        sender_username = dbm.get_username_by_id(sender_id)
        signature = ciphertext[4]

        sk = secret_key.lower()

        decrypted_message, hmac_validity = ef.decrypt_message(sk, ciphertext)

        verification = ds.verify_signature(decrypted_message.decode(), bytes.fromhex(signature), sender_username)

        self.label_message_received.configure(text="Message: " + decrypted_message.decode())

        if hmac_validity:
            self.label_hmac_verification.configure(text="HMAC verified", text_color="green")
        else:
            self.label_hmac_verification.configure(text="HMAC not verified", text_color="red")

        if verification:
            self.label_digital_signature_verification.configure(text="Signature verified", text_color="green")
        else:
            self.label_digital_signature_verification.configure(text="Signature not verified", text_color="red")
class MainWindow(CTk):
    def __init__(self, username, password):
        super().__init__()

        self.username = username
        self.password = password
        self.title("Mon-Amour")

        self.geometry("380x410")
        self.resizable(False, False)

        self.tab_view = CustomTabView(self, username, password)
        self.tab_view.pack(fill="both", expand=True)
