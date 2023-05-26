from customtkinter import *

import account_management as am
import rsa_functions as rf
import database_management as dbm
import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf

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

                # DUPLICATED CODE --- FIX THIS
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

        else:
            print("User does not exist. Creating new account...")
            dbm.add_user(username, password)
            print("Account created successfully")

            # DUPLICATED CODE --- FIX THIS
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
        super().__init__(master, width=800, height=600, **kwargs)

        self.username = username
        self.password = password

        # Create tabs
        self.add("Send")
        self.add("Receive")

        # Add widgets to Send tab
        # Recipient
        self.label_recipient = CTkLabel(self.tab("Send"), text="Recipient")
        self.label_recipient.grid(row=0, column=0, padx=20, pady=10)
        self.entry_recipient = CTkEntry(self.tab("Send"))
        self.entry_recipient.grid(row=0, column=1, padx=20, pady=10)

        # Question
        self.label_question_sent = CTkLabel(self.tab("Send"), text="Question")
        self.label_question_sent.grid(row=1, column=0, padx=20, pady=10)
        self.entry_question_sent = CTkEntry(self.tab("Send"))
        self.entry_question_sent.grid(row=1, column=1, padx=20, pady=10)

        # Answer
        self.label_answer_sent = CTkLabel(self.tab("Send"), text="Answer")
        self.label_answer_sent.grid(row=2, column=0, padx=20, pady=10)
        self.entry_answer_sent = CTkEntry(self.tab("Send"), show="*")
        self.entry_answer_sent.grid(row=2, column=1, padx=20, pady=10)

        # Message
        self.label_message_sent = CTkLabel(self.tab("Send"), text="Message")
        self.label_message_sent.grid(row=3, column=0, padx=20, pady=10)
        self.entry_message_sent = CTkEntry(self.tab("Send"))
        self.entry_message_sent.grid(row=3, column=1, padx=20, pady=10)

        # Button
        self.button_send = CTkButton(self.tab("Send"), text="Send", command=lambda: self.cipher(
            username,
            password,
            self.entry_question_sent.get(),
            self.entry_answer_sent.get(),
            self.entry_message_sent.get(),
            self.entry_recipient.get()
        ))
        self.button_send.grid(row=4, column=1, padx=20, pady=10)

        # Add widgets to Receive tab
        global ciphertext, sender_id
        try:
            ciphertext, sender_id = fm.read_file(username)
            question_received = ciphertext[1]

            # Question
            self.label_question_received = CTkLabel(self.tab("Receive"), text="Question: " + question_received)
            self.label_question_received.grid(row=0, column=0, padx=20, pady=10)

            # Answer
            self.label_answer_guess = CTkLabel(self.tab("Receive"), text="Answer")
            self.label_answer_guess.grid(row=1, column=0, padx=20, pady=10)
            self.entry_answer_guess = CTkEntry(self.tab("Receive"))
            self.entry_answer_guess.grid(row=1, column=1, padx=20, pady=10)

            # Button
            self.button_receive = CTkButton(self.tab("Receive"), text="Test my love", command=lambda: self.decipher(
                self.entry_answer_guess.get(),
            ))
            self.button_receive.grid(row=3, column=1, padx=20, pady=10)

        except:
            self.label_no_messages = CTkLabel(self.tab("Receive"), text="No messages")
            self.label_no_messages.grid(row=0, column=0, padx=20, pady=10)

        # Message
        self.label_message_received = CTkLabel(self.tab("Receive"), text="")
        self.label_message_received.grid(row=2, column=0, padx=20, pady=10)

        # HMAC Verification
        self.label_hmac_verification = CTkLabel(self.tab("Receive"), text="")
        self.label_hmac_verification.grid(row=3, column=0, padx=20, pady=10)

        # Digital Signature Verification
        self.label_digital_signature_verification = CTkLabel(self.tab("Receive"), text="")
        self.label_digital_signature_verification.grid(row=4, column=0, padx=20, pady=10)

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
        sk = secret_key.lower()

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

        self.label_message_received.configure(text=decrypted_message.decode())

        if hmac_validity:
            self.label_hmac_verification.configure(text="HMAC verified")
        else:
            self.label_hmac_verification.configure(text="HMAC not verified")

        if verification:
            self.label_digital_signature_verification.configure(text="Signature verified")
        else:
            self.label_digital_signature_verification.configure(text="Signature not verified")
class MainWindow(CTk):
    def __init__(self, username, password):
        super().__init__()

        self.username = username
        self.password = password

        self.geometry("800x600")

        self.tab_view = CustomTabView(self, username, password)
        self.tab_view.grid(row=0, column=0, padx=20, pady=20)
