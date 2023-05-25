from customtkinter import *

import account_management as am
import database_management as dm
import rsa_functions as rf
import account_management as am
import database_management as dm
import digital_signature as ds
import encryption_functions as ef
import file_management as fm
import mac_functions as mf
import rsa_functions as rf

class LoginWindow(CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        main_frame = CTkFrame(self, fg_color=self.cget("bg"))
        main_frame.grid(row=0, column=0, padx=10, pady=10)

        # Login title
        title = CTkLabel(main_frame, text="Login")
        title.grid(row=0, column=0, pady=(0, 20))

        # Username label
        username_label = CTkLabel(main_frame, text="Username")
        username_label.grid(row=1, column=0, sticky="w", pady=(0, 10))
        user_entry = CTkEntry(main_frame)
        user_entry.grid(row=1, column=1, pady=(0, 10))

        # Password label
        password_label = CTkLabel(main_frame, text="Password")
        password_label.grid(row=2, column=0, sticky="w", pady=(0, 10))
        password_entry = CTkEntry(main_frame, show="*")
        password_entry.grid(row=2, column=1, pady=(0, 10), padx=10)

        # Login button
        login_button = CTkButton(main_frame, text="Login", command=lambda: self.login(user_entry.get(), password_entry.get()))
        login_button.grid(row=4, column=1, pady=(0, 20), sticky="e")

    def login(self, username, password):
        dm.load_database()
        if dm.check_if_user_exists(username):
            hashed_password = dm.get_user_password(username)

            if dm.password_checking(password, hashed_password):
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
            dm.add_user(username, password)
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
        self.label_question = CTkLabel(self.tab("Send"), text="Question")
        self.label_question.grid(row=1, column=0, padx=20, pady=10)
        self.entry_question = CTkEntry(self.tab("Send"))
        self.entry_question.grid(row=1, column=1, padx=20, pady=10)

        # Answer
        self.label_answer = CTkLabel(self.tab("Send"), text="Answer")
        self.label_answer.grid(row=2, column=0, padx=20, pady=10)
        self.entry_answer = CTkEntry(self.tab("Send"), show="*")
        self.entry_answer.grid(row=2, column=1, padx=20, pady=10)

        # Message
        self.label_message = CTkLabel(self.tab("Send"), text="Message")
        self.label_message.grid(row=3, column=0, padx=20, pady=10)
        self.entry_message = CTkEntry(self.tab("Send"))
        self.entry_message.grid(row=3, column=1, padx=20, pady=10)

        #Button
        self.button_send = CTkButton(self.tab("Send"), text="Send", command=lambda: self.cipher(
            username,
            password,
            self.entry_question.get(),
            self.entry_answer.get(),
            self.entry_message.get(),
            self.entry_recipient.get()
        ))
        self.button_send.grid(row=4, column=1, padx=20, pady=10)

        # Add widgets to Receive tab
        # Question
        self.label = CTkLabel(self.tab("Receive"), text="Question:")
        self.label.grid(row=0, column=0, padx=20, pady=10)
        self.entry = CTkEntry(self.tab("Receive"))
        self.entry.grid(row=0, column=1, padx=20, pady=10)

        # Answer
        self.label = CTkLabel(self.tab("Receive"), text="Answer")
        self.label.grid(row=1, column=0, padx=20, pady=10)
        self.entry = CTkEntry(self.tab("Receive"))
        self.entry.grid(row=1, column=1, padx=20, pady=10)

        # Message
        self.label = CTkLabel(self.tab("Receive"), text="Message")
        self.label.grid(row=2, column=0, padx=20, pady=10)
        self.entry = CTkEntry(self.tab("Receive"))
        self.entry.grid(row=2, column=1, padx=20, pady=10)

        # Button
        self.button = CTkButton(self.tab("Receive"), text="Test my love")
        self.button.grid(row=3, column=1, padx=20, pady=10)

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

        iter_counter, salt, ciphertext = ef.encrypt_message(message, sk)
        hmac_value = mf.calculate_hmac(ciphertext, sk)
        signature = ds.generate_signature(message, username, password)
        fm.write_file(iter_counter, question, salt, ciphertext, hmac_value, signature, username, recipient)

class MainWindow(CTk):
    def __init__(self, username, password):
        super().__init__()

        self.username = username
        self.password = password

        self.geometry("800x600")

        self.tab_view = CustomTabView(self, username, password)
        self.tab_view.grid(row=0, column=0, padx=20, pady=20)






