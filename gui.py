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

            if dbm.password_checking(password, hashed_password) and password != "":
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
    1. Introduction
	This program called "Mon-Amour Messaging App" aims to send and receive messages of love.
	To use this application, you will need to register.
	When sending a message, it will be encrypted using the AES128 algorithm in CTR mode. To perform the encryption, you will need to provide the answer to the question defined by the sender.
	When receiving a message, it will be decrypted using the same algorithm and mode. The question defined by the sender will be displayed on the screen, and you need to enter the same answer as the sender to view the message content.


    2. User Guide
        2.1. After launching the application, the login page will be displayed, showing two text boxes and two buttons. Enter a username in the "Username" text box and a password in the "Password" text box. Then, click the "Login" button to start your experience with the "Mon-Amour Messaging App".
        The "Help" button is used to open the help manual, where you will find all the necessary information to correctly use the application.

        2.2  If you register successfully, a new page will be shown with two options: "Send Message" and "Receive Message". 
        	1. Send Message: By clicking this button on the main menu, you will be redirected to a new tab. In that tab, you will find three text boxes and two buttons. 
        	1.1 In the first text box, "Recipient", enter the recipient of the message;
        	1.2 In  second text box, "Question", enter a question (e.g., "What is your favorite color?");
        	1.3 In the third text box, "Answer", enter the answer to the question you entered in the previous box (e.g., "yellow");
        	1.4 In the fourth text box, "Message", include the message you want to send.
        	1.5 The "Send" button will send your message;
        	1.6 If you don't want to send the message, choose another tab.

        	2. Receive Message: When clicking this button, you will be redirected to a new tab. In that tab, you should find a question, a text box, and a button.
        	2.1 In the text box, "Answer", enter the correct answer to the question displayed on the screen. 
        	2.2 Then, click the "Receive" button, and if the answer to the question is correct, you will be able to view the content of the message you received. Otherwise, a pop-up will appear indicating that the answer to the question is incorrect.
        """

        # Add widgets to Help tab
        scrollable_frame = CTkScrollableFrame(self.tab("Help"))
        scrollable_frame.pack(expand=True, fill="both")
        self.label_help = CTkLabel(scrollable_frame, text=help, wraplength=320, font=("Poppins", 12), justify="left")
        self.label_help.grid(row=0, column=0, padx=20)

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
        print(decrypted_message)

        if decrypted_message is None:
            self.label_message_received.configure(text="Answer incorrect", text_color="red")
        else:
            digital_signature_verification = ds.verify_signature(decrypted_message, bytes.fromhex(signature), sender_username)

            self.label_message_received.configure(text="Message: " + decrypted_message, text_color="white")
            self.label_hmac_verification.configure(text="HMAC verified", text_color="green")

            if hmac_validity:
                self.label_hmac_verification.configure(text="HMAC verified: Authentic message recieved.", text_color="green")
            else:
                self.label_hmac_verification.configure(text="HMAC not verified: The message recieved is not authentic!!", text_color="red")

            if digital_signature_verification:
                self.label_digital_signature_verification.configure(text="Signature verified: ", text_color="green")
            else:
                self.label_digital_signature_verification.configure(text="Signature not verified: ", text_color="red")
class MainWindow(CTk):
    def __init__(self, username, password):
        super().__init__()

        self.username = username
        self.password = password
        self.title("Mon-Amour")

        self.geometry("400x420")
        self.resizable(False, False)

        self.tab_view = CustomTabView(self, username, password)
        self.tab_view.pack(fill="both", expand=True)
