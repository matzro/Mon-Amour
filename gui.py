import customtkinter as ct

ct.set_appearance_mode("dark")
ct.set_default_color_theme("blue")

def tab1(tabview): # to send messages
    text = ct.CTkLabel(tabview.tab('Send message'), text='Send message', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

    question = ct.CTkEntry(tabview.tab('Send message'), placeholder_text='Question', font=('Calibri', 15))
    question.pack(padx=10, pady=10)

    secret_key = ct.CTkEntry(tabview.tab('Send message'), placeholder_text='Secret Key',
                                         font=('Calibri', 15), show='*')
    secret_key.pack(padx=10, pady=10)

    message = ct.CTkEntry(tabview.tab('Send message'), placeholder_text='Message', font=('Calibri', 15))
    message.pack(padx=10, pady=10)

    send_button = ct.CTkButton(tabview.tab('Send message'), text='Send', font=('Calibri', 15))
    send_button.pack(padx=10, pady=10)

def tab2(tabview): # to receive messages
    text = ct.CTkLabel(tabview.tab('Receive message'), text='Receive message', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

    #ciphertext = fm.read_file(FILE_NAME)
    #question2 = ciphertext[1]

    question = ct.CTkLabel(tabview.tab('Receive message'), text="questao")
    question.pack(padx=10, pady=10)

    secret_key = ct.CTkEntry(tabview.tab('Receive message'), placeholder_text='Secret Key',
                                         font=('Calibri', 15), show='*')
    secret_key.pack(padx=10, pady=10)

    receive_button = ct.CTkButton(tabview.tab('Receive message'), text='Receive', font=('Calibri', 15),)
    receive_button.pack(padx=10, pady=10)

def tab3(tabview):
    text = ct.CTkLabel(tabview.tab('Help'), text='Help', font=('Calibri', 15))
    text.pack(padx=10, pady=10)

def callInterface():
    window = ct.CTk()

    # --- Main window ---
    window.geometry("650x550")

    texto = ct.CTkLabel(window, text='Welcome to Mon-Amour messaging app', font=('Calibri', 20))
    texto.pack(padx=10, pady=20)

    tabview = ct.CTkTabview(window, width=400, height=350)
    tabview.pack()
    tabview.add('Send message')
    tabview.add('Receive message')
    tabview.add('Help')

    # --- Tabs ---
    tab1(tabview)
    tab2(tabview)
    tab3(tabview)

    # --- Close window ---
    botao4 = ct.CTkButton(window, text='Exit', font=('Calibri', 15), command=window.destroy)
    botao4.pack(padx=10, pady=10)


    window.mainloop()
