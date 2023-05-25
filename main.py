import customtkinter
from gui import *


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

