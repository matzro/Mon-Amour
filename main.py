from gui import *

def on_closing():
    app.destroy()

if __name__ == '__main__':
    """This is the main function. It creates the GUI and calls the functions cipher() and decipher() when the user clicks
    """
    app = LoginWindow()
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()

