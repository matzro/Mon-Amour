from gui import *


def on_closing():
    """Kills the program when the window is closed
    """
    app.destroy()


def main():
    """Initializes the program and the GUI
    """
    app = LoginWindow()
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()


if __name__ == '__main__':
    main()