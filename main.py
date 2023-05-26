from gui import *


def on_closing():
    app.destroy()


if __name__ == '__main__':
    """Main function"""
    app = LoginWindow()
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()
