from gui import *


def on_closing():
    app.destroy()


def main():
    app = LoginWindow()
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()


if __name__ == '__main__':
    main()