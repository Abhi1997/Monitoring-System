import sys
from PyQt6.QtWidgets import QApplication
from Mega_Login_cl import MegaLogin


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet("QWidget { background-color:#444444; color:white; }")

    login = MegaLogin()
    login.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()