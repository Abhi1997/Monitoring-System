from email.mime import base
import sys
import datetime
import subprocess
import socket
import os
import csv
import time
import re
import random
import traceback
import platform

import psutil

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QLineEdit, QMessageBox, QFrame, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox, QDialog, QDialogButtonBox,
    QGridLayout, QFileDialog, QComboBox, QProgressBar, QTextEdit
)
from PyQt6.QtCore import QTimer, Qt, pyqtSignal, QDate, QThread
from PyQt6.QtGui import QFont, QPixmap, QIcon

import matplotlib
matplotlib.use("qtagg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from Admin_Console_cl import AdminConsole
from Resource_Monitor_App_cl import ResourceMonitorApp

# scapy for advanced packet capture, optional
try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# SUPABASE
from supabase import create_client, Client

SUPABASE_URL = "https://dfddejhgkbocpefsfwnm.supabase.co"  # example from your snippet
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRmZGRlamhna2JvY3BlZnNmd25tIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDE0MzcxODcsImV4cCI6MjA1NzAxMzE4N30.yAjJu50qA7G8eM9elBiTIZ_4g_Vt8UAa8t9JzdqgAv4"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
def check_credentials_supabase(user_id: str, pwd: str):
    """
    Returns (role, ip_address) if user_id + password match in 'users' table, else (None, None).
    """
    try:
        res = supabase.table("users").select("*").eq("user_id", user_id).execute()
        rows = res.data or []
        if not rows:
            return (None, None)
        row = rows[0]
        stored_pwd = row.get("password", "")
        role = row.get("role", "user")
        ip_addr = row.get("ip_address", "0.0.0.0")
        if pwd == stored_pwd:
            return (role, ip_addr)
    except Exception as e:
        print("Supabase error in check_credentials:", e)
    return (None, None)

class MegaLogin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login with role-based: admin or user -> console or resource monitor")
        self.setStyleSheet("background-color:#444444; color:white;")
        self.resize(400, 200)

        cw = QWidget()
        self.setCentralWidget(cw)
        layout = QVBoxLayout(cw)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("user_id")
        layout.addWidget(self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setPlaceholderText("password")
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass_edit)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.attempt_login)
        layout.addWidget(self.login_btn)

    def attempt_login(self):
        user_id = self.user_edit.text().strip()
        pwd = self.pass_edit.text().strip()
        if not user_id or not pwd:
            QMessageBox.warning(self, "Error", "User ID or password empty.")
            return

        role, ip_addr = check_credentials_supabase(user_id, pwd)
        if role is None:
            QMessageBox.warning(self, "Login Failed", "Invalid user or password.")
            return

        if role == "admin":
            self.admin = AdminConsole(user_id)
            self.admin.show()
            self.close()
        else:
            self.user_win = ResourceMonitorApp(user_id)
            self.user_win.show()
            self.close()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet("QWidget { background-color:#444444; color:white; }")

    login = MegaLogin()
    login.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
