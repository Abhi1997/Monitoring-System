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
class AdminConsole(QMainWindow):
    def __init__(self, user_id: str):
        super().__init__()
        self.user_id = user_id
        self.setWindowTitle(f"Admin Console - {user_id}")
        self.resize(900, 600)
        self.setStyleSheet("background-color:#2a2a2a; color:white;")

        cw = QWidget()
        self.setCentralWidget(cw)
        layout = QVBoxLayout(cw)

        top_bar = QHBoxLayout()
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setStyleSheet("background-color:#666666; color:white;")
        self.logout_btn.clicked.connect(self.logout)
        top_bar.addWidget(self.logout_btn)

        self.open_monitor_btn = QPushButton("Open Full Monitor")
        self.open_monitor_btn.setStyleSheet("background-color:#444444; color:white;")
        self.open_monitor_btn.clicked.connect(self.open_full_monitor)
        top_bar.addWidget(self.open_monitor_btn)

        layout.addLayout(top_bar)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "UserID", "IP", "LastUpdate", "CPU%", "Mem%", "GPU%", "NetUp?"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.timer = QTimer()
        self.timer.setInterval(10000)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start()

        self.refresh_data()

    def refresh_data(self):
        print("[AdminConsole] fetching user_usage from supabase.")
        try:
            res = supabase.table("user_usage").select("*").execute()
            rows = res.data or []
            self.table.setRowCount(len(rows))
            for i, rdict in enumerate(rows):
                uid = rdict.get("user_id", "?")
                ip = rdict.get("ip_address", "?")
                last_update = rdict.get("last_update", "")
                cpu = rdict.get("cpu_usage", 0)
                mem = rdict.get("mem_usage", 0)
                gpu = rdict.get("gpu_usage", 0)
                net = rdict.get("net_up", False)

                self.table.setItem(i, 0, QTableWidgetItem(uid))
                self.table.setItem(i, 1, QTableWidgetItem(ip))
                self.table.setItem(i, 2, QTableWidgetItem(str(last_update)))
                self.table.setItem(i, 3, QTableWidgetItem(f"{cpu:.1f}"))
                self.table.setItem(i, 4, QTableWidgetItem(f"{mem:.1f}"))
                self.table.setItem(i, 5, QTableWidgetItem(f"{gpu:.1f}"))
                self.table.setItem(i, 6, QTableWidgetItem("Yes" if net else "No"))
        except Exception as e:
            print("Error fetching user_usage:", e)
            QMessageBox.warning(self, "DB Error", str(e))

    def logout(self):
        
        from Mega_Login_cl import MegaLogin
        self.timer.stop()
        # Assuming MegaLogin is defined elsewhere in your code.
        self.login = MegaLogin()
        self.login.show()
        self.close()

    def open_full_monitor(self):
        # Assuming ResourceMonitorApp is defined elsewhere in your code.
        self.monitor = ResourceMonitorApp("admin_ip")
        self.monitor.show()
