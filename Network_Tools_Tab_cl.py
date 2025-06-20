
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
class NetworkToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout=QVBoxLayout(self)

        self.info_label=QLabel("Enter host, select ping/traceroute, see output below.")
        layout.addWidget(self.info_label)

        form=QFormLayout()
        self.host_edit=QLineEdit()
        self.host_edit.setText("8.8.8.8")
        form.addRow("Host/IP:",self.host_edit)

        self.tool_combo=QComboBox()
        self.tool_combo.addItems(["ping","traceroute"])
        form.addRow("Tool:",self.tool_combo)

        layout.addLayout(form)

        self.run_btn=QPushButton("Run Tool")
        self.run_btn.clicked.connect(self.run_tool)
        layout.addWidget(self.run_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.output_label=QLabel("")
        self.output_label.setStyleSheet("background-color:#333333; color:white;")
        self.output_label.setMinimumHeight(200)
        layout.addWidget(self.output_label)

        self.setLayout(layout)

    def run_tool(self):
        host=self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(self,"Error","Host/IP cannot be empty.")
            return
        tool=self.tool_combo.currentText()
        if tool=="ping":
            # cross-platform ping: on Windows => ping -n 4, on Linux => ping -c 4
            if platform.system().lower().startswith("win"):
                cmd=["ping","-n","4",host]
            else:
                cmd=["ping","-c","4",host]
        else:
            if platform.system().lower().startswith("win"):
                # windows doesn't have traceroute by default, it's 'tracert'
                cmd=["tracert","-h","5",host]
            else:
                cmd=["traceroute","-m","5",host]

        try:
            res=subprocess.run(cmd,capture_output=True,text=True,check=False)
            self.output_label.setText(res.stdout+"\n"+res.stderr)
        except FileNotFoundError:
            self.output_label.setText(f"Command not found: {cmd[0]}")
        except Exception as e:
            self.output_label.setText(str(e))
