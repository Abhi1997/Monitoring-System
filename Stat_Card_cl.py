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
class StatCard(QFrame):
    def __init__(self, title: str, initial="--"):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #1f1f1f;
                border: 1px solid #2a2a2a;
                border-radius: 3px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #aaaaaa;")
        tf = QFont("Arial", 10)
        self.title_label.setFont(tf)

        self.value_label = QLabel(str(initial))
        self.value_label.setStyleSheet("color: #71f291;")
        vf = QFont("Arial", 16, QFont.Weight.Bold)
        self.value_label.setFont(vf)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, val):
        self.value_label.setText(str(val))
