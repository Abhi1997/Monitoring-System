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
from Time_Series_Panel_cl import TimeSeriesPanel

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
import mysql.connector
class ResourceMonitorTab(QWidget):
    def __init__(self, resource_name):
        super().__init__()
        self.resource_name = resource_name.lower()

        layout = QVBoxLayout(self)

        self.panel = TimeSeriesPanel(f"{resource_name} Monitor")

        self.usage_text = QLabel(f"{resource_name}: 0 Mbps")
        layout.addWidget(self.usage_text)
        layout.addWidget(self.panel)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_usage)
        self.timer.start(2000)

        self.last_net_data = psutil.net_io_counters()

        self.setLayout(layout)

    def update_usage(self):
        now=time.time()
        val=0.0
        if self.resource_name=="cpu":
            val=psutil.cpu_percent()
        elif self.resource_name=="memory":
            val=psutil.virtual_memory().percent
        elif self.resource_name=="gpu":
            # val=get_nvidia_gpu_usage()
            val=random.uniform(0,20)
        elif self.resource_name=="network":
            val=random.uniform(0,50)

        self.usage_text.setText(f"{self.resource_name.capitalize()}: {val:.2f}")
        self.panel.add_data_point(now,val)