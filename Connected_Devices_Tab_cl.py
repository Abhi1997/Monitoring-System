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
from PyQt6.QtGui import QFont, QPixmap,QColor,QIcon, QColor, QPainter

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
def get_local_ip():
    """Attempts to get the local IP address (non-loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"
def create_colored_icon(color: QColor, size: int = 12) -> QIcon:
    """Creates a circular colored icon for the status indicator."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))  # Transparent background
    painter = QPainter(pixmap)
    painter.setBrush(color)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(0, 0, size, size)
    painter.end()
    return QIcon(pixmap)

class ConnectedDevicesTab(QWidget):
    """
    Optimized tab to scan the local /24 subnet and show which IPs respond to ping.
    """
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.info_label = QLabel("Scan the local /24 subnet. Green: UP, Red: Down.")
        layout.addWidget(self.info_label)

        self.scan_btn = QPushButton("Scan Subnet")
        self.scan_btn.clicked.connect(self.scan_subnet)
        layout.addWidget(self.scan_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["IP Address", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setColumnWidth(1, 150)  # Make sure status column is wide enough
        layout.addWidget(self.table)



    def scan_subnet(self):
        self.table.setRowCount(0)
    
        local_ip = get_local_ip()
        if local_ip == "0.0.0.0":
            QMessageBox.warning(self, "No IP", "Could not determine local IP for scanning.")
            return
    
        ip_parts = local_ip.split(".")
        if len(ip_parts) != 4:
            QMessageBox.warning(self, "Error", "Local IP not in dotted-decimal form.")
            return
    
        base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    
        row_count = 0
        for host in range(1, 256):
            ip = f"{base}.{host}"
            alive = False
    
            # OS-specific ping command
            if platform.system().lower().startswith("win"):
                cmd = ["ping", "-n", "1", "-w", "300", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
    
            try:
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    alive = True
            except Exception as e:
                print(f"Ping error for {ip}: {e}")
    
            self.table.insertRow(row_count)
    
            ip_item = QTableWidgetItem(ip)
            self.table.setItem(row_count, 0, ip_item)
    
            # Create a colored circle label
            dot_label = QLabel()
            dot_size = 12
            pixmap = QPixmap(dot_size, dot_size)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QColor("lime" if alive else "red"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(0, 0, dot_size, dot_size)
            painter.end()
            dot_label.setPixmap(pixmap)
            dot_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot_label.setToolTip("UP" if alive else "Down")
    
            self.table.setCellWidget(row_count, 1, dot_label)
    
            row_count += 1
    
        QMessageBox.information(self, "Scan complete", f"Scanned {base}.0/24.")