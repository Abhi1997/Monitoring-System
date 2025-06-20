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
import mysql.connector
class PacketCaptureTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self.info_label = QLabel(
            "Requires root. Enter a filter (e.g. 'tcp port 80') -> 'Start'. Captures packets."
        )
        layout.addWidget(self.info_label)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Scapy filter (e.g. 'tcp port 80')")
        layout.addWidget(self.filter_edit)

        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setToolTip("Start capturing packets with the given filter.")
        self.start_btn.clicked.connect(self.start_capture)
        layout.addWidget(self.start_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["No", "Source", "Destination"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        self.status_label = QLabel("Status: Idle")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)

        self.packets = []

    def start_capture(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Scapy Missing", "Install scapy with 'pip install scapy'.")
            return

        ffilter = self.filter_edit.text().strip()

        self.status_label.setText("Status: Capturing...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(False)
        self.packets = []
        self.table.setRowCount(0)

        try:
            sniff(prn=self.process_packet, filter=ffilter if ffilter else None, store=0, timeout=30, count=0)
        except PermissionError:
            QMessageBox.warning(self, "Permission Error", "Root privileges required for scapy capturing.")
            self.stop_capture()
        except Exception as e:
            QMessageBox.warning(self, "Capture Error", f"Error capturing:\n{e}")
            self.stop_capture()

    def process_packet(self, packet):
        packet_info = {
            'src': packet[1].src if 'IP' in packet else '--',
            'dst': packet[1].dst if 'IP' in packet else '--'
        }
        self.packets.append(packet_info)
        self.update_table()
        self.progress_bar.setValue(len(self.packets) * 100 // 10)
        if len(self.packets) >= 10:
            self.stop_capture()

    def update_table(self):
        self.table.setRowCount(len(self.packets))
        for i, packet_info in enumerate(self.packets):
            no_item = QTableWidgetItem(str(i + 1))
            src_item = QTableWidgetItem(packet_info['src'])
            dst_item = QTableWidgetItem(packet_info['dst'])
            self.table.setItem(i, 0, no_item)
            self.table.setItem(i, 1, src_item)
            self.table.setItem(i, 2, dst_item)

    def stop_capture(self):
        self.status_label.setText("Status: Idle")
        self.start_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.timer.stop()
        QMessageBox.information(self, "Capture Done", f"Captured {len(self.packets)} packets.")

