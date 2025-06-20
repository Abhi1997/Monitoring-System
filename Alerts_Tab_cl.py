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
class AlertsTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        label = QLabel("Set CPU & Mem thresholds. Alerts if usage > threshold.\n(Example only.)")
        layout.addWidget(label)

        form = QFormLayout()
        self.cpu_sp = QSpinBox()
        self.cpu_sp.setRange(0, 100)
        self.cpu_sp.setValue(90)
        self.mem_sp = QSpinBox()
        self.mem_sp.setRange(0, 100)
        self.mem_sp.setValue(90)
        form.addRow("CPU% threshold:", self.cpu_sp)
        form.addRow("Mem% threshold:", self.mem_sp)
        layout.addLayout(form)

        self.enable_cb = QCheckBox("Enable Alerts")
        self.enable_cb.setChecked(True)
        layout.addWidget(self.enable_cb)

        self.cpu_progress = QProgressBar(self)
        self.cpu_progress.setRange(0, 100)
        self.cpu_progress.setValue(0)
        self.cpu_progress.setTextVisible(True)
        self.cpu_progress.setFormat("CPU: %p%")
        
        self.mem_progress = QProgressBar(self)
        self.mem_progress.setRange(0, 100)
        self.mem_progress.setValue(0)
        self.mem_progress.setTextVisible(True)
        self.mem_progress.setFormat("Memory: %p%")

        layout.addWidget(self.cpu_progress)
        layout.addWidget(self.mem_progress)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.check_alerts)
        self.timer.start(3000)

        self.last_cpu_alert = None
        self.last_mem_alert = None

    def update_progress(self, cpu_val, mem_val):
        self.cpu_progress.setValue(int(cpu_val))
        self.mem_progress.setValue(int(mem_val))
        self.update_progress_color(cpu_val, self.cpu_progress)
        self.update_progress_color(mem_val, self.mem_progress)

    def update_progress_color(self, value, progress_bar):
        if value < 50:
            progress_bar.setStyleSheet("QProgressBar {border: 2px solid gray; border-radius: 5px; background: #e0e0e0; text-align: center; color: black;} QProgressBar::chunk {background: green;}")
        elif value < 75:
            progress_bar.setStyleSheet("QProgressBar {border: 2px solid gray; border-radius: 5px; background: #e0e0e0; text-align: center; color: black;} QProgressBar::chunk {background: yellow;}")
        else:
            progress_bar.setStyleSheet("QProgressBar {border: 2px solid gray; border-radius: 5px; background: #e0e0e0; text-align: center; color: black;} QProgressBar::chunk {background: red;}")

    def check_alerts(self):
        if not self.enable_cb.isChecked():
            return

        cpu_val = psutil.cpu_percent()
        mem_val = psutil.virtual_memory().percent

        self.update_progress(cpu_val, mem_val)

        if cpu_val > self.cpu_sp.value():
            if self.last_cpu_alert != cpu_val:
                self.last_cpu_alert = cpu_val
                alert_msg = f"CPU usage {cpu_val:.1f}% > {self.cpu_sp.value()}%!"
                self.show_alert("CPU Alert", alert_msg)

        if mem_val > self.mem_sp.value():
            if self.last_mem_alert != mem_val:
                self.last_mem_alert = mem_val
                alert_msg = f"Memory usage {mem_val:.1f}% > {self.mem_sp.value()}%!"
                self.show_alert("Memory Alert", alert_msg)

    def show_alert(self, title, message):
        alert_label = QLabel(f"<b>{title}</b>: {message}")
        alert_label.setStyleSheet("color: red; font-weight: bold;")
        self.layout().addWidget(alert_label)
        QTimer.singleShot(3000, lambda: self.remove_alert(alert_label))

    def remove_alert(self, alert_label):
        self.layout().removeWidget(alert_label)
        alert_label.deleteLater()
