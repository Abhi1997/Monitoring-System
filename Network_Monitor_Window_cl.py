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

def get_nvidia_gpu_usage() -> float:
    """
    Improved function to retrieve GPU usage from nvidia-smi.
    Logs exceptions if something goes wrong.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, check=True
        )
        raw = result.stdout.strip()
        if not raw:
            print("[get_nvidia_gpu_usage] nvidia-smi returned empty output.")
            return 0.0
        val = float(raw)
        return val
    except FileNotFoundError as e:
        print("[get_nvidia_gpu_usage] nvidia-smi not found in PATH:", e)
        return 0.0
    except subprocess.CalledProcessError as e:
        print(f"[get_nvidia_gpu_usage] nvidia-smi command failed: {e.stderr or e}")
        return 0.0
    except Exception as e:
        print(f"[get_nvidia_gpu_usage] Unexpected error: {e}")
        return 0.0
class NetworkMonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitor (Reset Graph on Start)")
        self.setStyleSheet("color: white; background-color: #222222;")

        self.is_monitoring = False
        self.update_interval = 1000
        self.db_logging_enabled = True

        self.history_len = 60
        self.download_data = [0] * self.history_len
        self.upload_data = [0] * self.history_len

        netio = psutil.net_io_counters()
        self.last_recv = netio.bytes_recv
        self.last_sent = netio.bytes_sent
        self.last_time = time.time()

        cw = QWidget()
        self.setCentralWidget(cw)
        layout = QVBoxLayout(cw)

        top_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.toggle_monitor)
        top_layout.addWidget(self.start_btn)
        layout.addLayout(top_layout)

        usage_layout = QHBoxLayout()
        self.down_label = QLabel("Download: 0 Kbps")
        self.up_label = QLabel("Upload: 0 Kbps")
        self.gpu_label = QLabel("GPU: 0.0%")
        usage_layout.addWidget(self.down_label)
        usage_layout.addWidget(self.up_label)
        usage_layout.addWidget(self.gpu_label)
        layout.addLayout(usage_layout)

        self.fig = Figure(figsize=(5, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor("#222222")
        self.ax.set_facecolor("#333333")
        self.ax.tick_params(colors="white")
        for side in ["bottom", "top", "left", "right"]:
            self.ax.spines[side].set_color("white")
        self.ax.set_title("Bandwidth (Kbps)", color="white")

        self.canvas = FigureCanvasQTAgg(self.fig)
        layout.addWidget(self.canvas)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_usage)

    def toggle_monitor(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.start_btn.setText("Stop")

            netio = psutil.net_io_counters()
            self.last_recv = netio.bytes_recv
            self.last_sent = netio.bytes_sent
            self.last_time = time.time()

            self.download_data = [0] * self.history_len
            self.upload_data = [0] * self.history_len

            self.ax.clear()
            self.ax.set_facecolor("#333333")
            self.ax.tick_params(colors="white")
            for side in ["bottom", "top", "left", "right"]:
                self.ax.spines[side].set_color("white")
            self.ax.set_title("Bandwidth (Kbps)", color="white")
            self.canvas.draw()

            self.timer.start(self.update_interval)
        else:
            self.is_monitoring = False
            self.start_btn.setText("Start")
            self.timer.stop()

    def update_usage(self):
        now = time.time()
        dt = now - self.last_time
        if dt <= 0:
            return
        netio = psutil.net_io_counters()
        recv_diff = netio.bytes_recv - self.last_recv
        sent_diff = netio.bytes_sent - self.last_sent

        kbps_down = (recv_diff * 8 / 1024) / dt
        kbps_up = (sent_diff * 8 / 1024) / dt

        self.down_label.setText(f"Download: {kbps_down:.1f} Kbps")
        self.up_label.setText(f"Upload: {kbps_up:.1f} Kbps")

        gpu_val = get_nvidia_gpu_usage()
        self.gpu_label.setText(f"GPU: {gpu_val:.1f}%")

        self.download_data.pop(0)
        self.download_data.append(kbps_down)
        self.upload_data.pop(0)
        self.upload_data.append(kbps_up)

        self.ax.clear()
        self.ax.set_facecolor("#333333")
        self.ax.tick_params(colors="white")
        for side in ["bottom", "top", "left", "right"]:
            self.ax.spines[side].set_color("white")
        self.ax.set_title("Bandwidth (Kbps)", color="white")

        self.ax.plot(range(-self.history_len + 1, 1), self.download_data, color="#71f291", label="Download")
        self.ax.plot(range(-self.history_len + 1, 1), self.upload_data, color="#ffcc66", label="Upload")
        self.ax.legend(loc="upper left", facecolor="#444444", edgecolor="white", labelcolor="white")

        mx = max(max(self.download_data), max(self.upload_data))
        top = mx * 1.2 if mx > 1 else 100
        self.ax.set_ylim(0, top)
        self.canvas.draw()

        self.last_recv = netio.bytes_recv
        self.last_sent = netio.bytes_sent
        self.last_time = now
