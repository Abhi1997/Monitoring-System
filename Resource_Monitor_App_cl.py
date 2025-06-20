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
from Connected_Devices_Tab_cl import get_local_ip
from Network_Monitor_Window_cl import NetworkMonitorWindow, get_nvidia_gpu_usage
from Resource_Monitor_Tab_cl import ResourceMonitorTab
from Processes_Tab_cl import ProcessesTab
from Packet_Capture_Tab_cl import PacketCaptureTab
from Alerts_Tab_cl import AlertsTab
from Network_Tools_Tab_cl import NetworkToolsTab
from Connected_Devices_Tab_cl import ConnectedDevicesTab

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
def upsert_user_usage(user_id: str, ip_addr: str, cpu_val: float, mem_val: float, gpu_val: float, net_up: bool):
    """
    Upsert usage data into 'user_usage' table keyed by (user_id, ip_address).
    Overwrites old row for that user+IP.
    """
    try:
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data = {
            "user_id": user_id,
            "ip_address": ip_addr,
            "last_update": now_utc,
            "cpu_usage": cpu_val,
            "mem_usage": mem_val,
            "gpu_usage": gpu_val,
            "net_up": net_up
        }
        supabase.table("user_usage").upsert(data).execute()
    except Exception as e:
        print("Error upserting user usage:", e)
class ResourceMonitorApp(QMainWindow):
    def __init__(self, user_id: str):
        super().__init__()
        self.user_id = user_id
        self.ip_addr = get_local_ip()
        self.setWindowTitle(f"ResourceMonitor - user={user_id}, ip={self.ip_addr}")
        self.resize(1300, 800)
        self.setStyleSheet("background-color:#2a2a2a; color:white;")

        cw = QWidget()
        self.setCentralWidget(cw)
        layout = QVBoxLayout(cw)

        top_bar = QHBoxLayout()
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setStyleSheet("background-color:#666666; color:white;")
        self.logout_btn.clicked.connect(self.logout)
        top_bar.addWidget(self.logout_btn)
        layout.addLayout(top_bar)

        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        self.resources_tab = QTabWidget()
        self.tab_widget.addTab(self.resources_tab, "Resources")

        cpu_tab = ResourceMonitorTab("CPU")
        mem_tab = ResourceMonitorTab("Memory")
        gpu_tab = ResourceMonitorTab("GPU")
        net_tab = ResourceMonitorTab("Network")
        res_layout = QVBoxLayout(self.resources_tab)
        res_layout.addWidget(cpu_tab)
        res_layout.addWidget(mem_tab)
        res_layout.addWidget(gpu_tab)
        res_layout.addWidget(net_tab)
        self.resources_tab.setLayout(res_layout)

        self.proc_tab = ProcessesTab()
        self.tab_widget.addTab(self.proc_tab, "Processes")

        self.packet_tab = PacketCaptureTab()
        self.tab_widget.addTab(self.packet_tab, "Packet Capture")

        self.alerts_tab = AlertsTab()
        self.tab_widget.addTab(self.alerts_tab, "Alerts")

        self.tools_tab = NetworkToolsTab()
        self.tab_widget.addTab(self.tools_tab, "Network Tools")

        self.netmon = NetworkMonitorWindow()
        self.tab_widget.addTab(self.netmon, "Net Monitor")

        self.connected_tab = ConnectedDevicesTab()
        self.tab_widget.addTab(self.connected_tab, "Connected Devices")

        self.usage_timer = QTimer()
        self.usage_timer.setInterval(30000)
        self.usage_timer.timeout.connect(self.push_usage)
        self.usage_timer.start()

    def push_usage(self):
        cpu_val = psutil.cpu_percent()
        mem_val = psutil.virtual_memory().percent
        gpu_val = get_nvidia_gpu_usage()
        net_stats = psutil.net_if_stats()
        net_up = any(iface.isup for iface in net_stats.values())

        upsert_user_usage(self.user_id, self.ip_addr, cpu_val, mem_val, gpu_val, net_up)

    def logout(self):
        from Mega_Login_cl import MegaLogin
        self.usage_timer.stop()
        self.login = MegaLogin()
        self.login.show()
        self.close()