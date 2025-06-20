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

def get_local_ip() -> str:
    """
    Attempt to get the primary local IP address by connecting to 8.8.8.8:80.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

# ---------------------------------------------------------------------------
# MySQL DB manager code
import mysql.connector

class DBManager:
    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.conn = None

    def connect(self):
        if self.conn and self.conn.is_connected():
            self.conn.close()
        self.conn = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        return self.conn

    def get_connection(self):
        if self.conn is None or not self.conn.is_connected():
            self.connect()
        return self.conn

    def close(self):
        if self.conn and self.conn.is_connected():
            self.conn.close()
            self.conn = None

db_manager = DBManager(
    host="localhost",
    user="root",
    password="Innovation",
    database="ICK"
)

def check_credentials_mysql(username: str, pwd: str) -> bool:
    """
    (Optional) MySQL-based login check, if needed.
    """
    try:
        conn = db_manager.get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM users WHERE username=%s AND password=%s",
            (username, pwd)
        )
        row = cur.fetchone()
        return (row and row[0] > 0)
    except mysql.connector.Error as err:
        print(f"MySQL error (login): {err}")
        return False
    except Exception as e:
        print(f"Other DB error: {e}")
        return False

def store_net_log_in_db(ts: datetime.datetime, dl_kbps: float, up_kbps: float, gpu_usage: float):
    """
    Example storing net logs in MySQL's 'network_logs' table. 
    (Optional, depends on your schema.)
    """
    try:
        conn = db_manager.get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO network_logs (ts, download_kbps, upload_kbps, gpu_usage)
            VALUES (%s, %s, %s, %s)
        """, (ts, dl_kbps, up_kbps, gpu_usage))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"MySQL error storing net log: {err}")

# ---------------------------------------------------------------------------
# Basic CSV logs parse (Optional)
import csv

def parse_logs(folder="logs"):
    """
    Just a demonstration approach to parse logs in 'logs' folder. 
    Return a daily_data dict: daily_data[date_str] -> [(dt, cpu, mem, gpu, net), ...]
    """
    daily_data = {}
    if not os.path.isdir(folder):
        return daily_data

    files = [f for f in os.listdir(folder) if f.lower().endswith(".csv")]
    if not files:
        return daily_data

    for filename in files:
        path = os.path.join(folder, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) < 5:
                        continue
                    timestr, cpu_s, mem_s, gpu_s, net_s = row
                    try:
                        dt = datetime.datetime.strptime(timestr.strip(), "%Y-%m-%d %H:%M:%S")
                        cpu_v = float(cpu_s)
                        mem_v = float(mem_s)
                        gpu_v = float(gpu_s)
                        net_v = float(net_s)
                    except:
                        continue
                    date_s = dt.date().isoformat()
                    daily_data.setdefault(date_s, []).append((dt, cpu_v, mem_v, gpu_v, net_v))
        except:
            pass
    return daily_data

# ---------------------------------------------------------------------------
# The "AdminConsole" for role='admin'
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
        self.timer.stop()
        # Assuming MegaLogin is defined elsewhere in your code.
        self.login = MegaLogin()
        self.login.show()
        self.close()

    def open_full_monitor(self):
        # Assuming ResourceMonitorApp is defined elsewhere in your code.
        self.monitor = ResourceMonitorApp("admin_ip")
        self.monitor.show()

# ---------------------------------------------------------------------------
# Additional resource tabs, etc.
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


class TimeSeriesPanel(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #1f1f1f;
                border: 1px solid #2a2a2a;
                border-radius: 3px;
            }
        """)
        layout = QVBoxLayout(self)

        # Title label
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #ffffff;")
        f = QFont("Arial", 10, QFont.Weight.Bold)
        self.title_label.setFont(f)
        layout.addWidget(self.title_label)

        # Figure and axis setup
        self.fig = Figure(figsize=(4, 2), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor("#1f1f1f")
        self.ax.set_facecolor("#1f1f1f")
        self.ax.tick_params(colors="#aaaaaa")
        for side in ["bottom", "top", "left", "right"]:
            self.ax.spines[side].set_color("#aaaaaa")
        self.ax.grid(color="#444444", linestyle="--", linewidth=0.5)

        # Data
        self.xdata = []
        self.ydata = []

        # Canvas for rendering the plot
        self.canvas = FigureCanvasQTAgg(self.fig)
        layout.addWidget(self.canvas)
        self.setLayout(layout)

        # Set y-axis limits to 0-100 (percentage range)
        self.ax.set_ylim(0, 100)

        # Hide horizontal axis labels
        self.ax.set_xticklabels([])
        self.ax.set_xticks([])

    def add_data_point(self, x, y):
        self.xdata.append(x)
        self.ydata.append(y)
        
        # Limit to the last 60 data points
        self.xdata = self.xdata[-60:]
        self.ydata = self.ydata[-60:]

        # Clear and re-plot the graph
        self.ax.clear()
        self.ax.set_facecolor("#1f1f1f")
        self.ax.tick_params(colors="#aaaaaa")
        for side in ["bottom", "top", "left", "right"]:
            self.ax.spines[side].set_color("#aaaaaa")
        self.ax.grid(color="#444444", linestyle="--", linewidth=0.5)

        self.ax.plot(self.xdata, self.ydata, color="#71f291")
        self.ax.set_ylim(0, 100)

        self.canvas.draw()


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


class ProcessesTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by PID or name...")
        self.search_edit.textChanged.connect(self.refresh_processes)
        layout.addWidget(self.search_edit)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["PID", "Name", "CPU%", "Mem%", "Priority"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()

        self.kill_btn = QPushButton("Kill Process")
        self.kill_btn.setToolTip("Kill the selected process.")
        self.kill_btn.clicked.connect(self.kill_process)
        btn_layout.addWidget(self.kill_btn)

        self.priority_btn = QPushButton("Set Priority")
        self.priority_btn.setToolTip("Change the priority of the selected process.")
        self.priority_btn.clicked.connect(self.set_priority_dialog)
        btn_layout.addWidget(self.priority_btn)

        layout.addLayout(btn_layout)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setToolTip("Refresh the process list manually.")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        btn_layout.addWidget(self.refresh_btn)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(3000)

    def refresh_processes(self):
        search_text = self.search_edit.text().lower().strip()

        selected_row = self.table.currentRow()
        selected_pid = None
        if selected_row >= 0:
            item = self.table.item(selected_row, 0)
            if item:
                selected_pid = item.text()

        proc_list = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            info = p.info
            if (not search_text or 
                search_text in str(info['pid']) or 
                (info['name'] and search_text in info['name'].lower())):
                proc_list.append(p)

        proc_list.sort(key=lambda x: x.info['cpu_percent'] or 0, reverse=True)

        self.table.setRowCount(len(proc_list))
        for row, pp in enumerate(proc_list):
            info = pp.info
            pid_item = QTableWidgetItem(str(info['pid']))
            name_item = QTableWidgetItem(info['name'])
            cpu_item = QTableWidgetItem(f"{info['cpu_percent']:.1f}" if info['cpu_percent'] else "0.0")
            mem_item = QTableWidgetItem(f"{info['memory_percent']:.1f}" if info['memory_percent'] else "0.0")
            
            try:
                prio = pp.nice()
            except Exception:
                prio = "?"
            
            prio_item = QTableWidgetItem(str(prio))

            self.table.setItem(row, 0, pid_item)
            self.table.setItem(row, 1, name_item)
            self.table.setItem(row, 2, cpu_item)
            self.table.setItem(row, 3, mem_item)
            self.table.setItem(row, 4, prio_item)

        if selected_pid:
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).text() == selected_pid:
                    self.table.selectRow(r)
                    break

    def kill_process(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a process row first.")
            return
        
        pid = int(self.table.item(row, 0).text())
        try:
            psutil.Process(pid).kill()
            QMessageBox.information(self, "Killed", f"Process PID {pid} was killed.")
        except psutil.AccessDenied:
            QMessageBox.warning(self, "Permission Error", f"You lack permission to kill PID {pid}.")
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "Error", f"PID {pid} does not exist.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not kill PID {pid}:\n{e}")

    def set_priority_dialog(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a process row first.")
            return
        
        pid = int(self.table.item(row, 0).text())
        dialog = PriorityDialog(pid)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_priority = dialog.get_priority()
            try:
                p = psutil.Process(pid)
                p.nice(new_priority)
                QMessageBox.information(self, "Priority Set", f"PID {pid} priority changed to {new_priority}.")
            except psutil.AccessDenied:
                QMessageBox.warning(self, "Permission Error", f"You lack permission to set priority for PID {pid}.")
            except psutil.NoSuchProcess:
                QMessageBox.warning(self, "Error", f"PID {pid} no longer exists.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not set priority:\n{e}")
        self.refresh_processes()


class PriorityDialog(QDialog):
    def __init__(self, pid):
        super().__init__()
        self.setWindowTitle("Set Priority")
        self.pid = pid
        layout = QVBoxLayout(self)

        label = QLabel(f"Set new 'nice' value for PID {pid}.\nRange -20 (highest) to 19 (lowest).")
        layout.addWidget(label)

        self.spin = QSpinBox()
        self.spin.setRange(-20, 19)
        layout.addWidget(self.spin)

        buttonBox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        layout.addWidget(buttonBox)

    def get_priority(self):
        return self.spin.value()


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


##############################################################################
# The ring-buffer Net Monitor
##############################################################################
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


##############################################################################
# ConnectedDevicesTab: Naive local subnet scan
##############################################################################
class ConnectedDevicesTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        self.info_label = QLabel("Naive IP scan: Attempt to ping each IP in your local /24 subnet, listing successes.")
        layout.addWidget(self.info_label)

        self.scan_btn = QPushButton("Scan Subnet")
        self.scan_btn.clicked.connect(self.scan_subnet)
        layout.addWidget(self.scan_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["IP", "Status"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def scan_subnet(self):
        self.table.setRowCount(0)
        local_ip = get_local_ip()  # e.g. 192.168.0.20
        if local_ip == "0.0.0.0":
            QMessageBox.warning(self, "No IP", "Could not determine local IP for scanning.")
            return

        ip_parts = local_ip.split(".")
        base = ".".join(ip_parts[:3])
        row_count = 0
        system = platform.system().lower()
        for host in range(1, 255):
            ip = f"{base}.{host}"
            if system.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", "300", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]

            alive = subprocess.run(cmd, capture_output=True).returncode == 0
            self.table.insertRow(row_count)
            self.table.setItem(row_count, 0, QTableWidgetItem(ip))
            self.table.setItem(row_count, 1, QTableWidgetItem("UP" if alive else "Down"))
            row_count += 1

        QMessageBox.information(self, "Scan complete", f"Scanned {base}.0/24.")


##############################################################################
# The ResourceMonitorApp with multiple tabs
##############################################################################
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
        self.usage_timer.stop()
        self.login = MegaLogin()
        self.login.show()
        self.close()


##############################################################################
# The role-based MegaLogin
##############################################################################
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
