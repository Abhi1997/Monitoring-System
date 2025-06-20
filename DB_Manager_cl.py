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
