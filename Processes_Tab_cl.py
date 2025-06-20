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
from Priority_Dialog_cl import PriorityDialog

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
