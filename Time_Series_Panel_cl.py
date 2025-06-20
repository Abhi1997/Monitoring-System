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
