# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import multiprocessing
import sys
import os
import queue
import traceback
import ipaddress
import threading
import math
import socket

# 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from PyQt5.QtWidgets import (
                                QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                QTextEdit, QMessageBox, QGroupBox, QProgressBar,
                                QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
                                QFrame
                            )
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette, QBrush

# 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from utils.db_connector import DBConnector
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.windows_inspector import WindowsInspector
from output.pdf_report import PDFGenerator

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def my_exception_hook(exctype, value, tb):
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    print(error_msg)

sys.excepthook = my_exception_hook

# --- [스타일시트: 다크 모드 & 모던 UI] ---
STYLESHEET = """
QMainWindow {
    background-color: #1e1e1e;
}
QWidget {
    color: #e0e0e0;
    font-family: 'Segoe UI', 'Malgun Gothic', sans-serif;
    font-size: 14px;
}
QGroupBox {
    border: 1px solid #3e3e3e;
    border-radius: 8px;
    margin-top: 20px;
    background-color: #252526;
    font-weight: bold;
    color: #007acc;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 5px;
}
QLineEdit {
    background-color: #333333;
    border: 1px solid #444444;
    border-radius: 4px;
    padding: 8px;
    color: #ffffff;
    selection-background-color: #007acc;
}
QLineEdit:focus {
    border: 1px solid #007acc;
}
QPushButton {
    background-color: #3a3a3a;
    border: 1px solid #555555;
    border-radius: 6px;
    padding: 10px 15px;
    color: #ffffff;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #4a4a4a;
    border-color: #007acc;
}
QPushButton:pressed {
    background-color: #2a2a2a;
}
QPushButton:disabled {
    background-color: #252526;
    color: #666666;
    border-color: #333333;
}
/* 클리어 버튼 전용 스타일 */
QPushButton#ClearBtn {
    padding: 4px 10px;
    font-size: 12px;
    background-color: #444;
    border: 1px solid #666;
}
QPushButton#ClearBtn:hover {
    background-color: #c0392b; /* 붉은색 호버 */
    border-color: #e74c3c;
}
QTableWidget {
    background-color: #252526;
    border: 1px solid #3e3e3e;
    gridline-color: #3e3e3e;
    selection-background-color: #264f78;
    color: #cccccc;
}
QHeaderView::section {
    background-color: #333333;
    padding: 6px;
    border: 1px solid #3e3e3e;
    color: #e0e0e0;
    font-weight: bold;
}
QTextEdit {
    background-color: #1e1e1e;
    border: 1px solid #3e3e3e;
    color: #00ff00;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QProgressBar {
    border: 1px solid #3e3e3e;
    border-radius: 5px;
    text-align: center;
    background-color: #252526;
    color: white;
}
QProgressBar::chunk {
    background-color: #007acc;
    border-radius: 4px;
}
QSplitter::handle {
    background-color: #3e3e3e;
}
QLabel#Title {
    color: #ffffff;
    font-size: 22px;
    font-weight: bold;
    margin-bottom: 10px;
}
"""

# --- [백그라운드 워커 스레드] ---
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    finish_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    started_signal = pyqtSignal(int)
    asset_found_signal = pyqtSignal(str, str, str)

    def __init__(self, mode, target_input, user=None, pw=None, key_path=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user = user
        self.pw = pw
        self.stop_flag = False
        self.max_threads = 20  
        self.audit_threads = 5 
        self.db_queue = queue.Queue()
        self.writer_thread = None
        self.writer_stop = False
        self.asset_ids = {} 
        self.lock = threading.Lock() 

    def db_writer(self):
        db = DBConnector()
        while not self.writer_stop:
            try:
                item = self.db_queue.get(timeout=1)
                if item[0] == 'save_asset':
                    _, ip, hostname, os_type = item
                    asset_id = db.save_asset(ip, hostname=hostname, os_type=os_type)
                    with self.lock:
                        self.asset_ids[ip] = asset_id
                elif item[0] == 'save_open_port':
                    _, ip, port, banner = item
                    asset_id = None
                    with self.lock:
                        asset_id = self.asset_ids.get(ip)
                    if asset_id:
                        db.save_open_port(asset_id, port, banner)
            except queue.Empty:
                continue
            except Exception:
                pass

    def process_network_scan(self, ip):
        if self.stop_flag: return
        scanner = AdvancedScanner()
        try:
            is_alive, os_type = scanner.host_discovery(ip)
            if not is_alive: return

            self.db_queue.put(('save_asset', ip, "Scanned_Asset", os_type))
            open_ports = scanner.syn_scan(ip)
            port_str = "None"
            
            if open_ports:
                port_str = ", ".join(map(str, open_ports))
                self.log_signal.emit(f"[+] 발견: {ip} ({os_type}) | Ports: {port_str}")
                for port in open_ports:
                    banner = scanner.grab_banner(ip, port)
                    self.db_queue.put(('save_open_port', ip, port, banner))
            else:
                self.log_signal.emit(f"[+] 발견: {ip} ({os_type}) | Ports: None")

            self.asset_found_signal.emit(ip, os_type, port_str)

        except Exception as e:
            self.log_signal.emit(f"[!] {ip} 스캔 오류: {e}")

    def process_audit_scan(self, ip):
        """[수정됨] 시뮬레이션 모드도 Inspector를 통해 정식 진단 수행"""
        if self.stop_flag: return
        
        # IP 정리
        clean_ip = ip.strip().lower()
        
        # OS 판단 로직
        target_os = "Unknown"
        
        # 1. 시뮬레이션 IP인 경우 강제 할당
        if clean_ip in ["localhost", "127.0.0.1"]:
            target_os = "Linux"
        elif clean_ip in ["0.0.0.0", "127.0.0.2"]:
            target_os = "Windows"
        else:
            # 2. 실제 포트 스캔으로 판단
            def check_port(target_ip, port):
                try:
                    with socket.create_connection((target_ip, port), timeout=1): return True
                except: return False

            if check_port(ip, 5985): target_os = "Windows"
            elif check_port(ip, 22): target_os = "Linux"
            else:
                self.log_signal.emit(f"[-] {ip} 진단 불가 (Port 22/5985 닫힘)")
                return

        conn_success = False
        results = {}
        
        try:
            # Inspector 호출 (시뮬레이션 로직은 Inspector 내부로 위임)
            if target_os == "Windows":
                self.log_signal.emit(f"[*] {ip} -> WinRM 진단 시작...")
                inspector = WindowsInspector(ip, self.user, self.pw)
                if inspector.connect():
                    conn_success = True
                    results = inspector.run_all_checks()
                else:
                    self.log_signal.emit(f"[-] WinRM 접속 실패: {ip}")

            elif target_os == "Linux":
                self.log_signal.emit(f"[*] {ip} -> SSH 진단 시작...")
                inspector = SSHInspector(ip, username=self.user, password=self.pw)
                if inspector.connect():
                    conn_success = True
                    results = inspector.run_all_checks()
                    inspector.close()
                else:
                    self.log_signal.emit(f"[-] SSH 접속 실패: {ip}")

            # 결과 DB 저장 및 로그 출력
            if conn_success and results:
                db_local = DBConnector()
                asset_id = db_local.save_asset(ip, hostname="Audit_Target", os_type=target_os)
                
                vuln_count = 0
                safe_count = 0
                
                if asset_id:
                    for code, (status, detail) in results.items():
                        if db_local.save_scan_result(asset_id, code, status, detail):
                            if status in ["VULNERABLE", "취약", "Fail"]:
                                vuln_count += 1
                                self.log_signal.emit(f"    ❌ [{code}] 취약: {detail}")
                            else:
                                safe_count += 1
                                # 양호 항목은 너무 많으니 로그 생략하거나 필요 시 주석 해제
                                # self.log_signal.emit(f"    ✅ [{code}] 양호")
                
                self.log_signal.emit(f"    -> 진단 완료: 취약 {vuln_count}건 / 양호 {safe_count}건")

        except Exception as e:
            self.log_signal.emit(f"[Error] {ip} 진단 중 오류: {str(e)}")

    def run(self):
        self.log_signal.emit(f"[*] 엔진 가동 (Threads: {self.max_threads})")
        
        target_gen = None
        total_count = 0
        try:
            if "/" in self.target_input:
                network = ipaddress.ip_network(self.target_input, strict=False)
                total_count = network.num_addresses - 2 if network.prefixlen < 31 else 1
                target_gen = network.hosts()
            else:
                total_count = 1
                target_gen = [self.target_input]
        except ValueError:
            self.log_signal.emit("[Error] IP 형식이 올바르지 않습니다.")
            self.finish_signal.emit("입력 오류")
            return

        self.started_signal.emit(total_count)
        self.asset_ids = {}
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        processed_count = 0
        work_func = self.process_network_scan if self.mode == "NETWORK_SCAN" else self.process_audit_scan
        cur_threads = self.max_threads if self.mode == "NETWORK_SCAN" else self.audit_threads

        with ThreadPoolExecutor(max_workers=cur_threads) as executor:
            futures = {executor.submit(work_func, str(ip)): str(ip) for ip in target_gen}
            for future in as_completed(futures):
                if self.stop_flag:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                processed_count += 1
                if total_count > 0 and (processed_count % 5 == 0 or processed_count >= total_count):
                     self.progress_signal.emit(int((processed_count / total_count) * 100))

        if not self.stop_flag: self.progress_signal.emit(100)
        self.writer_stop = True
        self.writer_thread.join(timeout=3)
        self.finish_signal.emit("작업 완료")

# --- [메인 윈도우 UI] ---
class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Z-VulnScan v2.0 Enterprise')
        self.setGeometry(100, 100, 1100, 750)
        self.setWindowIcon(QIcon(resource_path('app_icon.ico')))
        
        # 다크 모드 스타일 적용
        self.setStyleSheet(STYLESHEET)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20) 
        main_layout.setSpacing(15) 

        # 1. 헤더 (타이틀 + 버전)
        header_layout = QHBoxLayout()
        title_label = QLabel("🛡️ Z-VulnScan Security Auditor")
        title_label.setObjectName("Title")
        ver_label = QLabel("v2.0.0")
        ver_label.setStyleSheet("color: #666; font-weight: bold; margin-top: 10px;")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(ver_label)
        main_layout.addLayout(header_layout)

        # 2. 입력 패널 (카드 UI)
        input_group = QGroupBox("Target Configuration")
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(20, 25, 20, 20)
        input_layout.setSpacing(15)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address or CIDR (e.g., 192.168.0.0/24)")
        self.ip_input.setMinimumWidth(250)
        
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("SSH User (root)")
        
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        
        input_layout.addWidget(QLabel("Target:"))
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(QLabel("User:"))
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(QLabel("PW:"))
        input_layout.addWidget(self.pw_input)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 3. 액션 버튼 그룹
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.btn_scan = QPushButton("🔍 Network Discovery")
        self.btn_scan.setToolTip("활성 자산을 식별하고 포트를 스캔합니다.")
        self.btn_scan.clicked.connect(self.start_network_scan)
        
        self.btn_audit = QPushButton("🛡️ Vulnerability Audit")
        self.btn_audit.setToolTip("식별된 자산에 대해 정밀 진단을 수행합니다.")
        self.btn_audit.setStyleSheet("QPushButton { border-color: #d73a49; } QPushButton:hover { border-color: #ff5555; background-color: #3e2020; }")
        self.btn_audit.clicked.connect(self.start_audit)
        
        self.btn_pdf = QPushButton("📄 Generate Report")
        self.btn_pdf.setToolTip("진단 결과를 PDF 리포트로 저장합니다.")
        self.btn_pdf.setStyleSheet("QPushButton { border-color: #28a745; } QPushButton:hover { border-color: #4cd964; background-color: #1e3a20; }")
        self.btn_pdf.clicked.connect(self.generate_pdf)
        
        self.btn_stop = QPushButton("🛑 Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)

        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        btn_layout.addStretch() 
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_stop)
        main_layout.addLayout(btn_layout)

        # 4. 메인 콘텐츠 (Splitter)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)
        
        # [LEFT] 자산 리스트
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 5, 0)
        
        # [NEW] 테이블 헤더 (라벨 + Clear 버튼)
        table_header_layout = QHBoxLayout()
        lbl_assets = QLabel("📋 Identified Assets")
        lbl_assets.setStyleSheet("font-weight: bold; color: #007acc;")
        
        self.btn_clear_assets = QPushButton("🗑️ Clear List")
        self.btn_clear_assets.setObjectName("ClearBtn") # 스타일 적용용 ID
        self.btn_clear_assets.setToolTip("목록을 비웁니다.")
        self.btn_clear_assets.clicked.connect(self.clear_asset_table)
        
        table_header_layout.addWidget(lbl_assets)
        table_header_layout.addStretch()
        table_header_layout.addWidget(self.btn_clear_assets)
        
        left_layout.addLayout(table_header_layout)
        
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(3)
        self.asset_table.setHorizontalHeaderLabels(["IP Address", "OS Type", "Open Ports"])
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.asset_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.asset_table.verticalHeader().setVisible(False) 
        self.asset_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.asset_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.asset_table.setShowGrid(False) 
        self.asset_table.setAlternatingRowColors(True) 
        self.asset_table.doubleClicked.connect(self.on_asset_double_click)
        
        left_layout.addWidget(self.asset_table)
        left_widget.setLayout(left_layout)
        
        # [RIGHT] 로그 콘솔
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(5, 0, 0, 0)
        
        # 로그 헤더
        log_header_layout = QHBoxLayout()
        lbl_logs = QLabel("💻 System Logs")
        lbl_logs.setStyleSheet("font-weight: bold; color: #28a745;")
        
        # 로그 클리어 버튼도 있으면 좋음
        self.btn_clear_logs = QPushButton("🗑️ Clear Logs")
        self.btn_clear_logs.setObjectName("ClearBtn")
        self.btn_clear_logs.clicked.connect(lambda: self.log_console.clear())

        log_header_layout.addWidget(lbl_logs)
        log_header_layout.addStretch()
        log_header_layout.addWidget(self.btn_clear_logs)

        right_layout.addLayout(log_header_layout)
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        right_layout.addWidget(self.log_console)
        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([450, 650])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        
        main_layout.addWidget(splitter)

        # 5. 하단 상태바
        status_container = QWidget()
        status_container.setStyleSheet("background-color: #252526; border-radius: 5px; padding: 5px;")
        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(10, 5, 10, 5)
        
        self.pbar = QProgressBar()
        self.pbar.setFixedHeight(15)
        self.pbar.setTextVisible(False)
        
        self.time_label = QLabel("Ready")
        self.time_label.setStyleSheet("color: #cccccc; font-size: 12px; font-weight: bold;")
        
        status_layout.addWidget(self.pbar)
        status_layout.addWidget(self.time_label)
        
        main_layout.addWidget(status_container)
        central_widget.setLayout(main_layout)
        
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_timer)
        self.elapsed_seconds = 0

    # --- 기능 로직 ---
    def add_asset_to_table(self, ip, os_type, ports):
        items = self.asset_table.findItems(ip, Qt.MatchExactly)
        row = -1
        if items:
            row = items[0].row()
        else:
            row = self.asset_table.rowCount()
            self.asset_table.insertRow(row)

        c_ip = QTableWidgetItem(ip)
        c_os = QTableWidgetItem(os_type)
        c_port = QTableWidgetItem(ports)
        
        c_ip.setForeground(QBrush(QColor("#ffffff")))
        c_port.setForeground(QBrush(QColor("#aaaaaa")))

        if os_type == "Linux":
            c_os.setForeground(QBrush(QColor("#ff9900"))) # 오렌지
        elif os_type == "Windows":
            c_os.setForeground(QBrush(QColor("#00bfff"))) # 딥스카이 블루
        else:
            c_os.setForeground(QBrush(QColor("#777777"))) # 회색

        self.asset_table.setItem(row, 0, c_ip)
        self.asset_table.setItem(row, 1, c_os)
        self.asset_table.setItem(row, 2, c_port)

    # [NEW] 테이블 비우기 함수
    def clear_asset_table(self):
        self.asset_table.setRowCount(0)
        self.log_message("[UI] Asset list cleared.")

    def on_asset_double_click(self):
        row = self.asset_table.currentRow()
        if row >= 0:
            ip = self.asset_table.item(row, 0).text()
            self.ip_input.setText(ip)
            self.log_message(f"[UI] Target Selected: {ip} -> Ready to Audit.")
            if ip in ["127.0.0.1", "localhost"]:
                self.user_input.setText("root")
                self.pw_input.setText("toor")
            elif ip == "0.0.0.0":
                self.user_input.setText("Administrator")
                self.pw_input.setText("password123")

    def update_timer(self):
        self.elapsed_seconds += 1
        mins, secs = divmod(self.elapsed_seconds, 60)
        self.time_label.setText(f"Elapsed: {mins:02d}:{secs:02d}")

    def update_progress(self, val):
        self.pbar.setValue(val)

    def log_message(self, msg):
        self.log_console.append(msg)

    def scan_finished(self, msg):
        self.timer.stop()
        self.pbar.setValue(100)
        QMessageBox.information(self, "Finished", msg)
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def start_network_scan(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Please input IP address.")
            return
        # 스캔 시작 시 자동 초기화 여부는 선택 사항 (여기서는 수동 Clear 버튼이 있으므로 유지)
        if "/" in ip: self.asset_table.setRowCount(0)
        self.prepare_scan()
        self.worker = ScanWorker("NETWORK_SCAN", ip)
        self.connect_worker()
        self.worker.start()

    def start_audit(self):
        ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        pw = self.pw_input.text().strip()
        if "/" in ip:
            QMessageBox.warning(self, "Notice", "Please select a single target for deep audit.")
        self.prepare_scan()
        self.worker = ScanWorker("AUDIT_VULN", ip, user, pw)
        self.connect_worker()
        self.worker.start()

    def generate_pdf(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            generator = PDFGenerator()
            generator.generate()
            QApplication.restoreOverrideCursor()
            self.log_message(f"[Success] Report Generated: {generator.filename}")
            QMessageBox.information(self, "Success", f"Report saved:\n{generator.filename}")
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Error", str(e))

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop_flag = True
            self.btn_stop.setEnabled(False)
            self.log_message("[!!!] Stopping...")

    def prepare_scan(self):
        # self.log_console.clear() # 로그는 남겨두는 게 좋을 수 있음 (수동 Clear 사용)
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        self.elapsed_seconds = 0
        self.timer.start()

    def connect_worker(self):
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.started_signal.connect(lambda n: self.log_message(f"[Info] Target Count: {n}"))
        self.worker.asset_found_signal.connect(self.add_asset_to_table)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop_flag = True
            self.worker.wait(2000)
        event.accept()

if __name__ == '__main__':
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())