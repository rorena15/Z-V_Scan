# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys
import os

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
    QHeaderView, QProgressBar, QComboBox, QMessageBox, QGroupBox,
    QSplitter, QTextEdit, QMenu, QInputDialog
)
from PySide6.QtCore import Qt, QTimer
# [Fix] QTextCursor 추가 임포트 (로그 창 스크롤 에러 해결)
from PySide6.QtGui import QIcon, QColor, QBrush, QAction, QTextCursor

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

def resource_path(relative_path): 
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# 엔진 모듈 연동
from core.worker import ScanWorker              
from core.advanced_scanner import AdvancedScanner
from output.pdf_report import PDFGenerator
from output.excel_report import ExcelGenerator
from utils.os_utils import OSUtils
from utils.secure_storage import SecureStorage
from utils.db_connector import DBConnector
from gui.styles import STYLESHEET
from utils.network_visualizer import NetworkVisualizer

class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = DBConnector()
        self.worker = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        self.elapsed_seconds = 0
        
        # 스캔 결과 임시 저장소 (UI 렉 방지용 버퍼)
        self.scan_result_buffer = []
        
        self.initUI()
        self.refresh_dashboard()

    # -- UI 세팅 --
    def initUI(self):
        self.setWindowTitle('Z-VulnScan v3.0.0 Professional Edition')
        self.setGeometry(100, 100, 1100, 750)
        self.setWindowIcon(QIcon(resource_path('app_icon.ico')))
        self.setStyleSheet(STYLESHEET)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 1. 헤더
        header_layout = QHBoxLayout()
        title_label = QLabel("🛡️ Z-VulnScan V3.0.0 Professional Edition")
        title_label.setStyleSheet("color: #ffffff; font-size: 16pt; font-weight: bold;")
        
        self.lbl_stats_assets = QLabel("Assets: 0")
        self.lbl_stats_assets.setStyleSheet("color: #00b0ff; font-weight: bold; margin-left: 20px; font-size: 11pt;")
        self.lbl_stats_vulns = QLabel("Issues: 0")
        self.lbl_stats_vulns.setStyleSheet("color: #ff5555; font-weight: bold; margin-left: 10px; font-size: 11pt;")
        ver_label = QLabel("v3.0.0")
        ver_label.setStyleSheet("color: #666; font-weight: bold;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(self.lbl_stats_assets)
        header_layout.addWidget(self.lbl_stats_vulns)
        header_layout.addStretch()
        header_layout.addWidget(ver_label)
        main_layout.addLayout(header_layout)

        # 2. 타겟 & 포트 설정
        input_group = QGroupBox("Configuration")
        input_layout = QVBoxLayout()
        
        # Row 1: Target & Creds
        row1 = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address or CIDR (e.g., 192.168.0.0/24)")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("SSH/WinRM User")
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        
        row1.addWidget(QLabel("Target:"))
        row1.addWidget(self.ip_input)
        row1.addWidget(QLabel("User:"))
        row1.addWidget(self.user_input)
        row1.addWidget(QLabel("PW:"))
        row1.addWidget(self.pw_input)
        
        # Row 2: Port Settings
        row2 = QHBoxLayout()
        self.port_mode_combo = QComboBox()
        self.port_mode_combo.addItems(["⚡ Default (Fast)", "📝 Custom Range", "🐢 Full Scan (1-65535)"])
        self.port_mode_combo.currentIndexChanged.connect(self.toggle_port_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Ex: 80,443,8080 or 1-1024")
        self.port_input.setEnabled(False)
        
        row2.addWidget(QLabel("Scan Mode:"))
        row2.addWidget(self.port_mode_combo)
        row2.addWidget(QLabel("Custom Ports:"))
        row2.addWidget(self.port_input)
        
        input_layout.addLayout(row1)
        input_layout.addLayout(row2)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 3. 버튼 그룹
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.btn_scan = QPushButton("🔍 Network Discovery")
        self.btn_scan.setToolTip("활성 자산 식별 및 포트 스캔")
        self.btn_scan.clicked.connect(self.start_network_scan)
        
        self.btn_audit = QPushButton("🛡️ Vulnerability Audit")
        self.btn_audit.setToolTip("정밀 진단 수행 (시뮬레이션 포함)")
        self.btn_audit.setStyleSheet(
            "QPushButton { border-color: #d73a49; } "
            "QPushButton:hover { border-color: #ff5555; background-color: #3e2020; }"
        )
        self.btn_audit.clicked.connect(self.start_audit)
        
        self.btn_pdf = QPushButton("📄 PDF Report")
        self.btn_pdf.setToolTip("Pro: PDF 리포트 생성")
        self.btn_pdf.setStyleSheet(
            "QPushButton { border-color: #28a745; } "
            "QPushButton:hover { border-color: #4cd964; background-color: #1e3a20; }"
        )
        self.btn_pdf.clicked.connect(self.generate_pdf)
        
        self.btn_excel = QPushButton("📊 Excel Export")
        self.btn_excel.setToolTip("Pro: 상세 진단 결과 엑셀 저장")
        self.btn_excel.setStyleSheet(
            "QPushButton { border-color: #1e7145; color: #ffffff; }"
            "QPushButton:hover { border-color: #2e8b57; background-color: #1e3a20; }"
        )
        self.btn_excel.clicked.connect(self.generate_excel)
        
        self.btn_map = QPushButton("🗺️ Topology Map")
        self.btn_map.clicked.connect(self.show_topology)
        self.btn_map.setStyleSheet(
            "QPushButton { border-color: #1e7145; color: #ffffff; }"
            "QPushButton:hover { border-color: #2e8b57; background-color: #1e3a20; }"
            )
        
        self.btn_stop = QPushButton("🛑 Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        
        self.btn_db_manager = QPushButton("DB Manager")
        self.btn_db_manager.clicked.connect(self.open_db_manager)

        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_excel)
        btn_layout.addWidget(self.btn_map)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_db_manager)
        main_layout.addLayout(btn_layout)

        # 4. 콘텐츠 (Splitter)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)
        
        # [LEFT] 자산 리스트
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 5, 0)
        
        header_h = QHBoxLayout()
        lbl_assets = QLabel("📋 Identified Assets")
        lbl_assets.setStyleSheet("font-weight: bold; color: #007acc;")
        
        self.btn_clear_assets = QPushButton("🗑️ Clear List")
        self.btn_clear_assets.setObjectName("ClearBtn")
        self.btn_clear_assets.clicked.connect(self.clear_asset_table)
        
        header_h.addWidget(lbl_assets)
        header_h.addStretch()
        header_h.addWidget(self.btn_clear_assets)
        left_layout.addLayout(header_h)
        
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(4)
        self.asset_table.setHorizontalHeaderLabels(["IP Address", "OS Type", "Open Ports", "Memo / Tag"])
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.asset_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.asset_table.verticalHeader().setVisible(False)
        self.asset_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.asset_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.asset_table.setShowGrid(False)
        self.asset_table.setAlternatingRowColors(True)
        self.asset_table.doubleClicked.connect(self.on_asset_double_click)
        self.asset_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.asset_table.customContextMenuRequested.connect(self.show_context_menu)
        
        left_layout.addWidget(self.asset_table)
        left_widget.setLayout(left_layout)
        
        # [RIGHT] 로그 콘솔
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(5, 0, 0, 0)
        
        log_h = QHBoxLayout()
        lbl_logs = QLabel("💻 System Logs")
        lbl_logs.setStyleSheet("font-weight: bold; color: #28a745;")
        
        self.btn_clear_logs = QPushButton("🗑️ Clear Logs")
        self.btn_clear_logs.setObjectName("ClearBtn")
        self.btn_clear_logs.clicked.connect(self.clear_logs)
        
        log_h.addWidget(lbl_logs)
        log_h.addStretch()
        log_h.addWidget(self.btn_clear_logs)
        right_layout.addLayout(log_h)
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        # [Style] 로그 콘솔 스타일 (해커 테마)
        self.log_console.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 10pt;
                border: 1px solid #333;
            }
        """)
        right_layout.addWidget(self.log_console)
        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([450, 650])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        main_layout.addWidget(splitter)

        # 5. 상태바
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
        self.load_saved_assets()

    # --- 기능 메서드 ---
    
    # [Unified] 자산 추가 함수 통합 (중복 제거 및 기능 합침)
    def add_asset_to_table(self, ip, os_type, ports, memo_text=None):
        """테이블에 자산을 추가합니다. (DB 로드 / 스캔 결과 공용)"""
        
        # 1. 중복 검사 (Cache 확인 -> 빠름)
        if not hasattr(self, 'scanned_ip_cache'):
            self.scanned_ip_cache = set()
            
        # 이미 캐시에 있으면 건너뛰거나(스캔중), 업데이트를 위해 행을 찾음
        items = self.asset_table.findItems(ip, Qt.MatchExactly)
        row = -1
        
        if items:
            row = items[0].row() # 이미 존재하면 업데이트
        else:
            row = self.asset_table.rowCount()
            self.asset_table.insertRow(row) # 없으면 추가
            self.scanned_ip_cache.add(ip)

        # 2. 메모 데이터 처리
        # 스캔 결과(None)라면 DB에서 조회, 히스토리 로드라면 전달된 값 사용
        if memo_text is None:
            # 실시간 스캔 시 DB 조회를 하면 느려질 수 있으니,
            # 여기서는 빈 칸으로 두고 나중에 필요하면 로드하는 게 좋습니다.
            # 하지만 사용자 편의를 위해 DB에 메모가 있다면 가져옵니다.
            db = DBConnector()
            memo_text = db.get_memo(ip)

        # 3. 아이템 생성 및 스타일링
        c_ip = QTableWidgetItem(ip)
        c_os = QTableWidgetItem(os_type)
        c_port = QTableWidgetItem(ports)
        c_memo = QTableWidgetItem(memo_text if memo_text else "")
        
        # 색상 설정 (다크 테마 최적화)
        c_ip.setForeground(QBrush(QColor("#ffffff")))
        c_port.setForeground(QBrush(QColor("#aaaaaa")))
        c_memo.setForeground(QBrush(QColor("#00ff00"))) # 메모 강조
        
        if "Linux" in os_type:
            c_os.setForeground(QBrush(QColor("#ff9900"))) # 오렌지
        elif "Windows" in os_type:
            c_os.setForeground(QBrush(QColor("#00bfff"))) # 하늘색
        else:
            c_os.setForeground(QBrush(QColor("#777777"))) # 회색

        self.asset_table.setItem(row, 0, c_ip)
        self.asset_table.setItem(row, 1, c_os)
        self.asset_table.setItem(row, 2, c_port)
        self.asset_table.setItem(row, 3, c_memo)

    def clear_asset_table(self):
        if self.asset_table.rowCount() == 0:
            return

        reply = QMessageBox.question(
            self, "Confirm Delete", 
            "⚠️ 모든 자산 데이터와 메모가 삭제됩니다.\n초기화하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No 
        )

        if reply == QMessageBox.Yes:
            db = DBConnector()
            if db.delete_all_assets():
                self.asset_table.setRowCount(0)
                if hasattr(self, 'scanned_ip_cache'):
                    self.scanned_ip_cache.clear()
                self.log_message("[System] 🗑️ All assets cleared.")
                QMessageBox.information(self, "Cleared", "초기화되었습니다.")

    def clear_logs(self):
        self.log_console.clear()
        self.log_message("[UI] Log console cleared.")

    def on_asset_double_click(self):
        row = self.asset_table.currentRow()
        if row >= 0:
            ip = self.asset_table.item(row, 0).text()
            self.ip_input.setText(ip)
            self.log_message(f"[UI] Target Selected: {ip}")
            
            if ip in ["127.0.0.1", "localhost"]:
                self.user_input.setText("root")
                self.pw_input.setText("toor")
            elif ip == "0.0.0.0":
                self.user_input.setText("Administrator")
                self.pw_input.setText("password123")

    def update_timer(self):
        self.elapsed_seconds += 1
        
        def format_time(seconds):
            m, s = divmod(seconds, 60)
            h, m = divmod(m, 60)
            if h > 0: return f"{h:02d}:{m:02d}:{s:02d}"
            return f"{m:02d}:{s:02d}"

        elapsed_str = format_time(self.elapsed_seconds)
        eta_str = "Calculating..."

        if hasattr(self, 'current_scan_count') and self.current_scan_count > 0:
            avg_time = self.elapsed_seconds / self.current_scan_count
            remain_cnt = self.total_scan_count - self.current_scan_count
            if remain_cnt < 0: remain_cnt = 0
            
            rem_sec = int(avg_time * remain_cnt)
            if rem_sec > 86400: eta_str = "> 24h"
            else: eta_str = format_time(rem_sec)
        
        elif self.pbar.value() >= 100:
            eta_str = "Done"

        self.time_label.setText(f"Elapsed: {elapsed_str} | ETA: {eta_str}")

    def update_progress(self, percent, count):
        self.pbar.setValue(percent)
        self.current_scan_count = count

    def log_message(self, msg):
        """[Fix] 로그 창 크래시 해결 및 최적화"""
        # 1. 텍스트 추가
        self.log_console.append(msg)
        
        # 2. 줄 수 제한 (1000줄)
        doc = self.log_console.document()
        if doc.blockCount() > 1000:
            cursor = self.log_console.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 100)
            cursor.removeSelectedText()
            
        # 3. [Fix] 올바른 MoveOperation 상수 사용
        self.log_console.moveCursor(QTextCursor.MoveOperation.End)
        self.log_console.ensureCursorVisible()

    def set_ui_busy(self, busy):
        # [Optimized] UI 상태 제어
        self.btn_scan.setDisabled(busy)
        self.btn_audit.setDisabled(busy)
        self.btn_stop.setEnabled(busy)
        self.btn_pdf.setDisabled(busy)
        self.btn_excel.setDisabled(busy)
        self.btn_map.setDisabled(busy)

        self.ip_input.setDisabled(busy)
        self.port_mode_combo.setDisabled(busy)
        self.user_input.setDisabled(busy)
        self.pw_input.setDisabled(busy)

        if busy:
            self.port_input.setDisabled(True)
            
            # [핵심] 스캔 결과 버퍼 초기화 (여기서 초기화해야 함)
            self.scan_result_buffer = []
            # 캐시 초기화
            if hasattr(self, 'scanned_ip_cache'):
                self.scanned_ip_cache.clear()
            else:
                self.scanned_ip_cache = set()
            
            self.pbar.setValue(0)
            self.elapsed_seconds = 0
            self.time_label.setText("Initializing...")
        else:
            is_custom = (self.port_mode_combo.currentIndex() == 1)
            self.port_input.setEnabled(is_custom)
            
            self.timer.stop()
            self.pbar.setValue(100)

    def update_asset_table(self, ip, os_type, open_ports):
        """[Optimized] 실시간 테이블 렌더링 대신 버퍼에 저장"""
        # 로그는 이미 실시간으로 뜨므로, 테이블 데이터는 모아둡니다.
        self.scan_result_buffer.append((ip, os_type, open_ports))

    def scan_finished(self, msg):
        self.timer.stop()
        self.pbar.setValue(100)
        self.set_ui_busy(False)
        
        # [Batch Update] 모아둔 결과를 한 번에 테이블에 등록
        if self.scan_result_buffer:
            self.log_message(f"[System] Registering {len(self.scan_result_buffer)} assets to table...")
            
            self.asset_table.setSortingEnabled(False) # 속도 향상
            
            for data in self.scan_result_buffer:
                ip, os, ports = data
                self.add_asset_to_table(ip, os, ports)
                
            self.asset_table.setSortingEnabled(True) # 정렬 복구
            self.log_message("[System] Table update completed.")
        
        QMessageBox.information(self, "Finished", f"{msg}\n(Total Found: {len(self.scan_result_buffer)})")
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        self.log_message(f"[System] Scan Finished. (Total: {self.elapsed_seconds}s)")
        
        # 보안 조치
        target_ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        SecureStorage.delete_credential(target_ip, user)

    def start_network_scan(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Target IP를 입력해주세요.")
            self.ip_input.setFocus()
            return

        mode_idx = self.port_mode_combo.currentIndex()
        target_ports = None 

        if mode_idx == 1: 
            p_str = self.port_input.text().strip()
            if not p_str:
                QMessageBox.warning(self, "Input Error", "Custom 포트를 입력해주세요.")
                return
            target_ports = AdvancedScanner.parse_ports(p_str)
            if not target_ports:
                QMessageBox.warning(self, "Error", "포트 형식이 올바르지 않습니다.")
                return
        elif mode_idx == 2: 
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("⚠️ Full Scan Warning")
            msg.setText("<b>전체 포트(1-65535) 스캔을 시작하시겠습니까?</b>")
            msg.setInformativeText("시간이 매우 오래 걸리며 네트워크 부하가 발생할 수 있습니다.")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.No)
            if msg.exec() == QMessageBox.No: return
            target_ports = list(range(1, 65536))
        self.asset_table.setRowCount(0)
        
        # 중복 방지 캐시 초기화
        if hasattr(self, 'scanned_ip_cache'):
            self.scanned_ip_cache.clear()
        else:
            self.scanned_ip_cache = set()

        self.set_ui_busy(True)
        self.worker = ScanWorker("NETWORK_SCAN", ip, ports=target_ports)
        self.connect_worker()
        self.worker.start()

    def start_audit(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Target IP를 입력해주세요.")
            return
        if "/" in ip:
            QMessageBox.warning(self, "Notice", "Audit은 단일 IP만 지원합니다.")
            return

        is_sim = ip in ["127.0.0.1", "localhost", "0.0.0.0"]
        user = self.user_input.text().strip()
        pw = self.pw_input.text().strip()
        
        if not is_sim and (not user or not pw):
            QMessageBox.warning(self, "Auth Error", "SSH/WinRM 계정 정보가 필요합니다.")
            return
        
        if not is_sim:
            if not SecureStorage.save_credential(ip, user, pw):
                QMessageBox.critical(self, "Error", "자격증명 저장 실패")
                return

        self.set_ui_busy(True)
        self.worker = ScanWorker("AUDIT_VULN", ip, user)
        self.connect_worker()
        self.worker.start()

    def generate_pdf(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            generator = PDFGenerator()
            filepath = generator.generate()
            QApplication.restoreOverrideCursor()
            self.log_message(f"[Success] PDF Saved: {filepath}")
            if QMessageBox.question(self, "Success", "PDF를 여시겠습니까?", QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:
                self.open_file_platform_safe(filepath)
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Error", str(e))

    def generate_excel(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            generator = ExcelGenerator()
            filepath = generator.generate()
            QApplication.restoreOverrideCursor()
            self.log_message(f"[Success] Excel Saved: {filepath}")
            if QMessageBox.question(self, "Success", "Excel을 여시겠습니까?", QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:
                self.open_file_platform_safe(filepath)
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Error", str(e))

    def show_topology(self):
        # 1. 자산 데이터 가져오기
        assets = self.db.get_all_assets()
        if not assets:
            QMessageBox.warning(self, "No Data", "표시할 자산 데이터가 없습니다.\n스캔을 먼저 수행해주세요.")
            return
        # 2. 로딩 표시 (선택사항)
        self.statusBar().showMessage("Generating Topology Map...")
        try:
            viz = NetworkVisualizer()
            # HTML 파일 생성
            html_path = viz.create_topology(assets)
            
            if html_path and os.path.exists(html_path):
                # 4. 다이얼로그 띄우기
                from gui.topology_dialog import TopologyDialog
                dlg = TopologyDialog(html_path, self)
                dlg.exec()
                self.statusBar().showMessage("Topology Map Closed.", 3000)
            else:
                QMessageBox.critical(self, "Error", "토폴로지 맵 생성에 실패했습니다.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")
            self.statusBar().showMessage("Error generating map.")

    def open_file_platform_safe(self, filepath):
        if not OSUtils.open_file(filepath):
            QMessageBox.warning(self, "Error", f"파일을 열 수 없습니다:\n{filepath}")

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop_flag = True
            self.btn_stop.setEnabled(False)
            self.log_message("[!!!] Stopping Scan...")

    def connect_worker(self):
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.started_signal.connect(self.on_scan_started)
        # [Optimized] 스캔 결과를 버퍼에 담는 함수 연결
        self.worker.asset_found_signal.connect(self.update_asset_table)

    def on_scan_started(self, count):
        self.log_message(f"[Info] Scanning Start. Targets: {count}")
        self.total_scan_count = count
        self.current_scan_count = 0
        self.timer.start(1000)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop_flag = True
            self.worker.wait(2000)
        event.accept()

    def toggle_port_input(self, index):
        is_custom = (index == 1)
        self.port_input.setEnabled(is_custom)
        if is_custom: self.port_input.setFocus()

        if index == 2:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Full Scan Warning")
            msg.setText("<b>Full Port Scan (1-65535)</b>")
            msg.setInformativeText("매우 오래 걸릴 수 있습니다. 계속하시겠습니까?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.No)
            if msg.exec() == QMessageBox.No:
                self.port_mode_combo.blockSignals(True)
                self.port_mode_combo.setCurrentIndex(0)
                self.port_mode_combo.blockSignals(False)

    def load_saved_assets(self):
        # History 로드 시에는 Buffer가 아닌 즉시 등록 사용 (DB 내용이니까)
        db = DBConnector()
        assets = db.get_all_assets()
        
        self.asset_table.setRowCount(0)
        self.scanned_ip_cache = set() # 캐시 초기화
        
        for ip, os_type, memo, mac_addr in assets:
            display_os = os_type
            if mac_addr: display_os = f"{os_type} | {mac_addr}"
            self.add_asset_to_table(ip, display_os, "Scanned History", memo_text=memo)
            
        if assets:
            self.log_message(f"[System] Loaded {len(assets)} assets from history.")

    def edit_asset_memo(self):
        row = self.asset_table.currentRow()
        if row < 0: return
        
        ip = self.asset_table.item(row, 0).text()
        current_memo = self.asset_table.item(row, 3).text()
        
        text, ok = QInputDialog.getText(self, "Asset Memo", f"Edit Memo for {ip}:", QLineEdit.Normal, current_memo)
        if ok:
            db = DBConnector()
            if db.update_memo(ip, text):
                self.asset_table.item(row, 3).setText(text)
                self.log_message(f"[Asset] Memo updated for {ip}")

    def show_context_menu(self, pos):
        if not self.asset_table.selectionModel().selection().indexes(): return
        
        row = self.asset_table.currentRow()
        ip = self.asset_table.item(row, 0).text()
        os_type = self.asset_table.item(row, 1).text()
        
        menu = QMenu()
        menu.addAction("📝 Edit Memo / Tag", self.edit_asset_memo)
        menu.addSeparator()
        menu.addAction(f"📡 Ping Check ({ip})", lambda: OSUtils.open_ping_test(ip))
        menu.addSeparator()
        
        if "Windows" in os_type:
            menu.addAction("🖥️ RDP Connect", lambda: OSUtils.open_rdp(ip))
        elif "Linux" in os_type:
            user = self.user_input.text().strip() or "root"
            menu.addAction("🐧 SSH Connect", lambda: OSUtils.open_ssh(ip, user))
            
        menu.addAction("📄 Copy IP", lambda: QApplication.clipboard().setText(ip))
        menu.exec(self.asset_table.viewport().mapToGlobal(pos))
        
    def open_db_manager(self):
        from gui.db_manager import DatabaseManagerDialog
        
        # DB 커넥터 인스턴스를 넘겨줍니다
        dlg = DatabaseManagerDialog(self.db, self)
        dlg.exec()
        
        # 매니저 창이 닫히면 메인 화면의 통계나 리스트도 갱신하는 것이 좋음
        self.refresh_dashboard() # (만약 이런 기능이 있다면)
        
    def refresh_dashboard(self):
        #DB에서 최신 데이터를 읽어와 테이블과 통계를 갱신합니다.
        # 1. 통계 데이터 갱신
        stats = self.db.get_dashboard_stats()
        if hasattr(self, 'lbl_stats_assets'):
            self.lbl_stats_assets.setText(f"Assets: {stats['total_assets']}")
        if hasattr(self, 'lbl_stats_vulns'):
            self.lbl_stats_vulns.setText(f"Issues: {stats['vuln_critical']}")
            
        # 2. 자산 리스트 갱신
        # 기존 테이블 초기화
        self.asset_table.setRowCount(0)
        self.scanned_ip_cache = set() # 캐시 초기화
        
        # DB에서 전체 자산 가져오기
        assets = self.db.get_all_assets() # [(ip, os, memo, mac), ...]
        
        self.asset_table.setSortingEnabled(False) # 렌더링 속도 향상
        
        for ip, os_type, memo, mac_addr in assets:
            # OS 표기 처리 (MAC 주소 있으면 병기)
            display_os = os_type
            if mac_addr: 
                display_os = f"{os_type} | {mac_addr}"
            
            # 기존에 만드신 add_asset_to_table 재활용
            self.add_asset_to_table(ip, display_os, "History", memo_text=memo)
            
        self.asset_table.setSortingEnabled(True)
        
        self.log_message(f"[System] Dashboard Refreshed. (Assets: {stats['total_assets']})")