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
    QHeaderView, QProgressBar, QComboBox, QMessageBox, 
    QSplitter, QTextEdit, QMenu, QInputDialog, QFileDialog,
    QGroupBox,
    QToolBar,
    QTabWidget,
    QAbstractItemView
)

# [PySide6 핵심 기능]
from PySide6.QtCore import Qt, QTimer, QUrl

# [PySide6 그래픽 및 액션]
from PySide6.QtGui import QIcon, QColor, QBrush, QAction, QTextCursor, QDesktopServices

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
from utils.auth_token import get_engine_token

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
        self.setWindowTitle('Z-Vuln Scan v3.0.0 Professional Edition')
        self.resize(1200, 850)
        self.setWindowIcon(QIcon(resource_path('app_icon.ico')))
        
        # [테마] 전체 스타일시트 (Deep Dark 모드 + 가독성 개선)
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; }
            QWidget { color: #d4d4d4; font-size: 10pt; font-family: 'Segoe UI', sans-serif; }
            QToolTip { color: #ffffff; background-color: #2b2b2b; border: 1px solid #767676; }
            
            /* [공통] 입력창 스타일 */
            QLineEdit {
                background-color: #2d2d30;
                color: #ffffff;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 6px;
            }
            QLineEdit:focus { border: 1px solid #555555; background-color: #1e1e1e; }
            QLineEdit:disabled { background-color: #333333; color: #888888; }
            
            /* [공통] 콤보박스 스타일 (투명화 해결 포함) */
            QComboBox {
                background-color: #2d2d30;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 5px;
                color: #ffffff;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; border-left: 2px solid #555; width: 0; height: 0; }
            QComboBox QAbstractItemView {
                background-color: #2d2d30;
                color: #ffffff;
                border: 1px solid #3e3e42;
                selection-background-color: #3e3e42;
                selection-color: #ffffff;
            }

            /* 알림창(QMessageBox) & 입력창(QInputDialog) 테마 적용 */
            QMessageBox, QInputDialog {
                background-color: #252526;
                color: #d4d4d4;
            }
            QMessageBox QLabel, QInputDialog QLabel {
                color: #d4d4d4;
                font-weight: normal;
            }
            /* 다이얼로그 내부 버튼 스타일 */
            QMessageBox QPushButton, QInputDialog QPushButton {
                background-color: #3e3e42;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 6px 20px;
                min-width: 60px;
            }
            QMessageBox QPushButton:hover, QInputDialog QPushButton:hover {
                background-color: #4e4e52;
                border-color: #777;
            }
            QMessageBox QPushButton:pressed, QInputDialog QPushButton:pressed {
                background-color: #2d2d30;
            }
        """)

        # [1. 상단 툴바]
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setStyleSheet("""
            QToolBar { background: #252526; border-bottom: 1px solid #333; spacing: 10px; padding: 5px; }
            QToolButton { color: #cccccc; background: transparent; padding: 6px; border-radius: 4px; font-weight: bold; }
            QToolButton:hover { background: #3e3e42; color: white; }
        """)

        # 툴바 액션
        self.action_db = QAction("📂 DB Manager", self)
        self.action_db.triggered.connect(self.open_db_manager)
        toolbar.addAction(self.action_db)
        
        toolbar.addSeparator()
        
        self.action_map = QAction("🗺️ Topology", self)
        self.action_map.triggered.connect(self.show_topology)
        toolbar.addAction(self.action_map)
        
        toolbar.addSeparator()

        self.action_pdf = QAction("📄 PDF", self)
        self.action_pdf.triggered.connect(self.generate_pdf)
        toolbar.addAction(self.action_pdf)
        
        self.action_xls = QAction("📊 Excel", self)
        self.action_xls.triggered.connect(self.generate_excel)
        toolbar.addAction(self.action_xls)

        # --- 메인 컨텐츠 ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # [2. 헤더 영역]
        header_layout = QHBoxLayout()
        
        # 타이틀
        title_widget = QWidget()
        title_widget.setStyleSheet("background-color: #1e1e1e; border-radius: 6px;")
        title_layout = QHBoxLayout(title_widget)
        title_layout.setContentsMargins(15, 8, 15, 8)
        
        title_label = QLabel("🛡️ Z-Vuln Scan Professional")
        title_label.setStyleSheet("color: #e0e0e0; font-size: 14pt; font-weight: bold; border: none;")
        ver_label = QLabel("v3.0.0")
        ver_label.setStyleSheet("color: #666; font-weight: bold; border: none; margin-left: 5px; margin-top: 5px;")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(ver_label)
        header_layout.addWidget(title_widget)
        
        header_layout.addStretch()
        
        # 통계 컨테이너
        stats_container = QWidget()
        stats_container.setStyleSheet("background-color: #1e1e1e; border-radius: 6px; ali")
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setContentsMargins(15, 8, 15, 8)
        
        self.lbl_stats_assets = QLabel("Assets: 0")
        self.lbl_stats_assets.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11pt; border: none;")
        
        self.lbl_stats_vulns = QLabel("Issues: 0")
        self.lbl_stats_vulns.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 11pt; border: none; margin-left: 15px;")
        
        stats_layout.addWidget(self.lbl_stats_assets)
        stats_layout.addWidget(self.lbl_stats_vulns)
        
        header_layout.addWidget(stats_container)
        main_layout.addLayout(header_layout)

        # [3. 설정 영역] (탭 제거 -> 통합 뷰)
        # 깔끔한 그룹박스로 감싸서 시각적 분리
        config_group = QGroupBox("Scan Configuration")
        config_group.setStyleSheet("""
            QGroupBox { 
                border: 1px solid #333; 
                border-radius: 6px; 
                margin-top: 10px; 
                background-color: #252526; 
                color: #ddd; 
                font-weight: bold;
                padding-top: 15px;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }
        """)
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(15, 15, 15, 15)
        config_layout.setSpacing(15)

        # Row 1: Target & Mode (가장 중요한 정보)
        row1_layout = QHBoxLayout()
        
        lbl_target = QLabel("Target:")
        lbl_target.setStyleSheet("color: #ccc; font-weight: bold;")
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Target IP Address (e.g., 192.168.1.1 or 192.168.1.0/24)")
        self.ip_input.setStyleSheet("font-size: 11pt; padding: 8px;") # 중요하니까 조금 크게
        
        lbl_mode = QLabel("Mode:")
        lbl_mode.setStyleSheet("color: #ccc; font-weight: bold;")
        
        self.port_mode_combo = QComboBox()
        self.port_mode_combo.addItems(["⚡ Fast Scan (Major)", "📝 Custom Range", "🐢 Full Scan(1~ 65535)"])
        self.port_mode_combo.setStyleSheet("padding: 8px;")
        self.port_mode_combo.currentIndexChanged.connect(self.toggle_port_input)

        row1_layout.addWidget(lbl_target)
        row1_layout.addWidget(self.ip_input, 3) # 비율 3
        row1_layout.addSpacing(15)
        row1_layout.addWidget(lbl_mode)
        row1_layout.addWidget(self.port_mode_combo, 1) # 비율 1
        
        config_layout.addLayout(row1_layout)

        # Row 2: Auth & Advanced (한 줄에 정렬)
        row2_layout = QHBoxLayout()
        
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("SSH/WinRM User")
        
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Custom Ports (80, 443...)")
        self.port_input.setEnabled(False) # 모드 선택 시 활성화

        # 라벨 없이 Placeholder로 깔끔하게 처리하거나, 아이콘 사용 가능
        # 여기선 공간 절약을 위해 라벨 최소화
        row2_layout.addWidget(QLabel("User:"))
        row2_layout.addWidget(self.user_input, 2)
        row2_layout.addSpacing(10)
        row2_layout.addWidget(QLabel("Pass:"))
        row2_layout.addWidget(self.pw_input, 2)
        row2_layout.addSpacing(10)
        row2_layout.addWidget(QLabel("Ports:"))
        row2_layout.addWidget(self.port_input, 2)
        
        config_layout.addLayout(row2_layout)
        
        main_layout.addWidget(config_group)

        # [4. 액션 버튼]
        action_layout = QHBoxLayout()
        action_layout.setSpacing(15)
        
        btn_scan_style = """
            QPushButton { background-color: #383838; color: white; font-weight: bold; font-size: 11pt; padding: 12px; border: 1px solid #555; border-radius: 4px; }
            QPushButton:hover { background-color: #4d4d4d; border-color: #777; }
            QPushButton:pressed { background-color: #2b2b2b; }
        """
        btn_audit_style = """
            QPushButton { background-color: #7b1fa2; color: white; font-weight: bold; font-size: 11pt; padding: 12px; border: 1px solid #6a1b9a; border-radius: 4px; }
            QPushButton:hover { background-color: #9c27b0; }
        """
        
        self.btn_scan = QPushButton("🚀 Network Discovery Scan")
        self.btn_scan.setToolTip("네트워크 스캔 수행")
        self.btn_scan.setStyleSheet(btn_scan_style)
        self.btn_scan.clicked.connect(self.start_network_scan)
        
        self.btn_audit = QPushButton("🛡️ Vulnerability Audit")
        self.btn_audit.setToolTip("취약점 진단 수행")
        self.btn_audit.setStyleSheet(btn_audit_style)
        self.btn_audit.clicked.connect(self.start_audit)
        
        self.btn_stop = QPushButton("🛑 STOP")
        self.btn_stop.setFixedWidth(100)
        self.btn_stop.setStyleSheet("""
            QPushButton { background-color: #1e1e1e; color: #ff5555; border: 1px solid #555; padding: 12px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #2d2d30; border-color: #ff5555; }
            QPushButton:disabled { color: #555; border-color: #333; }
        """)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)

        action_layout.addWidget(self.btn_scan, 4)
        action_layout.addWidget(self.btn_audit, 4)
        action_layout.addWidget(self.btn_stop, 1)
        
        main_layout.addLayout(action_layout)

        # [5. 결과 뷰]
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("QSplitter::handle { background-color: #333; }")
        
        # [LEFT] 자산 리스트
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        list_header = QHBoxLayout()
        lbl_list = QLabel("📋 Asset List")
        lbl_list.setStyleSheet("font-weight: bold; color: #ddd; font-size: 10pt;")
        
        self.btn_clear_assets = QPushButton("Clear List")
        self.btn_clear_assets.setFixedSize(90, 30)
        self.btn_clear_assets.setStyleSheet("""
            QPushButton { background: #2d2d30; color: #aaa; border: 1px solid #444; border-radius: 4px; }
            QPushButton:hover { background: #3e3e42; color: white; border-color: #666; }
        """)
        self.btn_clear_assets.clicked.connect(self.clear_asset_table)
        
        list_header.addWidget(lbl_list)
        list_header.addStretch()
        list_header.addWidget(self.btn_clear_assets)
        left_layout.addLayout(list_header)
        
        self.asset_table = QTableWidget()
        self.asset_table.setColumnCount(4)
        self.asset_table.setHorizontalHeaderLabels(["IP Addr", "OS / Type", "Ports", "Memo"])
        self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_table.verticalHeader().setVisible(False)
        self.asset_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.asset_table.setAlternatingRowColors(False)
        self.asset_table.setStyleSheet("""
            QTableWidget { background-color: #1e1e1e; gridline-color: #333; border: 1px solid #444; border-radius: 4px; }
            QHeaderView::section { background-color: #252526; color: #ccc; padding: 8px; border: none; border-bottom: 1px solid #444; font-weight: bold; }
            QTableWidget::item { padding: 5px; color: #ddd; }
            QTableWidget::item:selected { background-color: #37373d; color: white; border-left: 2px solid #ff5555; }
            QTableWidget::item:hover { background-color: #2a2a2e; }
        """)
        self.asset_table.doubleClicked.connect(self.on_asset_double_click)
        self.asset_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.asset_table.customContextMenuRequested.connect(self.show_context_menu)
        
        left_layout.addWidget(self.asset_table)
        left_widget.setLayout(left_layout)
        
        # [RIGHT] 로그 콘솔
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        log_header = QHBoxLayout()
        lbl_log = QLabel("📟 System Log")
        lbl_log.setStyleSheet("font-weight: bold; color: #4ec9b0; font-size: 10pt;")
        
        self.btn_clear_logs = QPushButton("Clear Log")
        self.btn_clear_logs.setFixedSize(90, 30)
        self.btn_clear_logs.setStyleSheet("""
            QPushButton { background: #2d2d30; color: #aaa; border: 1px solid #444; border-radius: 4px; }
            QPushButton:hover { background: #3e3e42; color: white; border-color: #666; }
        """)
        self.btn_clear_logs.clicked.connect(self.clear_logs)
        
        log_header.addWidget(lbl_log)
        log_header.addStretch()
        log_header.addWidget(self.btn_clear_logs)
        right_layout.addLayout(log_header)
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("""
            QTextEdit {
                background-color: #101010;
                color: #cccccc;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 9pt;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        right_layout.addWidget(self.log_console)
        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([650, 500])
        main_layout.addWidget(splitter)

        # [6. 상태바]
        self.setStatusBar(None)
        
        status_bar_widget = QWidget()
        status_bar_widget.setStyleSheet("background-color: #2d2d30; color: #bbb; border-top: 1px solid #3e3e42;")
        status_layout = QHBoxLayout(status_bar_widget)
        status_layout.setContentsMargins(15, 5, 15, 5)
        
        self.time_label = QLabel("Ready")
        self.time_label.setStyleSheet("font-weight: bold; font-size: 9pt; color: #ddd;")
        
        self.pbar = QProgressBar()
        self.pbar.setFixedHeight(14)
        self.pbar.setTextVisible(False)
        self.pbar.setStyleSheet("QProgressBar { background: #1e1e1e; border: 1px solid #444; border-radius: 3px; } QProgressBar::chunk { background: #888; }")
        
        status_layout.addWidget(self.time_label)
        status_layout.addStretch()
        status_layout.addWidget(self.pbar, 1)
        
        docked_status_container = QWidget()
        docked_layout = QVBoxLayout(docked_status_container)
        docked_layout.setContentsMargins(0,0,0,0)
        docked_layout.addWidget(status_bar_widget)
        main_layout.addWidget(docked_status_container)

        central_widget.setLayout(main_layout)

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
        
        # [핵심] 이제 self.action_XXX 로 접근 가능
        if hasattr(self, 'action_pdf'): self.action_pdf.setEnabled(not busy)
        if hasattr(self, 'action_xls'): self.action_xls.setEnabled(not busy)
        if hasattr(self, 'action_map'): self.action_map.setEnabled(not busy)
        if hasattr(self, 'action_db'):  self.action_db.setEnabled(not busy)

        self.ip_input.setDisabled(busy)
        self.port_mode_combo.setDisabled(busy)
        self.user_input.setDisabled(busy)
        self.pw_input.setDisabled(busy)

        if busy:
            self.port_input.setDisabled(True)
            self.scan_result_buffer = []
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
        token = get_engine_token()
        self.worker = ScanWorker("NETWORK_SCAN", ip, ports=target_ports, auth_token=token)
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
        token = get_engine_token()
        self.worker = ScanWorker("AUDIT_VULN", ip, user, auth_token=token)
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