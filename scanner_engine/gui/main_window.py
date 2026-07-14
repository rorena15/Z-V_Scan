# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys
import os
import requests
import threading

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
    QHeaderView, QProgressBar, QComboBox, QMessageBox, 
    QSplitter, QTextEdit, QMenu,
    QGroupBox,
    QAbstractItemView,
    QSizePolicy
)
# [PySide6 핵심 기능]
from PySide6.QtCore import Qt, QTimer
# [PySide6 그래픽 및 액션]
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
from core.license_validator import LicenseValidator
from core.config import AppConfig
from output.pdf_report import PDFGenerator
from output.excel_report import ExcelGenerator
from utils.os_utils import OSUtils
from utils.secure_storage import SecureStorage
from utils.db_connector import DBConnector
from utils.network_visualizer import NetworkVisualizer
from gui.styles import STYLESHEET
from gui.dialogs import LicenseDialog

class LicenseManager:
    #단일 바이너리 내에서 라이선스 등급에 따라 기능을 제어하는 매니저 클래스
    #- Standard: PDF 리포트만 가능, 윈도우 타이틀에 제한 표시
    #- Professional: Excel 리포트 가능, 전체 기능 활성화
    #
    TIER_STANDARD = "STANDARD"
    TIER_PROFESSIONAL = "PROFESSIONAL"

    def __init__(self):
        # 기본값은 STANDARD로 시작 (데모 시연 시 극적인 효과를 위해)
        self.current_tier = self.TIER_STANDARD

    def toggle_tier(self):
        #"""데모 시연용: 등급 스위칭 (Standard <-> Pro)"""
        if self.current_tier == self.TIER_STANDARD:
            self.current_tier = self.TIER_PROFESSIONAL
        else:
            self.current_tier = self.TIER_STANDARD
        return self.current_tier

    def get_window_title(self):
        #"""라이선스에 따른 윈도우 제목 반환"""
        base_title = f"Z-Vuln Scan {AppConfig.VERSION}"
        if self.current_tier == self.TIER_STANDARD:
            return f"{base_title} Standard"
        elif self.current_tier == self.TIER_PROFESSIONAL:
            return f"{base_title} Professional"
        return base_title

    def can_export_excel(self):
        #"""Professional 등급 이상만 엑셀 내보내기 허용"""
        return self.current_tier == self.TIER_PROFESSIONAL
    
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
        self.license_mgr = LicenseManager()
        self.update_ui_by_license()
        saved_key = LicenseValidator.load_license()
        if saved_key:
            is_valid, tier = LicenseValidator.validate_key(saved_key)
            if is_valid:
                # 3. 유효하면 해당 등급으로 즉시 적용 (Standard -> Pro/Ent)
                self.license_mgr.current_tier = tier
                print(f"[System] Valid License Found: {tier}")
        self.load_saved_data()

    # -- UI 세팅 --
    def initUI(self):
        self.setWindowTitle('Z-Vuln Scan')
        self.resize(1200, 850)
        self.setWindowIcon(QIcon(resource_path('app_icon.ico')))
        
        # [테마] 전체 스타일시트 (Deep Dark 모드 + 가독성 개선)
        self.setStyleSheet(STYLESHEET)

        # [1. 상단 툴바]
        self.toolbar = self.addToolBar("Main Toolbar")
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet("""
            QToolBar { background: #252526; border-bottom: 1px solid #333; spacing: 10px; padding: 5px; }
            QToolButton { color: #cccccc; background: transparent; padding: 6px; border-radius: 4px; font-weight: bold; }
            QToolButton:hover { background: #3e3e42; color: white; }
        """)

        # 툴바 액션
        self.action_db = QAction("📂 DB Manager", self)
        self.action_db.triggered.connect(self.open_db_manager)
        self.toolbar.addAction(self.action_db)
        
        self.toolbar.addSeparator()
        
        self.action_map = QAction("🗺️ Topology", self)
        self.action_map.triggered.connect(self.show_topology)
        self.toolbar.addAction(self.action_map)
        
        self.toolbar.addSeparator()

        self.action_pdf = QAction("📄 PDF", self)
        self.action_pdf.triggered.connect(self.generate_pdf)
        self.toolbar.addAction(self.action_pdf)
        
        self.toolbar.addSeparator()
        
        self.action_xls = QAction("📊 Excel", self)
        self.action_xls.triggered.connect(self.generate_excel)
        self.toolbar.addAction(self.action_xls)
        
        #self.toolbar.addSeparator()
        
        # ------------------------------------------------------------------
        # [TODO] 나중에 배포 시 주석 해제 (클라우드 연동 버튼)
        # ------------------------------------------------------------------
        #self.action_cloud = QAction("☁️ Cloud Sync", self)
        #self.action_cloud.triggered.connect(self.sync_to_cloud)
        #self.toolbar.addAction(self.action_cloud)
        #self.toolbar.addSeparator()
        # ------------------------------------------------------------------
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)
        
        # ------------------------------------------------------------------
        # [TODO] 나중에 배포 시 주석 해제 (라이선스 인증 버튼)
        # ------------------------------------------------------------------
        # self.action_license = QAction("Activate License", self)
        # self.action_license.triggered.connect(self.open_license_dialog)
        # self.toolbar.addAction(self.action_license) 
        # ------------------------------------------------------------------
        
        self.toolbar.addSeparator()
        
        # [임시] 개발용 데모 버튼 (나중에 위 코드를 풀면 이건 삭제)
        self.action_license_switch = QAction("Change License (Demo)", self)
        self.action_license_switch.triggered.connect(self.demo_toggle_license)
        self.toolbar.addAction(self.action_license_switch)
        
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
        
        self.title_label = QLabel("Z-Vuln Scan Standard")
        self.title_label.setStyleSheet("color: #e0e0e0; font-size: 14pt; font-weight: bold; border: none;")
        #self.ver_label = QLabel(AppConfig.VERSION)
        #self.ver_label.setStyleSheet("color: #666; font-weight: bold; border: none; margin-left: 5px; margin-top: 5px;")
        
        title_layout.addWidget(self.title_label)
        #title_layout.addWidget(self.ver_label)
        header_layout.addWidget(title_widget)
        
        header_layout.addStretch()
        
        # 통계 컨테이너
        stats_container = QWidget()
        stats_container.setStyleSheet("background-color: #1e1e1e; border-radius: 6px; ali")
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setContentsMargins(15, 8, 15, 8)
        
        self.lbl_stats_assets = QLabel("Assets: 0")
        self.lbl_stats_assets.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11pt; border: none;")
        
        #self.lbl_stats_vulns = QLabel("Issues: 0")
        #self.lbl_stats_vulns.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 11pt; border: none; margin-left: 15px;")
        
        stats_layout.addWidget(self.lbl_stats_assets)
        #stats_layout.addWidget(self.lbl_stats_vulns)
        
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
        
        lbl_mode = QLabel("Port Scan Mode:")
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
        self.btn_clear_assets.setFixedSize(90, 40)
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
        self.asset_table.setColumnCount(6)
        self.asset_table.setHorizontalHeaderLabels(["IP Addr","hostname", "OS / Type","MAC Addr", "Memo", "Vender"])
        self.asset_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_table.verticalHeader().setVisible(False)
        self.asset_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.asset_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
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
        self.btn_clear_logs.setFixedSize(90, 40)
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
    def add_asset_to_table(self, ip, hostname, os_type, mac_addr, vendor):
        # 1. 중복 검사 (Cache 확인 -> 빠름)
        if not hasattr(self, 'scanned_ip_cache'):
            self.scanned_ip_cache = set()
            
        items = self.asset_table.findItems(ip, Qt.MatchExactly)
        row = -1
        
        if items:
            row = items[0].row() 
        else:
            row = self.asset_table.rowCount()
            self.asset_table.insertRow(row)
            self.scanned_ip_cache.add(ip)

        # 2. 메모 가져오기
        memo_text = ""
        try:
            db = DBConnector()
            memo_text = db.get_memo(ip)
        except: pass

        # --- [핵심 수정] 강제 빈칸 처리 로직 ---
        # 입력된 값이 None이거나 "-" (대시)라면 무조건 빈 문자열("")로 바꿈
        def clean_text(text):
            if text is None: return ""
            s = str(text).strip()
            if s == "-": return ""  # 범인 제거!
            return s

        hostname = clean_text(hostname)
        os_type  = clean_text(os_type)
        mac_addr = clean_text(mac_addr)
        vendor   = clean_text(vendor)
        # ------------------------------------

        # 3. 아이템 생성
        item_ip = QTableWidgetItem(ip)
        item_host = QTableWidgetItem(hostname)
        item_os = QTableWidgetItem(os_type)
        item_mac = QTableWidgetItem(mac_addr)
        item_memo = QTableWidgetItem(memo_text if memo_text else "")
        item_vendor = QTableWidgetItem(vendor)
        
        # 4. 스타일링 (색상 설정)
        item_ip.setForeground(QBrush(QColor("#ffffff")))      
        item_host.setForeground(QBrush(QColor("#dddddd")))    
        item_mac.setForeground(QBrush(QColor("#aaaaaa")))     
        item_vendor.setForeground(QBrush(QColor("#aaaaaa")))  
        item_memo.setForeground(QBrush(QColor("#00ff00")))    
        
        if "Linux" in os_type or "Ubuntu" in os_type:
            item_os.setForeground(QBrush(QColor("#ff9900"))) 
        elif "Windows" in os_type:
            item_os.setForeground(QBrush(QColor("#00bfff"))) 
        else:
            item_os.setForeground(QBrush(QColor("#777777"))) 

        # 가운데 정렬
        for item in [item_ip, item_host, item_os, item_mac, item_memo, item_vendor]:
            item.setTextAlignment(Qt.AlignCenter)

        # 5. 테이블 배치
        self.asset_table.setItem(row, 0, item_ip)     
        self.asset_table.setItem(row, 1, item_host)   
        self.asset_table.setItem(row, 2, item_os)     
        self.asset_table.setItem(row, 3, item_mac)    
        self.asset_table.setItem(row, 4, item_memo)   
        self.asset_table.setItem(row, 5, item_vendor)

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
            return f"{h:02d}:{m:02d}:{s:02d}"

        elapsed_str = format_time(self.elapsed_seconds)
        
        # 상태 메시지 단순화
        if self.pbar.value() >= 100:
            status_txt = f"Done (Duration: {elapsed_str})"
        else:
            status_txt = f"Running... [{elapsed_str}]"

        self.time_label.setText(status_txt)

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
        if hasattr(self, 'action_xls'): 
            # 바쁠 때는 무조건 비활성, 안 바쁠 때는 라이선스 체크
            should_enable = (not busy) and self.license_mgr.can_export_excel()
            self.action_xls.setEnabled(should_enable)
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

    def update_asset_table(self, ip, hostname, os_type, mac_addr, vendor):
        """[Optimized] 실시간 테이블 렌더링 대신 버퍼에 저장"""
        # 로그는 이미 실시간으로 뜨므로, 테이블 데이터는 모아둡니다.
        self.scan_result_buffer.append((ip, hostname, os_type, mac_addr, vendor))

    def scan_finished(self, msg):
        self.timer.stop()
        self.pbar.setValue(100) 
        self.set_ui_busy(False) 
        
        if self.scan_result_buffer:
            count = len(self.scan_result_buffer)
            self.log_message(f"[System] Registering {count} assets to table...")
            
            self.asset_table.setSortingEnabled(False) 
            self.asset_table.setUpdatesEnabled(False) 
            
            for data in self.scan_result_buffer:
                ip, hostname, os_type, mac_addr, vendor = data
                self.add_asset_to_table(ip, hostname, os_type, mac_addr, vendor)
                
            self.asset_table.setUpdatesEnabled(True) 
            self.asset_table.setSortingEnabled(True) 
            self.log_message("[System] Table update completed.")
        
        QMessageBox.information(self, "Finished", f"{msg}\n(Total Found: {len(self.scan_result_buffer)})")
        
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        
        self.time_label.setText("Ready")
        self.time_label.setStyleSheet("font-weight: bold; font-size: 9pt; color: #ddd;")
        
        self.pbar.setValue(0) 

        self.log_message(f"[System] Scan Finished. (Total: {self.elapsed_seconds}s)")
        
        target_ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        SecureStorage.delete_credential(target_ip, user)
        
        # [2단계 연동 추가] 스캔 종료 시 위험 IP 미들웨어로 보고
        if target_ip:
            self.log_message(f"[System] 📡 미들웨어에 취약점 진단 결과 전송 중... ({target_ip})")
            # 취약점 개수는 예창패 시연을 위해 강제로 3개로 넘깁니다. 
            threading.Thread(target=self.report_to_middleware, args=(target_ip, 3), daemon=True).start()
        
    def report_to_middleware(self, ip, vuln_count):
        url = "http://127.0.0.1:8089/api/v1/vuln_report"
        payload = {"target_ip": ip, "vuln_count": vuln_count}
        try:
            requests.post(url, json=payload, timeout=3)
        except:
            pass

    def start_network_scan(self):
        self.btn_scan.setEnabled(False) 
        self.btn_audit.setEnabled(False)
        
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Target IP를 입력해주세요.")
            self.ip_input.setFocus()
            self.set_ui_busy(False)
            return

        mode_idx = self.port_mode_combo.currentIndex()
        target_ports = None 

        if mode_idx == 1: 
            p_str = self.port_input.text().strip()
            if not p_str:
                QMessageBox.warning(self, "Input Error", "Custom 포트를 입력해주세요.")
                self.set_ui_busy(False)
                return
            target_ports = AdvancedScanner.parse_ports(p_str)
            if not target_ports:
                QMessageBox.warning(self, "Error", "포트 형식이 올바르지 않습니다.")
                self.set_ui_busy(False)
                return
        elif mode_idx == 2: 
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("⚠️ Full Scan Warning")
            msg.setText("<b>전체 포트(1-65535) 스캔을 시작하시겠습니까?</b>")
            msg.setInformativeText("시간이 매우 오래 걸리며 네트워크 부하가 발생할 수 있습니다.")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.No)
            if msg.exec() == QMessageBox.No: 
                self.set_ui_busy(False)
                return
            target_ports = list(range(1, 65536))
        #self.asset_table.setRowCount(0)
        self.log_message("--- New Scan Started ---")
        
        # 중복 방지 캐시 초기화
        if hasattr(self, 'scanned_ip_cache'):
            self.scanned_ip_cache.clear()
        else:
            self.scanned_ip_cache = set()

        self.set_ui_busy(True)
        try:
            # None을 넘기면 Worker가 "Full Scan"으로 인식하게 됩니다.
            self.worker = ScanWorker("NETWORK_SCAN", ip, ports=target_ports)
            self.connect_worker()
            self.worker.start()
        except Exception as e:
            self.log_message(f"[Error] Failed to start scan: {e}")
            self.set_ui_busy(False)

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
        if not self.license_mgr.can_export_excel():
            QMessageBox.warning(self, "License Restricted", "이 기능은 Professional 라이선스 전용입니다.\n(데모: 툴바의 열쇠 버튼을 눌러보세요)")
            return
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
                # [수정됨] 다이얼로그 모듈 로드 실패 시 브라우저로 열기 (안전장치)
                try:
                    from gui.topology_dialog import TopologyDialog
                    dlg = TopologyDialog(html_path, self)
                    dlg.exec()
                except ImportError:
                    self.log_message("[Info] GUI Dialog missing. Opening in browser.")
                    self.open_file_platform_safe(html_path)
                
                self.statusBar().showMessage("Ready", 3000)
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
        
        # 2. [추가됨] 종료 시 자격증명(ID/PW) 보안 삭제
        target_ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        if target_ip and user:
            SecureStorage.delete_credential(target_ip, user)
            # 디버깅용 로그 (필요 시 주석 처리)
            print(f"[System] Credentials for {target_ip} wiped.")
        
        event.accept()

    def toggle_port_input(self, index):
        # 1. 인덱스가 1(Custom Range)일 때만 입력창 활성화
        is_custom = (index == 1)
        self.port_input.setEnabled(is_custom)

        # 2. 편의성: Custom 모드면 포트 입력창에 바로 포커스, 아니면 내용 지우기
        if is_custom:
            self.port_input.setFocus()
        else:
            self.port_input.clear()

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

    """
    현재 미사용 함수
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
    """

    def show_context_menu(self, pos):
        if not self.asset_table.selectionModel().selection().indexes(): return
        
        row = self.asset_table.currentRow()
        ip = self.asset_table.item(row, 0).text()
        os_type = self.asset_table.item(row, 1).text()
        
        """
        미사용 메모
        menu.addAction("📝 Edit Memo / Tag", self.edit_asset_memo)
        menu.addSeparator()
        """
        menu = QMenu()
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
        # [DB Sync] 최신 데이터로 화면 갱신
        
        # 1. 통계 갱신 (에러 방지 처리)
        try:
            stats = self.db.get_dashboard_stats()
            if hasattr(self, 'lbl_stats_assets'):
                self.lbl_stats_assets.setText(f"Assets: {stats['total_assets']}")
            if hasattr(self, 'lbl_stats_vulns'):
                self.lbl_stats_vulns.setText(f"Issues: {stats['vuln_critical']}")
        except: pass
            
        # 2. 테이블 초기화
        self.asset_table.setRowCount(0)
        self.scanned_ip_cache = set()
        
        # 3. 데이터 가져오기 (DBConnector.get_all_assets()는 항상
        #    (ip_addr, os_type, memo, mac_addr) 4개 컬럼을 반환한다.
        #    Hostname/Vendor는 이 쿼리로는 조회되지 않으므로 빈 값으로 둔다.
        #    (memo는 add_asset_to_table 내부에서 DB로부터 다시 조회하므로 여기서는 사용하지 않음)
        assets = self.db.get_all_assets()

        # 화면 깜빡임 방지
        self.asset_table.setSortingEnabled(False)
        self.asset_table.setUpdatesEnabled(False)

        for data in assets:
            try:
                ip, os_type, _memo, mac_addr = data

                # [데이터 세탁] DB에 '-'라고 저장된 것만 보기 좋게 빈칸으로 변경
                # (실제 데이터가 있으면 그대로 유지됨)
                os_type  = "" if str(os_type) == "-"  else os_type
                mac_addr = "" if str(mac_addr) == "-" else mac_addr

                self.add_asset_to_table(ip, "", os_type, mac_addr, "")

            except Exception as e:
                print(f"Error refreshing row: {e}")
            
        self.asset_table.setUpdatesEnabled(True)
        self.asset_table.setSortingEnabled(True)
        
        self.log_message(f"[System] Dashboard Refreshed. (Assets: {len(assets)})")
        
    def update_ui_by_license(self):
        # 1. 윈도우 제목 변경
        new_title = self.license_mgr.get_window_title()
        self.setWindowTitle(new_title)
        
        # (선택사항) 헤더 라벨도 있다면 같이 변경
        if hasattr(self, 'title_label'):
            self.title_label.setText(new_title)

        # 2. 엑셀 버튼 활성화/비활성화 (Feature Flag)
        can_excel = self.license_mgr.can_export_excel()
        if hasattr(self, 'action_xls') and hasattr(self, 'toolbar'):
            self.action_xls.setEnabled(can_excel)
            
            # 툴바에서 실제 버튼 위젯 가져오기
            btn_widget = self.toolbar.widgetForAction(self.action_xls)
            
            if btn_widget:
                if can_excel:
                    # [Pro 모드] 활성 상태: 흰색 (기존 스타일 유지)
                    self.action_xls.setText("📊 Excel Export")
                    self.action_xls.setToolTip("Export Scan Results to Excel (Professional)")
                    # 기본 텍스트 색상(흰색)으로 복구
                    btn_widget.setStyleSheet("color: #ffffff; font-weight: bold;")
                else:
                    # [Standard 모드] 비활성 상태: 회색 (#7f8c8d)
                    self.action_xls.setText("📊 Excel Export") # 텍스트도 그대로 유지 (잠금 아이콘 X)
                    self.action_xls.setToolTip("🔒 Locked (Requires Professional License)")
                    # 비활성 느낌의 회색 적용
                    btn_widget.setStyleSheet("color: #7f8c8d;")

    # 데모용 라이선스 토글 함수
    def demo_toggle_license(self):
        new_tier = self.license_mgr.toggle_tier()
        self.update_ui_by_license()
        
        msg = "Professional Mode Activated! (Full Features Unlocked)" if new_tier == "PROFESSIONAL" else "Reverted to Standard Mode. (Excel Export Locked)"
        QMessageBox.information(self, "License Change", msg)

    # ----------------------------------------------------------------------
    # [TODO] 나중에 주석 해제하여 사용 (라이선스 다이얼로그 연동)
    # ----------------------------------------------------------------------
    def open_license_dialog(self):
        pass # 주석 처리된 동안 에러 방지용
        # dlg = LicenseDialog(self)
        # if dlg.exec():
        #     if dlg.verified_tier:
        #         self.license_mgr.current_tier = dlg.verified_tier
        #         self.update_ui_by_license()
        #         self.log_message(f"[System] License Activated: {dlg.verified_tier}")
        
    def sync_to_cloud(self):
        # 아직 기능은 없지만, 사업계획서상 '로드맵' 기능을 시연하는 용도
        QMessageBox.information(self, "Enterprise Feature", 
            "☁️ [Cloud Sync]\n\n"
            "자산 데이터를 중앙 관제 대시보드(SaaS)로 전송합니다.\n"
            "(현재 데모 버전에서는 시뮬레이션만 수행됩니다.)")
        
    def load_saved_data(self):
        #[Startup] DB에 저장된 자산 정보를 불러와 테이블에 채웁니다.
        self.log_message("[System] Loading saved assets from database...")
        
        db = DBConnector()
        assets = db.get_all_assets()
        
        if not assets:
            self.log_message("[System] No saved assets found.")
            return

        # 화면 깜빡임 방지 (대량 데이터 로드 시 필수)
        self.asset_table.setSortingEnabled(False)
        self.asset_table.setUpdatesEnabled(False)
        
        count = 0
        for asset in assets:
            try:
                # DBConnector.get_all_assets()는 항상
                # (ip_addr, os_type, memo, mac_addr) 4개 컬럼을 반환한다.
                # Hostname/Vendor는 이 쿼리로는 조회되지 않으므로 빈 값으로 둔다.
                ip, os_type, _memo, mac = asset
                self.add_asset_to_table(ip, "", os_type, mac, "")
                count += 1
            except Exception as e:
                print(f"Error loading asset: {e}")
        
        self.asset_table.setUpdatesEnabled(True)
        self.asset_table.setSortingEnabled(True)
        
        # 상태 업데이트
        self.lbl_stats_assets.setText(f"Assets: {count}")
        self.log_message(f"[System] Successfully loaded {count} assets.")