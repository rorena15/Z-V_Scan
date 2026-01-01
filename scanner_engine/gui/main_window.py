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
from PySide6.QtGui import QIcon, QColor, QBrush, QAction

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

class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        self.elapsed_seconds = 0
        self.initUI()

    # -- UI 세팅 --
    def initUI(self):
        self.setWindowTitle('Z-VulnScan v2.2.0 Professional Edition')
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
        title_label = QLabel("🛡️ Z-VulnScan V2.2.0 Professional Edition")
        title_label.setStyleSheet("color: #ffffff; font-size: 16pt; font-weight: bold;")
        ver_label = QLabel("v2.2.0")
        ver_label.setStyleSheet("color: #666; font-weight: bold;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(ver_label)
        main_layout.addLayout(header_layout)

        # 2. 타겟 & 포트 설정 (Grid Layout 대체)
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
        
        # Row 2: Port Settings [NEW]
        row2 = QHBoxLayout()
        self.port_mode_combo = QComboBox()
        self.port_mode_combo.addItems(["⚡ Default (Fast)", "📝 Custom Range", "🐢 Full Scan (1-65535)"])
        self.port_mode_combo.currentIndexChanged.connect(self.toggle_port_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Ex: 80,443,8080 or 1-1024")
        self.port_input.setEnabled(False) # 기본값은 비활성화
        
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
        
        self.btn_stop = QPushButton("🛑 Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)

        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_excel)
        btn_layout.addWidget(self.btn_stop)
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
    def add_asset_to_table(self, ip, os_type, ports):
        """자산 테이블에 추가"""
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
            c_os.setForeground(QBrush(QColor("#ff9900")))
        elif os_type == "Windows":
            c_os.setForeground(QBrush(QColor("#00bfff")))
        else:
            c_os.setForeground(QBrush(QColor("#777777")))

        self.asset_table.setItem(row, 0, c_ip)
        self.asset_table.setItem(row, 1, c_os)
        self.asset_table.setItem(row, 2, c_port)

    # 자산 리스트 초기화
    def clear_asset_table(self):
        if self.asset_table.rowCount() == 0:
            return

        # 1. 안전장치: 사용자 확인 (메모 삭제 경고)
        reply = QMessageBox.question(
            self, 
            "Confirm Delete", 
            "⚠️ 경고: 모든 자산 데이터와 작성한 메모(Memo)가 영구적으로 삭제됩니다.\n\n"
            "정말로 초기화하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No 
        )

        if reply == QMessageBox.Yes:
            # 2. DB 데이터 삭제
            db = DBConnector()
            if db.delete_all_assets():
                # 3. UI 테이블 초기화
                self.asset_table.setRowCount(0)
                self.log_message("[System] 🗑️ All assets and history have been cleared from Database.")
                QMessageBox.information(self, "Cleared", "모든 데이터가 초기화되었습니다.")
            else:
                QMessageBox.critical(self, "Error", "DB 초기화 실패. 로그를 확인하세요.")
        self.asset_table.setRowCount(0)
        self.log_message("[UI] Asset list cleared.")

    # 로그 콘솔 초기화
    def clear_logs(self):
        self.log_console.clear()
        self.log_message("[UI] Log console cleared.")

    # 자산 더블클릭 시 Target 입력란에 자동 입력
    def on_asset_double_click(self):
        row = self.asset_table.currentRow()
        if row >= 0:
            ip = self.asset_table.item(row, 0).text()
            self.ip_input.setText(ip)
            self.log_message(f"[UI] Target Selected: {ip} -> Ready to Audit.")
            
            # 시뮬레이션 IP에 대한 자동 입력
            if ip in ["127.0.0.1", "localhost"]:
                self.user_input.setText("root")
                self.pw_input.setText("toor")
            elif ip == "0.0.0.0":
                self.user_input.setText("Administrator")
                self.pw_input.setText("password123")

    def update_timer(self):
        self.elapsed_seconds += 1
        
        # 경과 시간 포맷팅
        m, s = divmod(self.elapsed_seconds, 60)
        elapsed_str = f"{m:02d}:{s:02d}"
        
        # ETA (남은 시간) 계산 로직
        current_progress = self.pbar.value()
        eta_str = "--:--"
        
        if current_progress > 0 and current_progress < 100:
            # (경과시간 / 진행률) = 1%당 소요 시간
            # 남은 시간 = 1%당 소요 시간 * 남은 퍼센트
            estimated_total = self.elapsed_seconds / (current_progress / 100)
            remaining = int(estimated_total - self.elapsed_seconds)
            
            if remaining > 0:
                rm, rs = divmod(remaining, 60)
                eta_str = f"{rm:02d}:{rs:02d}"
            else:
                eta_str = "00:00"
        elif current_progress >= 100:
            eta_str = "Done"

        # 라벨 업데이트 (경과 시간 | 남은 시간)
        self.time_label.setText(f"Elapsed: {elapsed_str}  |  ETA: {eta_str}")

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
        self.set_ui_busy(False)
        self.log_message(f"[System] Scan Finished. (Total: {self.elapsed_seconds}s)")
        target_ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        
        # 보안 저장소에서 자격증명 삭제
        SecureStorage.delete_credential(target_ip, user)
        
        self.log_message("[*] 보안을 위해 자격증명 임시 데이터가 삭제되었습니다.")
        #QMessageBox.information(self, "Done", "진단이 완료되었습니다.")
        
    def set_ui_busy(self, busy):
        # UI 상태를 제어하여 스캔 중 입력 변경을 방지하고, 
        # 스캔이 끝나면 입력을 다시 활성화합니다.
        # 1. 버튼 상태 토글
        self.btn_scan.setDisabled(busy)   # 스캔 중엔 시작 버튼 비활성
        self.btn_audit.setDisabled(busy)  # 스캔 중엔 진단 버튼 비활성
        self.btn_stop.setEnabled(busy)    # 스캔 중에만 정지 버튼 활성
        
        # 2. PDF/Excel 버튼 (결과 나오기 전엔 비활성, 끝나면 활성)
        self.btn_pdf.setDisabled(busy)
        self.btn_excel.setDisabled(busy)

        # 3. 입력창 상태 제어 (핵심 수정 부분)
        # busy가 True면 Disabled(잠금), False면 Enabled(해제)
        self.ip_input.setDisabled(busy)
        self.port_mode_combo.setDisabled(busy)
        self.user_input.setDisabled(busy)
        self.pw_input.setDisabled(busy)

        # 4. 포트 입력창(Custom) 디테일 처리
        if busy:
            # 스캔 중에는 무조건 잠금
            self.port_input.setDisabled(True)
        else:
            # 스캔이 끝났을 때: 'Custom Range' 모드일 때만 입력창을 다시 틉니다.
            is_custom_mode = (self.port_mode_combo.currentIndex() == 1)
            self.port_input.setEnabled(is_custom_mode)

        # 5. 타이머 및 프로그레스바
        if busy:
            self.pbar.setValue(0)
            self.elapsed_seconds = 0
            self.time_label.setText("Initializing...")
            self.timer.start(1000)
        else:
            self.timer.stop()
            self.pbar.setValue(100) # 완료 시 100% 채움

        # 타이머 및 프로그레스바 제어
        if busy:
            self.pbar.setValue(0)
            self.elapsed_seconds = 0
            self.timer.start(1000) # 1초마다 타이머 갱신
        else:
            self.timer.stop()
            self.ip_input.setDisabled(False)
            self.port_mode_combo.setDisabled(False)

    def start_network_scan(self):
        # 1. IP 유효성 검사 (기능: IP 미입력 시 경고 및 포커스 이동)
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Target IP 주소를 입력해주세요.")
            self.ip_input.setFocus() # UX 강화: 입력창으로 커서 이동
            return

        # 2. 포트 설정 모드 확인
        mode_idx = self.port_mode_combo.currentIndex()
        target_ports = None # 기본값 (None이면 Fast Scan)

        # 3. 사용자 정의 포트(Custom Range) 처리
        if mode_idx == 1: 
            p_str = self.port_input.text().strip()
            if not p_str:
                QMessageBox.warning(self, "Input Error", "Custom 포트 범위를 입력해주세요.")
                self.port_input.setFocus()
                return
            
            # 포트 파싱 및 유효성 검증
            target_ports = AdvancedScanner.parse_ports(p_str)
            if not target_ports:
                QMessageBox.warning(self, "Input Error", "유효하지 않은 포트 형식입니다.\n(예: 80,443 또는 1-1000)")
                return
        
        # 4. 전체 포트(Full Scan) 처리
        elif mode_idx == 2: 
            # [수정] 깔끔하고 전문적인 경고 알림창
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("⚠️ Full Port Scan Warning")
            msg.setText("<b>전체 포트(1-65535) 정밀 스캔을 시작하시겠습니까?</b>")
            msg.setInformativeText(
                "이 작업은 대상 호스트의 응답 속도에 따라 "
                "<font color='#ff5555'><b>1시간 이상 소요</b></font>될 수 있습니다.<br><br>"
                "또한 다량의 패킷 전송으로 인해 "
                "<font color='#ff5555'><b>네트워크 부하</b></font>가 발생할 수 있으니 "
                "업무 시간 외 실행을 권장합니다."
            )
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.No) # 실수 방지를 위해 'No'를 기본값으로 설정
            
            reply = msg.exec()
            
            if reply == QMessageBox.No: 
                self.set_ui_busy(False) # UI 잠금 해제 (필수)
                return
                
            target_ports = list(range(1, 65536))

        # 5. 스캔 시작 프로세스
        self.set_ui_busy(True) # UI 잠금 및 타이머 시작
        
        # CIDR(대역) 스캔인 경우 자산 리스트 초기화
        if "/" in ip: 
            self.asset_table.setRowCount(0)
        
        # 워커 쓰레드 시작 (포트 리스트 전달)
        self.worker = ScanWorker("NETWORK_SCAN", ip, ports=target_ports)
        self.connect_worker()
        self.worker.start()

    def start_audit(self):
        # 1. IP 유효성 검사
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "진단할 Target IP 주소를 입력해주세요.")
            self.ip_input.setFocus()
            return

        # 2. CIDR 입력 방지
        if "/" in ip:
            QMessageBox.warning(self, "Notice", "정밀 진단(Audit)은 단일 IP만 지원합니다.\n네트워크 스캔을 먼저 수행하세요.")
            return

        # 3. 시뮬레이션 여부 확인
        is_simulation = ip in ["127.0.0.1", "localhost", "0.0.0.0"]

        # 4. 계정 정보 처리
        user = self.user_input.text().strip()
        pw = self.pw_input.text().strip()
        
        #시뮬레이션이 아닌데 계정 정보가 없으면 경고
        if not is_simulation and (not user or not pw):
            QMessageBox.warning(self, "Auth Error", "원격 진단을 위해 SSH/WinRM 계정 정보(User, PW)가 필요합니다.")
            return
        
        #시뮬레이션이 아닐 때만 보안 저장소에 저장
        if not is_simulation:
            if not SecureStorage.save_credential(ip, user, pw):
                QMessageBox.critical(self, "Error", "자격증명을 보안 저장소에 저장하지 못했습니다.\n(ID/PW가 비어있는지 확인해주세요)")
                return

        # 5. 스캔 시작
        self.set_ui_busy(True)
        self.worker = ScanWorker("AUDIT_VULN", ip, user) #pw 인자 제거됨 확인
        self.connect_worker()
        self.worker.start()

    def generate_pdf(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            generator = PDFGenerator()
            filepath = generator.generate()
            QApplication.restoreOverrideCursor() # 커서 복구
            
            self.log_message(f"[Success] Report Generated: {generator.filename}")
            
            reply = QMessageBox.question(
                self, "Success", 
                f"PDF 리포트가 생성되었습니다:\n{filepath}\n\n지금 여시겠습니까?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.open_file_platform_safe(filepath) #헬퍼 메서드 호출
                
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Error", str(e))

    # Excel 생성 메서드
    def generate_excel(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            generator = ExcelGenerator()
            filepath = generator.generate()
            QApplication.restoreOverrideCursor() # 커서 복구
            
            self.log_message(f"[Success] Excel Report Saved: {filepath}")
            
            reply = QMessageBox.question(
                self, "Success", 
                f"Excel 리포트가 생성되었습니다:\n{filepath}\n\n지금 여시겠습니까?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.open_file_platform_safe(filepath) # [변경] 헬퍼 메서드 호출
                
        except ImportError:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Error", "openpyxl 라이브러리가 필요합니다.\n(pip install openpyxl)")
        except Exception as e:
            QApplication.restoreOverrideCursor()
            self.log_message(f"[Error] Excel Generate Failed: {e}")
            QMessageBox.warning(self, "Error", f"생성 실패: {str(e)}")

    def open_file_platform_safe(self, filepath):
        success = OSUtils.open_file(filepath)
        if not success:
            QMessageBox.warning(self, "Error", f"파일을 열 수 없습니다:\n{filepath}\n(파일은 정상적으로 저장되었습니다.)")

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop_flag = True
            self.btn_stop.setEnabled(False)
            self.log_message("[!!!] Stopping...")

    def prepare_scan(self):
        # self.log_console.clear()
        # # 로그는 남겨두는 게 좋을 수 있음 (수동 Clear 사용)
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
        
    def toggle_port_input(self, index):
        # 1. Custom Range (Index 1) 활성화 처리
        is_custom = (index == 1)
        self.port_input.setEnabled(is_custom)
        if is_custom: 
            self.port_input.setFocus()

        # 2. [추가] Full Scan (Index 2) 선택 시 즉시 경고 팝업
        if index == 2:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("⚠️ Full Port Scan Warning")
            msg.setText("<b>전체 포트(1-65535) 정밀 스캔을 선택하셨습니다.</b>")
            msg.setInformativeText(
                "이 모드는 대상 호스트의 응답 속도에 따라 "
                "<font color='#ff5555'><b>1시간 이상 소요</b></font>될 수 있으며, "
                "네트워크에 <font color='#ff5555'><b>큰 부하</b></font>를 줄 수 있습니다.<br><br>"
                "정말로 이 옵션을 유지하시겠습니까?"
            )
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg.setDefaultButton(QMessageBox.No) # 'No'를 기본값으로 설정 (안전)
            
            reply = msg.exec()
            
            # 사용자가 'No'를 누르면 -> 강제로 'Default' 모드로 되돌림
            if reply == QMessageBox.No:
                self.port_mode_combo.blockSignals(True) # 이벤트 재발생 방지 (중요)
                self.port_mode_combo.setCurrentIndex(0) # Default 모드로 복귀
                self.port_mode_combo.blockSignals(False)

# --- [New Feature] 자산 메모 및 로드 관련 메서드 ---

    def load_saved_assets(self):
        #DB에서 이전에 스캔된 자산 목록을 불러와 UI에 표시
        db = DBConnector()
        assets = db.get_all_assets() # [(ip, os, memo), ...]
        
        self.asset_table.setRowCount(0)
        for ip, os_type, memo, mac_addr in assets:
            # 화면에 OS만 보여주는 대신 MAC 주소도 같이 보여주면 더 좋습니다.
            display_os = os_type
            if mac_addr:
                display_os = f"{os_type} | {mac_addr}"
            
            self.add_asset_to_table(ip, display_os, "Scanned History", memo_text=memo)
        
        if assets:
            self.log_message(f"[System] Loaded {len(assets)} assets from history.")

    def add_asset_to_table(self, ip, os_type, ports, memo_text=None):
        #자산 테이블에 추가 (메모 기능 연동)
        # 기존에 있는 행인지 확인
        items = self.asset_table.findItems(ip, Qt.MatchExactly)
        row = -1
        
        if items:
            row = items[0].row()
        else:
            row = self.asset_table.rowCount()
            self.asset_table.insertRow(row)

        # 메모가 None이면(스캔 결과), DB에서 기존 메모를 조회해서 유지해야 함
        if memo_text is None:
            db = DBConnector()
            memo_text = db.get_memo(ip)

        c_ip = QTableWidgetItem(ip)
        c_os = QTableWidgetItem(os_type)
        c_port = QTableWidgetItem(ports)
        c_memo = QTableWidgetItem(memo_text) # New
        
        # 스타일링
        c_ip.setForeground(QBrush(QColor("#ffffff")))
        c_port.setForeground(QBrush(QColor("#aaaaaa")))
        c_memo.setForeground(QBrush(QColor("#00ff00"))) # 메모는 녹색 계열로 강조
        
        if os_type == "Linux":
            c_os.setForeground(QBrush(QColor("#ff9900")))
        elif os_type == "Windows":
            c_os.setForeground(QBrush(QColor("#00bfff")))
        else:
            c_os.setForeground(QBrush(QColor("#777777")))

        self.asset_table.setItem(row, 0, c_ip)
        self.asset_table.setItem(row, 1, c_os)
        self.asset_table.setItem(row, 2, c_port)
        self.asset_table.setItem(row, 3, c_memo) # New

    def edit_asset_memo(self):
        #선택된 자산의 메모 수정
        row = self.asset_table.currentRow()
        if row < 0: return
        
        ip = self.asset_table.item(row, 0).text()
        current_memo = self.asset_table.item(row, 3).text()
        
        # 입력 다이얼로그 표시
        text, ok = QInputDialog.getText(
                                        self, "Asset Memo", 
                                        f"Edit Memo for {ip}:", 
                                        QLineEdit.Normal, current_memo
                                        )
        
        if ok:
            # 1. DB 업데이트
            db = DBConnector()
            if db.update_memo(ip, text):
                # 2. UI 업데이트
                self.asset_table.item(row, 3).setText(text)
                self.log_message(f"[Asset] Memo updated for {ip}")
            else:
                QMessageBox.warning(self, "Error", "DB Update failed.")

    def show_context_menu(self, pos):
        #자산 리스트 우클릭 메뉴: 운영 편의 기능 제공
        # 선택된 행이 없으면 메뉴 안 띄움
        indexes = self.asset_table.selectionModel().selection().indexes()
        if not indexes:
            return

        # 선택된 행의 데이터 가져오기
        row = self.asset_table.currentRow()
        ip = self.asset_table.item(row, 0).text()
        os_type = self.asset_table.item(row, 1).text()
        
        menu = QMenu()
        
        # [New] 메모 수정 메뉴 (최상단 배치)
        memo_action = QAction("📝 Edit Memo / Tag", self)
        memo_action.triggered.connect(self.edit_asset_memo)
        menu.addAction(memo_action)
        
        menu.addSeparator() # 구분선

        # 1. Ping 테스트 (살아있나 확인)
        ping_action = QAction(f"📡 Ping Check ({ip})", self)
        # Windows는 -t (계속), Linux는 기본 동작
        ping_action.triggered.connect(lambda: OSUtils.open_ping_test(ip))
        menu.addAction(ping_action)
        
        menu.addSeparator() # 구분선

        # 2. OS 맞춤형 원격 접속
        if "Windows" in os_type:
            # 원격 데스크톱(MSTSC) 바로 실행
            rdp_action = QAction("🖥️ Open Remote Desktop (RDP)", self)
            rdp_action.triggered.connect(lambda: OSUtils.open_rdp(ip))
            menu.addAction(rdp_action)
            
        elif "Linux" in os_type:
            # SSH 접속 창 바로 열기 (CMD 창 이용)
            ssh_action = QAction("🐧 Open SSH Connection", self)
            current_user = self.user_input.text().strip() or "root"
            ssh_action.triggered.connect(lambda: OSUtils.open_ssh(ip, current_user))
            menu.addAction(ssh_action)

        # 3. 클립보드 복사 (엑셀 등에 붙여넣기 용)
        copy_action = QAction("📄 Copy IP Address", self)
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(ip))
        menu.addAction(copy_action)

        # 메뉴 실행 (마우스 위치에)
        menu.exec(self.asset_table.viewport().mapToGlobal(pos))