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
import socket
from datetime import datetime

# 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
    QHeaderView, QProgressBar, QComboBox, QMessageBox, QFileDialog, 
    QGroupBox, QSplitter, QFrame, QDialog, QTextEdit, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor, QBrush

# 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from utils.db_connector import DBConnector
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.windows_inspector import WindowsInspector
from output.pdf_report import PDFGenerator
from output.excel_report import ExcelGenerator

def resource_path(relative_path):
    """PyInstaller 빌드 환경 대응"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def my_exception_hook(exctype, value, tb):
    """전역 예외 처리"""
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    print(f"[CRITICAL ERROR] {error_msg}")
    try:
        with open("error_log.txt", "a", encoding="utf-8") as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"[{datetime.now()}]\n{error_msg}")
    except:
        pass

sys.excepthook = my_exception_hook

# --- [스타일시트: 다크 모드 & 모던 UI] ---
STYLESHEET = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
QGroupBox { 
    border: 1px solid #3e3e3e; 
    border-radius: 8px; 
    margin-top: 20px; 
    background-color: #252526; 
    font-weight: bold; 
    color: #007acc; 
}
QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }
QLineEdit { 
    background-color: #333333; 
    border: 1px solid #444444; 
    border-radius: 4px; 
    padding: 8px; 
    color: #ffffff; 
}
QLineEdit:focus { border: 1px solid #007acc; }
QPushButton { 
    background-color: #3a3a3a; 
    border: 1px solid #555555; 
    border-radius: 6px; 
    padding: 10px 15px; 
    color: #ffffff; 
    font-weight: bold; 
}
QPushButton:hover { background-color: #4a4a4a; border-color: #007acc; }
QPushButton:pressed { background-color: #2a2a2a; }
QPushButton:disabled { background-color: #252526; color: #666666; border-color: #333333; }
QPushButton#ClearBtn { 
    padding: 4px 10px; 
    font-size: 12px; 
    background-color: #444; 
    border: 1px solid #666; 
}
QPushButton#ClearBtn:hover { background-color: #c0392b; border-color: #e74c3c; }
QTableWidget { 
    background-color: #252526; 
    alternate-background-color: #2d2d30;
    border: 1px solid #3e3e3e; 
    gridline-color: #3e3e3e; 
    color: #cccccc; 
}
QTableWidget::item {
    padding: 4px;
    border-bottom: 0px;
}
QTableWidget::item:selected {
    background-color: #094771;
    color: white;
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
    font-family: 'Consolas', monospace; 
    font-size: 12px; 
}
QProgressBar { 
    border: 1px solid #3e3e3e; 
    border-radius: 5px; 
    text-align: center; 
    background-color: #252526; 
    color: white; 
}
QProgressBar::chunk { background-color: #007acc; border-radius: 4px; }

QSplitter::handle { background-color: #3e3e3e; }

QComboBox{
    background-color: #333333;
}
QComboBox QAbstractItemView {
    background-color: #333333;
    color: #ffffff;
    selection-background-color: #007acc;
    selection-color: #ffffff;
    border: 1px solid #3e3e3e;
}
QMessageBox {
    background-color: #252526;
    color: #e0e0e0;
    border: 1px solid #3e3e3e;
}
QMessageBox QLabel {
    color: #e0e0e0; /* 메시지 텍스트 색상 */
    font-weight: normal;
}
"""

# --- [백그라운드 워커 스레드] ---
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    finish_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    started_signal = pyqtSignal(int)
    asset_found_signal = pyqtSignal(str, str, str)

    def __init__(self, mode, target_input, user=None, pw=None, ports=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user = user
        self.pw = pw
        self.ports = ports
        self.stop_flag = False
        self.max_threads = 20
        self.audit_threads = 5
        self.db_queue = queue.Queue()
        self.writer_thread = None
        self.writer_stop = False
        self.asset_ids = {}
        self.lock = threading.Lock()

    def db_writer(self):
        """비동기 DB 작성 스레드"""
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
            except Exception as e:
                self.log_signal.emit(f"[DB Error] {str(e)}")

    def process_network_scan(self, ip):
        """네트워크 스캔 프로세스"""
        if self.stop_flag:
            return
        
        scanner = AdvancedScanner()
        try:
            is_alive, os_type = scanner.host_discovery(ip)
            if not is_alive:
                return

            self.db_queue.put(('save_asset', ip, "Scanned_Asset", os_type))
            open_ports = scanner.syn_scan(ip, self.ports)
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
            self.log_signal.emit(f"[!] {ip} 스캔 오류: {str(e)}")

    def process_audit_scan(self, ip):
        """취약점 진단 프로세스"""
        if self.stop_flag:
            return
        
        # 시뮬레이션 모드 체크
        clean_ip = ip.strip().lower()
        if clean_ip in ["localhost", "127.0.0.1", "0.0.0.0", "127.0.0.2"]:
            self._run_simulation(clean_ip)
            return

        # 실제 진단 로직
        target_os = self._detect_target_os(ip)
        
        if target_os == "Unknown":
            self.log_signal.emit(f"[-] {ip} 진단 불가 (Port 22/5985 닫힘)")
            return

        conn_success = False
        results = {}
        
        try:
            if target_os == "Windows":
                conn_success, results = self._audit_windows(ip)
            elif target_os == "Linux":
                conn_success, results = self._audit_linux(ip)

            if conn_success and results:
                self._save_results_to_db(ip, "Audit_Target", target_os, results)

        except Exception as e:
            self.log_signal.emit(f"[Error] {ip} 진단 중 오류: {str(e)}")

    def _detect_target_os(self, ip):
        """대상 OS 탐지"""
        def check_port(target_ip, port):
            try:
                with socket.create_connection((target_ip, port), timeout=2):
                    return True
            except:
                return False

        if check_port(ip, 5985):
            return "Windows"
        elif check_port(ip, 22):
            return "Linux"
        return "Unknown"

    def _audit_windows(self, ip):
        """Windows 시스템 진단"""
        self.log_signal.emit(f"[*] {ip} -> WinRM 연결 시도...")
        inspector = WindowsInspector(ip, self.user, self.pw)
        
        if inspector.connect():
            results = inspector.run_all_checks()
            inspector.close()
            return True, results
        else:
            self.log_signal.emit(f"[-] WinRM 접속 실패: {ip}")
            return False, {}

    def _audit_linux(self, ip):
        """Linux 시스템 진단"""
        self.log_signal.emit(f"[*] {ip} -> SSH 연결 시도...")
        inspector = SSHInspector(ip, username=self.user, password=self.pw)
        
        if inspector.connect():
            results = inspector.run_all_checks()
            inspector.close()
            return True, results
        else:
            self.log_signal.emit(f"[-] SSH 접속 실패: {ip}")
            return False, {}

    def _run_simulation(self, ip):
        """시뮬레이션 모드 - 데모용 대량 데이터 생성"""
        self.log_signal.emit(f"[*] [Simulation] {ip} 가상 진단 모드 진입...")
        import time
        time.sleep(0.5)

        target_os = "Linux" if ip in ["localhost", "127.0.0.1"] else "Windows"
        results = {}

        if target_os == "Linux":
            results = {
                'U-01': ('VULNERABLE', 'PermitRootLogin yes 설정됨'),
                'U-02': ('VULNERABLE', '패스워드 최소 길이 미설정'),
                'U-03': ('SAFE', '계정 잠금 임계값 설정됨'),
                'U-04': ('VULNERABLE', '/etc/shadow 권한 취약 (644)'),
                'U-05': ('SAFE', 'PATH 환경변수 양호'),
                'U-06': ('SAFE', '소유자 없는 파일 없음'),
                'U-07': ('SAFE', '/etc/passwd 소유자 root 확인'),
                'U-19': ('VULNERABLE', 'Finger 서비스 실행 중'),
                'U-20': ('VULNERABLE', 'Anonymous FTP 접속 허용'),
                'U-21': ('SAFE', 'r-command 서비스 비활성화'),
                'U-22': ('VULNERABLE', 'Crontab 파일 소유자 취약'),
                'U-23': ('SAFE', 'DoS 취약 서비스 없음'),
                'U-54': ('VULNERABLE', 'Session Timeout 미설정')
            }
        else:
            results = {
                'W-01': ('VULNERABLE', 'Administrator 계정 이름 미변경'),
                'W-02': ('SAFE', 'Guest 계정 비활성화됨'),
                'W-03': ('VULNERABLE', 'Telnet 서비스 실행 중'),
                'W-04': ('VULNERABLE', '계정 잠금 정책 미설정'),
                'W-05': ('SAFE', '해독 가능한 암호화 저장 안 함'),
                'W-06': ('SAFE', 'Administrators 그룹 양호'),
                'W-08': ('VULNERABLE', '기본 공유(C$) 활성화됨'),
                'W-11': ('SAFE', 'Simple TCP 서비스 미설치'),
                'W-36': ('VULNERABLE', 'NetBIOS 바인딩 활성화'),
                'W-60': ('VULNERABLE', '최신 보안 패치(Hotfix) 미적용')
            }

        self._save_results_to_db(ip, "Simulation_Target", target_os, results)
        self.log_signal.emit(f"    -> {ip} ({target_os}) 시뮬레이션 완료. (항목: {len(results)}개)")

    def _save_results_to_db(self, ip, hostname, os_type, results):
        """DB 저장 및 로그 출력 공통 함수"""
        db_local = DBConnector()
        asset_id = db_local.save_asset(ip, hostname=hostname, os_type=os_type)
        
        vuln_cnt = 0
        safe_cnt = 0
        
        if asset_id:
            for code, (status, detail) in results.items():
                if db_local.save_scan_result(asset_id, code, status, detail):
                    if status in ["VULNERABLE", "취약", "Fail"]:
                        vuln_cnt += 1
                        self.log_signal.emit(f"    ❌ [{code}] 취약: {detail}")
                    else:
                        safe_cnt += 1
                        self.log_signal.emit(f"    ✅ [{code}] 양호")
        
        self.log_signal.emit(f"    📊 결과 요약: 취약 {vuln_cnt}건 / 양호 {safe_cnt}건")

    def run(self):
        """메인 실행 루프"""
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
        
        # DB Writer 스레드 시작
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
                    progress = int((processed_count / total_count) * 100)
                    self.progress_signal.emit(progress)

        if not self.stop_flag:
            self.progress_signal.emit(100)
        
        # DB Writer 정리
        self.writer_stop = True
        if self.writer_thread:
            self.writer_thread.join(timeout=3)
        
        self.finish_signal.emit("작업 완료")

class LegalDisclaimerDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Legal Disclaimer & Agreement")
        self.setFixedSize(600, 450)
        self.setWindowIcon(QIcon("app_icon.ico"))  # 아이콘 경로 확인
        
        # 스타일 적용 (다크 모드 톤)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #ffffff; }
            QLabel { color: #cccccc; font-size: 14px; }
            QTextEdit { 
                background-color: #252526; 
                color: #d4d4d4; 
                border: 1px solid #3e3e3e; 
                padding: 10px;
                font-family: 'Consolas', 'NanumGothic', monospace;
            }
            QCheckBox { color: #ffffff; font-weight: bold; spacing: 8px; }
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:disabled { background-color: #3e3e3e; color: #888888; }
            QPushButton:hover { background-color: #1177bb; }
        """)

        layout = QVBoxLayout()
        
        # 1. 경고 아이콘 및 제목
        title_layout = QHBoxLayout()
        title_label = QLabel("⚠️ Security Tool Usage Warning")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff5555;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # 2. 법적 고지문 (스크롤 가능)
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setHtml("""
        <h3 style='color: #ffaa00;'>[중요] 사용 전 반드시 읽어주십시오</h3>
        <p>본 소프트웨어 <b>Z-VulnScan</b>은 네트워크 보안 진단 및 관리 목적으로 제작된 도구입니다.</p>
        
        <p><b>1. 사용 권한 및 책임</b><br>
        사용자는 본 도구를 <u>자신이 소유하거나, 정당한 권한을 위임받은 네트워크/자산</u>에 대해서만 사용해야 합니다.
        사전 승인되지 않은 타인의 시스템을 스캔하는 행위는 <b>정보통신망법 등 관련 법령에 의거하여 민/형사상 처벌</b>을 받을 수 있습니다.</p>
        
        <p><b>2. 면책 조항</b><br>
        개발자는 본 도구의 사용으로 인해 발생하는 시스템 장애, 데이터 손실, 법적 분쟁 등 어떠한 결과에 대해서도 책임을 지지 않습니다.
        모든 사용 결과에 대한 책임은 전적으로 사용자 본인에게 있습니다.</p>
        
        <p><b>3. 사용 목적 제한</b><br>
        본 도구는 보안 취약점 점검, 교육, 연구 목적으로만 사용되어야 하며, 악의적인 공격이나 불법적인 침투 목적으로 사용할 수 없습니다.</p>
        <br>
        <p style='color: #cccccc;'>위 내용을 충분히 숙지하였으며, 이에 동의하는 경우에만 프로그램을 시작하십시오.</p>
        """)
        layout.addWidget(self.text_area)

        # 3. 동의 체크박스
        self.check_box = QCheckBox("위 법적 고지 내용을 모두 읽었으며, 이에 동의합니다.")
        self.check_box.stateChanged.connect(self.toggle_button)
        layout.addWidget(self.check_box)

        layout.addSpacing(10)

        # 4. 버튼 영역
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_exit = QPushButton("Decline (Exit)")
        self.btn_exit.setStyleSheet("background-color: #555555;")
        self.btn_exit.clicked.connect(self.reject)
        
        self.btn_agree = QPushButton("I Agree & Start")
        self.btn_agree.setDisabled(True) # 기본 비활성화
        self.btn_agree.clicked.connect(self.accept)
        
        btn_layout.addWidget(self.btn_exit)
        btn_layout.addWidget(self.btn_agree)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def toggle_button(self, state):
        # 체크박스가 체크(2)되면 버튼 활성화
        self.btn_agree.setEnabled(state == 2)

# --- [메인 윈도우 UI] ---
class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        self.elapsed_seconds = 0
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Z-VulnScan v2.1.0 pro')
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
        title_label = QLabel("🛡️ Z-VulnScan A.D & S.V Tool")
        title_label.setStyleSheet("color: #ffffff; font-size: 22px; font-weight: bold;")
        ver_label = QLabel("v2.1.0")
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
        self.btn_pdf.setToolTip("PDF 리포트 생성")
        self.btn_pdf.setStyleSheet(
            "QPushButton { border-color: #28a745; } "
            "QPushButton:hover { border-color: #4cd964; background-color: #1e3a20; }"
        )
        self.btn_pdf.clicked.connect(self.generate_pdf)
        
        self.btn_excel = QPushButton("📊 Excel Export")
        self.btn_excel.setToolTip("Enterprise: 상세 진단 결과 엑셀 저장")
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

    def clear_asset_table(self):
        """자산 리스트 초기화"""
        self.asset_table.setRowCount(0)
        self.log_message("[UI] Asset list cleared.")

    def clear_logs(self):
        """로그 콘솔 초기화"""
        self.log_console.clear()
        self.log_message("[UI] Log console cleared.")

    def on_asset_double_click(self):
        """자산 더블클릭 시 Target 입력란에 자동 입력"""
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
        
    def set_ui_busy(self, busy):
        """
        UI 상태를 제어하여 스캔 중 입력 변경을 방지하고, 
        스캔이 끝나면 입력을 다시 활성화합니다.
        """
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
            # 사용자 실수 방지를 위한 확인창 (안전 장치)
            reply = QMessageBox.question(self, "Warning", "전체 포트(65535개) 스캔은 시간이 오래 걸립니다.\n계속하시겠습니까?", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No: return
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
        # 1. IP 유효성 검사 (가장 먼저 실행)
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "진단할 Target IP 주소를 입력해주세요.")
            self.ip_input.setFocus()
            return

        # 2. CIDR 입력 방지 (Audit은 단일 호스트 대상)
        if "/" in ip:
            QMessageBox.warning(self, "Notice", "정밀 진단(Audit)은 단일 IP만 지원합니다.\n네트워크 스캔을 먼저 수행하세요.")
            return

        # 3. 계정 정보 확인 (Audit 필수)
        user = self.user_input.text().strip()
        pw = self.pw_input.text().strip()
        
        # 시뮬레이션 IP가 아니면 계정 정보 요구
        if ip not in ["127.0.0.1", "localhost", "0.0.0.0"] and (not user or not pw):
            QMessageBox.warning(self, "Auth Error", "원격 진단을 위해 SSH/WinRM 계정 정보(User, PW)가 필요합니다.")
            return

        # 4. 모든 검사 통과 후 시작
        self.set_ui_busy(True)
        self.worker = ScanWorker("AUDIT_VULN", ip, user, pw)
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
                self.open_file_platform_safe(filepath) # [변경] 헬퍼 메서드 호출
                
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Error", str(e))

    # [수정] Excel 생성 메서드
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
        """OS에 따라 적절한 방식으로 파일을 엽니다 (Win/Linux/Mac)"""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(filepath)
            elif sys.platform == 'darwin':  # macOS
                subprocess.call(['open', filepath])
            else:  # Linux (xdg-open 사용)
                subprocess.call(['xdg-open', filepath])
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "파일을 열 수 있는 기본 프로그램이 없습니다.")
        except Exception as e:
            self.log_message(f"[Error] Open File Failed: {e}")
            QMessageBox.warning(self, "Error", f"파일 열기 실패:\n{e}")

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
        # Index 1 = Custom Range 일 때만 입력 가능
        self.port_input.setEnabled(index == 1)
        if index == 1: self.port_input.setFocus()



if __name__ == '__main__':
    app = QApplication(sys.argv)
    # 법적 동의 팝업 먼저 실행
    disclaimer = LegalDisclaimerDialog()
    if disclaimer.exec_() == QDialog.Accepted:
        # 동의한 경우에만 메인 앱 실행
        scanner = ScannerApp()
        scanner.show()
        sys.exit(app.exec_())
    else:
        # 동의하지 않거나 창을 닫으면 종료
        sys.exit()
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())