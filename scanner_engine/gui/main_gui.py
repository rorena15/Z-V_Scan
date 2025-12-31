# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import multiprocessing
import sys
import os
import queue
import traceback
import ipaddress
import threading
import socket
import subprocess
from datetime import datetime

# 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
    QHeaderView, QProgressBar, QComboBox, QMessageBox, QGroupBox,
    QSplitter, QDialog, QTextEdit, QCheckBox,QMenu
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, Slot
from PySide6.QtGui import QFont, QIcon, QColor, QBrush, QAction

# 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from utils.db_connector import DBConnector
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.windows_inspector import WindowsInspector
from output.pdf_report import PDFGenerator
from output.excel_report import ExcelGenerator
from utils.os_utils import OSUtils
from core.vuln_matcher import VulnMatcher
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger

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
QWidget { color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }
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
    font-size: 9pt; 
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
    font-size: 9pt; 
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
    log_signal = Signal(str)
    finish_signal = Signal(str)
    progress_signal = Signal(int)
    started_signal = Signal(int)
    asset_found_signal = Signal(str, str, str)

    def __init__(self, mode, target_input, user=None, ports=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user = user
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
            open_ports = scanner.tcp_scan(ip, self.ports)
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
        """
        [취약점 정밀 진단]
        - 목적: KISA 규정 준수 여부 및 CVE 취약점 분석
        - 포함: 
        1) 외부 포트 기반 취약점 (VulnMatcher)
        2) 내부 설정 기반 취약점 (SSH/WinRM Inspector)
        """
        if self.stop_flag: return
        
        self.log_signal.emit(f"[*] {ip} 정밀 진단 시작...")

        # ----------------------------------------------------
        # [Step 1] 외부 포트 취약점 진단 (VulnMatcher)
        # ----------------------------------------------------
        try:
            # 주요 포트(위험 포트) 위주로 빠르게 재스캔하여 취약점 매칭
            scanner = AdvancedScanner()
            # KISA 진단에 중요한 포트들
            audit_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080] 
            
            open_ports = scanner.tcp_scan(ip, audit_ports)
            vuln_results = {} # VulnMatcher 결과 저장용

            if open_ports:
                for port in open_ports:
                    banner = scanner.grab_banner(ip, port)
                    # VulnMatcher 호출
                    v_info = VulnMatcher.match(port, banner)
                    
                    if v_info['found']:
                        status = 'VULNERABLE' if v_info['risk'] in ['High', 'Critical'] else 'WARNING'
                        
                        # [수정 완료] (상태, 상세내용, 항목명, 조치방안) 4개 튜플 구조로 변경
                        # 아까 VulnMatcher에 추가한 'remediation'을 여기서 DB로 전달해야 리포트에 나옴
                        vuln_results[v_info['kisa']] = (
                            status, 
                            f"[Port {v_info['service']}] {v_info['desc']}", 
                            v_info['name'],      # 항목명
                            v_info['remediation'] # <--- [핵심] 조치 방안 추가됨
                        )
                        
                        self.log_signal.emit(f"    🚨 외부 취약점 발견: {v_info['service']} ({v_info['kisa']})")

            # 외부 진단 결과가 있으면 먼저 DB 저장
            if vuln_results:
                self._save_results_to_db(ip, "Audit_Target", "Unknown", vuln_results)

        except Exception as e:
            self.log_signal.emit(f"[Warn] 포트 진단 중 오류: {e}")

        # ----------------------------------------------------
        # [Step 2] 내부 시스템 설정 진단 (Login Required)
        # ----------------------------------------------------
        # 시뮬레이션 모드 (localhost 등)
        clean_ip = ip.strip().lower()
        if clean_ip in ["localhost", "127.0.0.1", "0.0.0.0"]:
            self._run_simulation(clean_ip)
            return

        target_os = self._detect_target_os(ip)
        if target_os == "Unknown":
            self.log_signal.emit(f"[-] {ip} 내부 진단 불가 (SSH/WinRM 포트 닫힘)")
            return

        conn_success = False
        internal_results = {}
        
        try:
            if target_os == "Windows":
                conn_success, internal_results = self._audit_windows(ip)
            elif target_os == "Linux":
                conn_success, internal_results = self._audit_linux(ip)

            if conn_success and internal_results:
                self._save_results_to_db(ip, "Audit_Target", target_os, internal_results)
            
            self.log_signal.emit(f"✅ {ip} 진단 완료.")

        except Exception as e:
            self.log_signal.emit(f"[Error] {ip} 내부 진단 중 오류: {str(e)}")

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
        inspector = WindowsInspector(ip, self.user)
        
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
        inspector = SSHInspector(ip, username=self.user)
        
        if inspector.connect():
            results = inspector.run_all_checks()
            inspector.close()
            return True, results
        else:
            self.log_signal.emit(f"[-] SSH 접속 실패: {ip}")
            return False, {}

    def _run_simulation(self, ip):
        #시뮬레이션 데이터 풀 세트 (항목명 + 조치방안 포함)
        self.log_signal.emit(f"[*] [Simulation] {ip} 가상 진단 모드 진입...")
        import time
        time.sleep(0.5)

        target_os = "Linux" if ip in ["localhost", "127.0.0.1"] else "Windows"
        results = {}

        # 데이터 구조: '코드': ('상태', '상세내용', '항목명', '조치방안')
        if target_os == "Linux":
            results = {
                # --- [내부 설정 진단 Mock] ---
                'U-01': ('VULNERABLE', 'PermitRootLogin yes 설정됨', 'Root 계정 원격 접속 제한 미비',
                        '/etc/ssh/sshd_config 파일에서 PermitRootLogin no 설정 후 서비스 재기동'),
                
                'U-02': ('VULNERABLE', '패스워드 최소 길이 미설정 (pwquality.conf)', '패스워드 복잡성 설정 미흡',
                        '/etc/security/pwquality.conf 파일에서 minlen=8, dcredit=-1 등 복잡도 정책 적용'),
                
                'U-03': ('SAFE', '계정 잠금 임계값 설정됨 (5회)', '계정 잠금 임계값 설정',
                        '/etc/pam.d/system-auth 파일에서 deny=5 (5회 실패 시 잠금) 설정 확인'),
                
                'U-04': ('VULNERABLE', '/etc/shadow 권한 취약 (644)', '패스워드 파일 보호',
                        '/etc/shadow 파일 권한을 400(root만 읽기) 또는 000으로 설정 (chmod 400 /etc/shadow)'),
                
                'U-06': ('SAFE', '소유자 없는 파일 없음', '파일 및 디렉터리 소유자 설정',
                        'find / -nouser -o -nogroup 명령으로 소유자 없는 파일 검색 후 삭제 또는 소유자 변경'),
                
                'U-22': ('VULNERABLE', 'Crontab 파일 소유자 취약', 'Cron 파일 소유자 및 권한 설정',
                        '/etc/crontab 파일의 소유자를 root로 변경하고 권한을 640 이하로 설정'),
                
                # --- [외부 포트/CVE 진단 Mock] ---
                'U-20': ('VULNERABLE', '[Port 21] FTP Service Detected - CVE-2011-2523', '익명 FTP 접속 허용',
                        'vsftpd.conf 파일에서 anonymous_enable=NO 설정 및 최신 버전 패치 적용'),
                
                'U-66': ('VULNERABLE', '[Port 23] Telnet Service Detected', 'Telnet 서비스 비활성화',
                        '보안에 취약한 Telnet 서비스를 중지하고 SSH 프로토콜 사용 권장 (systemctl stop telnet)'),
                
                'W-57': ('WARNING', '[Port 80] HTTP Web Server Info Disclosure', '웹 서비스 정보 노출',
                        '웹 서버 설정(httpd.conf)에서 ServerTokens Prod 및 ServerSignature Off 설정')
            }
        else: # Windows
            results = {
                # --- [내부 설정 진단 Mock] ---
                'W-01': ('VULNERABLE', 'Administrator 계정 이름 미변경', '관리자 계정 이름 변경',
                        '제어판 > 관리 도구 > 로컬 보안 정책 > 보안 옵션에서 Administrator 계정 이름을 유추하기 어려운 이름으로 변경'),
                
                'W-02': ('SAFE', 'Guest 계정 비활성화됨', 'Guest 계정 비활성화',
                        '제어판 > 사용자 계정 > Guest 계정 끄기 설정 확인'),
                
                'W-04': ('VULNERABLE', '계정 잠금 정책 미설정', '계정 잠금 임계값 설정',
                        '로컬 보안 정책 > 계정 잠금 정책에서 계정 잠금 임계값을 5회 이하로 설정'),
                
                'W-06': ('SAFE', 'Administrators 그룹 멤버 양호', '관리자 그룹 멤버 관리',
                        'Administrators 그룹에 불필요한 사용자 계정이 존재하지 않도록 주기적 점검 및 제거'),
                
                'W-36': ('VULNERABLE', 'NetBIOS 바인딩 활성화됨', 'NetBIOS 바인딩 제거',
                        '네트워크 어댑터 속성 > TCP/IP 고급 설정 > WINS 탭에서 "NetBIOS over TCP/IP 사용 안 함" 체크'),
                
                'W-60': ('VULNERABLE', '최신 보안 패치(Hotfix) 미적용', 'Windows 보안 업데이트 적용',
                        'Windows Update를 실행하여 최신 보안 패치 및 롤업 업데이트 적용'),

                # --- [외부 포트/CVE 진단 Mock] ---
                'W-08': ('VULNERABLE', '[Port 445] SMB File Sharing - CVE-2017-0144', '하드디스크 기본 공유 제거',
                        '레지스트리 LanmanServer\\Parameters에서 AutoShareServer 값을 0으로 설정하여 C$ 공유 제거'),
                
                'W-18': ('WARNING', '[Port 3389] RDP Detected - CVE-2019-0708', '원격 터미널 접속 보안',
                        '시스템 속성 > 원격 탭에서 "네트워크 수준 인증(NLA)을 사용하는 컴퓨터에서만 연결 허용" 체크'),
                
                'W-58': ('WARNING', '[Port 443] HTTPS Server - Heartbleed Check', '웹 보안 설정(SSL/TLS)',
                        '웹 서버의 SSL/TLS 라이브러리를 최신 버전으로 업데이트하고 취약한 Cipher Suite 비활성화')
            }

        self._save_results_to_db(ip, "Simulation_Target", target_os, results)
        self.log_signal.emit(f"    -> {ip} ({target_os}) 시뮬레이션 완료. (항목: {len(results)}개)")

    def _save_results_to_db(self, ip, hostname, os_type, results):
        #튜플 개수(2개, 3개, 4개)에 상관없이 유연하게 언패킹하여 DB 저장
        db_local = DBConnector()
        asset_id = db_local.save_asset(ip, hostname=hostname, os_type=os_type)
        
        vuln_cnt = 0
        safe_cnt = 0
        
        if asset_id:
            for code, data in results.items():
                name = None
                remediation = None
                
                # 데이터 개수에 따른 유연한 처리 (Crash 방지 핵심 로직)
                if len(data) == 4:
                    # (상태, 상세, 이름, 조치방안) - 최신 버전
                    status, detail, name, remediation = data
                elif len(data) == 3:
                    # (상태, 상세, 이름) - 이전 버전 호환
                    status, detail, name = data
                else:
                    # (상태, 상세) - 초기 버전 호환
                    status, detail = data
                
                # DB 저장 시 name과 remediation 전달
                if db_local.save_scan_result(asset_id, code, status, detail, vuln_name=name, remediation=remediation):
                    if status in ["VULNERABLE", "취약", "Fail"]:
                        _signature = "Made_By_Rorena_2025_Seongnam_KR"
                        vuln_cnt += 1
                        # 로그에 이름이 있으면 이름 출력, 없으면 'Detected'
                        display_name = name if name else "Detected Item"
                        self.log_signal.emit(f"    ❌ [{code}] 취약: {display_name}")
                    else:
                        safe_cnt += 1
                        # 양호 항목은 로그가 너무 길어지지 않게 심플하게 출력
                        self.log_signal.emit(f"    ✅ [{code}] 양호")
        
        # 최종 요약 출력
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
        self.setFixedSize(700, 500)
        self.setWindowIcon(QIcon("app_icon.ico"))  # 아이콘 경로 확인
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        # 스타일 적용 (다크 모드 톤)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #ffffff; }
            QLabel { color: #cccccc; font-size: 11pt; }
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
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #ff5555;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # 2. 법적 고지문 (스크롤 가능)
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setHtml("""
        <h3 style='color: #ffaa00;'>[중요] 사용 전 반드시 읽어주십시오</h3>
        <p>본 소프트웨어 <b>Z-Vuln Scan</b>은 네트워크 보안 진단 및 관리 목적으로 제작된 도구입니다.</p>
        
        <p><b>1. 사용 권한 및 책임</b><br>
        사용자는 본 도구를 <u>자신이 소유하거나, 정당한 권한을 위임받은 네트워크/자산</u>에 대해서만 사용해야 합니다.<br>
        사전 승인되지 않은 타인의 시스템을 스캔하는 행위는 <b>정보통신망법 등 관련 법령에 의거하여 민/형사상 처벌</b>을 받을 수 있습니다.</p>
        
        <p><b>2. 면책 조항</b><br>
        개발자는 본 도구의 사용으로 인해 발생하는 시스템 장애, 데이터 손실, 법적 분쟁 등 어떠한 결과에 대해서도 책임을 지지 않습니다.<br>
        모든 사용 결과에 대한 책임은 전적으로 사용자 본인에게 있습니다.</p>
        
        <p><b>3. 사용 목적 제한</b><br>
        본 도구는 보안 취약점 점검, 교육, 연구 목적으로만 사용되어야 하며,<br>
        악의적인 공격이나 불법적인 침투 목적으로 사용할 수 없습니다.</p>
        
        <p><b>4. 시스템 요구사항 및 환경</b><br>
        본 도구는 패킷 제어를 위해 <b>[관리자 권한]</b>으로 실행되어야 하며, 결과 저장을 위해 <b>[파일 쓰기 권한]</b>이 필수적입니다. <br>
        권한이 제한된 환경(예: 압축 파일 내부 실행, 쓰기 금지된 저장소)에서는 프로그램이 정상 작동하지 않거나 종료될 수 있습니다.</p>
        <br>
        
        <br>
        <p style='color: #cccccc;'>위 내용을 충분히 숙지하였으며, 이에 동의하는 경우에만 프로그램을 시작하십시오.</p>
        """)
        layout.addWidget(self.text_area)

        # 3. 동의 체크박스
        self.check_box = QCheckBox("위 법적 고지 내용을 모두 읽었으며, 이에 동의합니다. 미동의시 도구 사용이 불가능합니다")
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
        
    def accept(self):
        #동의 버튼 클릭 시 호출됨
        try:
            # 로그 파일에 기록 (시간, 사용자명, PC명)
            import getpass
            import platform
            username = getpass.getuser()
            pc_name = platform.node()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            log_msg = f"[{timestamp}] AGREEMENT ACCEPTED | User: {username} | PC: {pc_name} | Version: v2.2.0\n"
            
            # 프로젝트 루트에 로그 저장
            with open("audit_agreement.log", "a", encoding="utf-8") as f:
                f.write(log_msg)
                
        except Exception as e:
            # 로깅 실패가 프로그램 실행을 막지는 않도록 예외 처리
            print(f"[Warning] Failed to write agreement log: {e}")
            
        # 부모 클래스의 accept 호출 (창 닫기 및 결과 반환)
        super().accept()

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
        target_ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        
        # 보안 저장소에서 자격증명 삭제
        SecureStorage.delete_credential(target_ip, user)
        
        self.log_message("[*] 보안을 위해 자격증명 임시 데이터가 삭제되었습니다.")
        #QMessageBox.information(self, "Done", "진단이 완료되었습니다.")
        
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
        
        # [수정] 시뮬레이션이 아닌데 계정 정보가 없으면 경고
        if not is_simulation and (not user or not pw):
            QMessageBox.warning(self, "Auth Error", "원격 진단을 위해 SSH/WinRM 계정 정보(User, PW)가 필요합니다.")
            return
        
        # [수정] 시뮬레이션이 아닐 때만 보안 저장소에 저장
        if not is_simulation:
            if not SecureStorage.save_credential(ip, user, pw):
                QMessageBox.critical(self, "Error", "자격증명을 보안 저장소에 저장하지 못했습니다.\n(ID/PW가 비어있는지 확인해주세요)")
                return

        # 5. 스캔 시작
        self.set_ui_busy(True)
        self.worker = ScanWorker("AUDIT_VULN", ip, user) # [중요] pw 인자 제거됨 확인
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
        
        # 1. Ping 테스트 (살아있나 확인)
        ping_action = QAction(f"📡 Ping Check ({ip})", self)
        # Windows는 -t (계속), Linux는 기본 동작
        cmd = f"start cmd /k ping {ip} -t" if OSUtils.is_windows() else f"gnome-terminal -- ping {ip}"
        ping_action.triggered.connect(lambda: subprocess.Popen(cmd, shell=True))
        menu.addAction(ping_action)
        
        menu.addSeparator() # 구분선

        # 2. OS 맞춤형 원격 접속 (이게 핵심!)
        if "Windows" in os_type:
            # 원격 데스크톱(MSTSC) 바로 실행
            rdp_action = QAction("🖥️ Open Remote Desktop (RDP)", self)
            rdp_action.triggered.connect(lambda: subprocess.Popen(f"mstsc /v:{ip}", shell=True))
            menu.addAction(rdp_action)
            
        elif "Linux" in os_type:
            # SSH 접속 창 바로 열기 (CMD 창 이용)
            ssh_action = QAction("🐧 Open SSH Connection", self)
            # SSH 접속 시도 (ID는 root로 가정하거나 입력받음)
            ssh_action.triggered.connect(lambda: subprocess.Popen(f"start cmd /k ssh root@{ip}", shell=True))
            menu.addAction(ssh_action)

        # 3. 클립보드 복사 (엑셀 등에 붙여넣기 용)
        copy_action = QAction("📄 Copy IP Address", self)
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(ip))
        menu.addAction(copy_action)

        # 메뉴 실행 (마우스 위치에)
        menu.exec(self.asset_table.viewport().mapToGlobal(pos))



if __name__ == '__main__':
    AppLogger.setup()
    # 1. 윈도우 멀티프로세싱 프리징 지원 (EXE 빌드 시 필수, 가장 먼저 호출)
    multiprocessing.freeze_support()
    app = QApplication(sys.argv)
    # 2. 법적 동의 팝업 실행
    disclaimer = LegalDisclaimerDialog()
    # 3. 동의(Accepted)한 경우에만 메인 앱 진입
    if disclaimer.exec() == QDialog.Accepted:
        scanner = ScannerApp()
        scanner.show()
        sys.exit(app.exec())
    else:
        # 동의하지 않거나 창을 닫으면 프로그램 종료
        sys.exit()