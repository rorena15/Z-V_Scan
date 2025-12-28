# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import sys
import os
import queue
import traceback
import ipaddress
import threading
import math

# 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from PyQt5.QtWidgets import (
                                QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                QTextEdit, QMessageBox, QGroupBox, QProgressBar
                            )
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

# 정확한 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from utils.db_connector import DBConnector
from concurrent.futures import ThreadPoolExecutor, as_completed

def my_exception_hook(exctype, value, tb):
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    print(error_msg)
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("치명적인 오류 발생")
    msg.setDetailedText(error_msg)
    msg.exec_()

sys.excepthook = my_exception_hook

# --- [백그라운드 워커 스레드] ---
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    finish_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    started_signal = pyqtSignal(int)

    def __init__(self, mode, target_input, user=None, pw=None, key_path=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user = user
        self.pw = pw
        self.stop_flag = False
        self.max_threads = 20  # 네트워크 스캔용 스레드
        self.audit_threads = 5 # SSH 연결용 스레드 (너무 많으면 차단당함)
        self.key_path = key_path
        self.db_queue = queue.Queue()
        self.writer_thread = None
        self.writer_stop = False
        self.asset_ids = {} # 스레드 간 공유 자원 (주의 필요)
        self.lock = threading.Lock() # asset_ids 접근 보호용

    # --- [공통] DB Writer (수정됨: finally 제거) ---
    def db_writer(self):
        db = DBConnector()
        while not self.writer_stop:
            try:
                item = self.db_queue.get(timeout=1)
                
                if item[0] == 'save_asset':
                    _, ip, hostname, os_type = item
                    # 내부적으로 connect/close 하므로 안전
                    asset_id = db.save_asset(ip, hostname=hostname, os_type=os_type)
                    with self.lock: # 딕셔너리 쓰기 보호
                        self.asset_ids[ip] = asset_id

                elif item[0] == 'save_open_port':
                    _, ip, port, banner = item
                    # asset_id가 아직 딕셔너리에 없을 수 있으므로 잠시 대기 혹은 재시도 로직 필요하나
                    # 구조상 asset 저장 후 포트 저장이 오므로 락만 걸면 대부분 해결
                    asset_id = None
                    with self.lock:
                        asset_id = self.asset_ids.get(ip)
                    
                    if asset_id:
                        db.save_open_port(asset_id, port, banner)

            except queue.Empty:
                continue
            except Exception as e:
                self.log_signal.emit(f"[DB Writer Error] {str(e)}")

    # --- [작업 1] 네트워크 스캔 단위 작업 ---
    def process_network_scan(self, ip):
        if self.stop_flag: return
        
        scanner = AdvancedScanner()
        try:
            # 1. 생존 확인 (Ping/ARP)
            is_alive, os_type = scanner.host_discovery(ip)
            if not is_alive:
                return

            self.db_queue.put(('save_asset', ip, "Scanned_Asset", os_type))

            # 2. 포트 스캔
            open_ports = scanner.syn_scan(ip)
            if open_ports:
                port_str = ", ".join(map(str, open_ports))
                self.log_signal.emit(f"[+] {ip} ({os_type}) -> Ports: {port_str}")

                for port in open_ports:
                    banner = scanner.grab_banner(ip, port)
                    self.db_queue.put(('save_open_port', ip, port, banner))

        except OSError as e:
            self.log_signal.emit(f"[!] {ip} 스캔 중 OS 오류: {e}")
        except Exception as e:
            self.log_signal.emit(f"[!] {ip} 알 수 없는 오류: {e}")

    # --- [작업 2] Audit(취약점) 진단 단위 작업 ---
    def process_audit_scan(self, ip):
        if self.stop_flag: return

        try:
            inspector = SSHInspector(ip, username=self.user, password=self.pw, port=22)
            if inspector.connect():
                self.log_signal.emit(f"[+] SSH 접속 성공: {ip} -> 진단 수행 중...")
                results = inspector.run_all_checks()

                # DB 저장은 Writer Queue를 타지 않고 직접 저장 (Audit은 결과가 복잡하여 로직 분리 추천되나, 여기선 직접 저장 유지)
                # 단, DB Lock 방지를 위해 매번 생성/종료
                db_local = DBConnector() 
                asset_id = db_local.save_asset(ip, hostname="Audit_Target", os_type="Linux")
                
                save_count = 0
                if asset_id:
                    for code, (status, detail) in results.items():
                        if db_local.save_scan_result(asset_id, code, status, detail):
                            save_count += 1
                            # 로그 양이 너무 많으면 성능 저하되므로 취약한 것만 출력
                            if status in ["VULNERABLE", "취약"]:
                                self.log_signal.emit(f"    ⚠️ [{ip}] {code} 취약!")
                
                self.log_signal.emit(f"    -> {ip} 진단 완료. (항목: {save_count}개)")
                inspector.close()
            else:
                self.log_signal.emit(f"[-] SSH 접속 실패: {ip}")
        except Exception as e:
            self.log_signal.emit(f"[Error] {ip} Audit 중 예외: {str(e)}")

    def run(self):
        self.log_signal.emit(f"[*] 스캔 엔진 가동 (Net Threads: {self.max_threads}, Audit Threads: {self.audit_threads})")

        # 1. 대상 IP 생성 (Generator 사용으로 메모리 절약)
        target_gen = None
        total_count = 0
        
        try:
            if "/" in self.target_input:
                network = ipaddress.ip_network(self.target_input, strict=False)
                total_count = network.num_addresses # 카운트만 미리 계산
                target_gen = network.hosts() # Generator 반환
            else:
                total_count = 1
                target_gen = [self.target_input] # 리스트
        except ValueError:
            self.log_signal.emit("[Error] IP 형식이 올바르지 않습니다.")
            self.finish_signal.emit("입력 오류")
            return

        self.started_signal.emit(total_count)
        self.asset_ids = {}

        # DB Writer 시작
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        # 스레드 풀 실행
        processed_count = 0
        
        # 모드에 따른 작업 함수 및 스레드 수 결정
        work_func = None
        cur_threads = 0
        
        if self.mode == "NETWORK_SCAN":
            work_func = self.process_network_scan
            cur_threads = self.max_threads
        elif self.mode == "AUDIT_VULN":
            work_func = self.process_audit_scan
            cur_threads = self.audit_threads # SSH는 연결 제한 고려하여 적게 설정

        # ThreadPoolExecutor로 병렬 처리
        with ThreadPoolExecutor(max_workers=cur_threads) as executor:
            # Generator를 사용하여 작업 제출 (메모리 효율적)
            futures = {executor.submit(work_func, str(ip)): str(ip) for ip in target_gen}

            for future in as_completed(futures):
                if self.stop_flag:
                    executor.shutdown(wait=False, cancel_futures=True)
                    self.log_signal.emit("[!] 사용자 중단 요청 감지. 작업을 정리합니다...")
                    break
                
                processed_count += 1
                # 진행률 업데이트 (너무 잦은 emit 방지)
                if processed_count % 5 == 0 or processed_count == total_count:
                    progress = int((processed_count / total_count) * 100)
                    self.progress_signal.emit(progress)

        # 종료 처리
        self.writer_stop = True
        if self.writer_thread.is_alive():
            self.writer_thread.join(timeout=3)

        status_msg = "작업이 중단되었습니다." if self.stop_flag else "모든 작업이 완료되었습니다."
        self.finish_signal.emit(status_msg)
# --- [메인 윈도우 UI] ---
class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None # 워커 초기화
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Z-Vuln Security Platform')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #f0f0f0;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        # 타이틀
        title_label = QLabel("지능형 취약점 진단 시스템 (Control Panel)")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # 입력 그룹
        input_group = QGroupBox("Target Configuration")
        input_layout = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Target IP (ex: 192.168.0.10)")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("SSH User (root)")
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("SSH Password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("SSH Key Path (Optional)")
        
        input_layout.addWidget(QLabel("IP:"))
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(QLabel("User:"))
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(QLabel("PW:"))
        input_layout.addWidget(self.pw_input)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 버튼 그룹
        btn_layout = QHBoxLayout()
        self.btn_scan = QPushButton("🔍 1. 네트워크 스캔 (Port)")
        self.btn_scan.setMinimumHeight(40)
        self.btn_scan.setStyleSheet("background-color: #007bff; color: white; font-weight: bold;")
        self.btn_scan.clicked.connect(self.start_network_scan)
        
        self.btn_audit = QPushButton("🛡️ 2. 취약점 정밀진단 (Audit)")
        self.btn_audit.setMinimumHeight(40)
        self.btn_audit.setStyleSheet("background-color: #dc3545; color: white; font-weight: bold;")
        self.btn_audit.clicked.connect(self.start_audit)
        
        self.btn_pdf = QPushButton("📄 3. PDF 리포트 생성")
        self.btn_pdf.setMinimumHeight(40)
        self.btn_pdf.setStyleSheet("background-color: #28a745; color: white; font-weight: bold;")
        self.btn_pdf.clicked.connect(self.generate_pdf)
        
        self.btn_stop = QPushButton("🛑 중지")
        self.btn_stop.setMinimumHeight(40)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #ff9800; 
                color: white;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:disabled {
                background-color: #dddddd;
                color: #888888;
                border: 1px solid #cccccc;
            }
            QPushButton:hover {
                background-color: #e68900;
            }
            QPushButton:pressed {
                background-color: #cc7a00;
            }
        """)
        self.btn_stop.clicked.connect(self.stop_scan)

        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_stop)
        layout.addLayout(btn_layout)

        # 프로그래스 바
        progress_layout = QVBoxLayout()
        self.time_label = QLabel("Ready")
        self.time_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.time_label.setStyleSheet("color: #555; font-weight: bold; font-size: 12px;")
        progress_layout.addWidget(self.time_label)

        self.pbar = QProgressBar(self)
        self.pbar.setValue(0)
        self.pbar.setTextVisible(True)
        self.pbar.setFormat("%p%")
        self.pbar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bbb;
                border-radius: 5px;
                text-align: center;
                height: 25px;
                background-color: #e0e0e0;
            }
            QProgressBar::chunk {
                background-color: #007bff;
                width: 20px;
            }
        """)
        progress_layout.addWidget(self.pbar)
        
        layout.addLayout(progress_layout)
        
        # 로그 콘솔
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        layout.addWidget(QLabel("Execution Logs:"))
        layout.addWidget(self.log_console)
        central_widget.setLayout(layout)
        
        # 타이머 설정
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_timer_display)
        self.elapsed_seconds = 0
        
    def update_timer_display(self):
        self.elapsed_seconds += 1
        
        # 1. 경과 시간 포맷팅
        e_min = self.elapsed_seconds // 60
        e_sec = self.elapsed_seconds % 60
        elapsed_str = f"{e_min:02d}:{e_sec:02d}"
        
        # 2. ETA 계산
        current_progress = self.pbar.value()
        eta_str = "계산 중..."
        
        if current_progress > 0:
            total_estimated_seconds = self.elapsed_seconds / (current_progress / 100)
            remaining_seconds = total_estimated_seconds - self.elapsed_seconds
            
            if remaining_seconds < 0: remaining_seconds = 0
            
            r_min = int(remaining_seconds // 60)
            r_sec = int(remaining_seconds % 60)
            eta_str = f"{r_min:02d}:{r_sec:02d}"

        # 3. 라벨 업데이트 (아이콘 포함)
        self.time_label.setText(f" 경과: {elapsed_str}  |  남은 시간: {eta_str}")
        
    def update_progress(self, val):
        self.pbar.setValue(val)

    def log_message(self, msg):
        self.log_console.append(msg)

    def scan_finished(self, msg):
        self.timer.stop()
        final_min = self.elapsed_seconds // 60
        final_sec = self.elapsed_seconds % 60
        self.time_label.setText(f"✅ 완료 (소요 시간: {final_min:02d}:{final_sec:02d})")
        QMessageBox.information(self, "완료", msg)
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        self.btn_pdf.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def start_network_scan(self):
        """네트워크 스캔 시작 버튼 핸들러 (ETA 선행 계산 적용)"""
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력하세요.")
            return
        
        self.reset_ui_state()
        
        # --- [ETA 선행 계산 로직] ---
        try:
            total_hosts = 0
            if "/" in ip:
                # CIDR 계산 (예: 192.168.0.0/24)
                net = ipaddress.ip_network(ip, strict=False)
                total_hosts = net.num_addresses
            else:
                # 단일 IP
                total_hosts = 1

            # ETA 공식: (호스트 수 / 스레드 수 20) * 배지당 1.5초
            batch_count = math.ceil(total_hosts / 20)
            est_time = batch_count * 1.5
            
            msg = f"[*] 대기열 등록: {total_hosts}개 호스트 / 예상 소요: 약 {est_time:.1f}초"
            self.time_label.setText(msg)
            self.log_message(msg)
            
            # UI가 멈추지 않고 글자가 바로 뜨도록 강제 갱신
            QApplication.processEvents()
            
        except Exception as e:
            # IP 형식이 잘못되었을 때는 Worker에서 처리하도록 패스
            self.log_message(f"[Info] 대상 계산 보류: {e}")

        # ---------------------------------

        self.worker = ScanWorker("NETWORK_SCAN", ip)
        self.connect_worker()
        self.worker.start()

    def start_audit(self):
        """보안 진단 시작 버튼 핸들러 (ETA 선행 계산 적용)"""
        ip = self.ip_input.text().strip()
        user = self.user_input.text().strip()
        pw = self.pw_input.text().strip()
        key = self.key_input.text().strip()
        
        if ip not in ["127.0.0.1", "localhost"] and (not user or not pw):
            QMessageBox.warning(self, "경고", "실제 서버 진단을 위해 계정/비밀번호가 필요합니다.\n(localhost 입력 시 시뮬레이션 모드 동작)")
            # return (필요시 주석 해제)

        self.reset_ui_state()

        # --- [ ETA 선행 계산 로직] ---
        try:
            total_hosts = 0
            if "/" in ip:
                net = ipaddress.ip_network(ip, strict=False)
                total_hosts = net.num_addresses
            else:
                total_hosts = 1
            
            # Audit 모드는 순차 처리이므로 시간이 더 걸림 (호스트당 약 3~5초 가정)
            est_time = total_hosts * 5.0
            
            msg = f"[*] SSH 연결 준비: {total_hosts}개 호스트 / 예상 소요: 약 {est_time:.1f}초"
            self.time_label.setText(msg)
            self.log_message(msg)
            
            QApplication.processEvents() # UI 강제 갱신

        except Exception:
            pass
        self.worker = ScanWorker("AUDIT_VULN", ip, user=user, pw=pw, key_path=key)
        self.connect_worker()
        self.worker.start()

    def generate_pdf(self):
        import subprocess
        try:
            self.log_message("[System] PDF 리포트 생성을 요청합니다...")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(os.path.dirname(current_dir), 'output', 'pdf_report.py')
            
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            process = subprocess.run([sys.executable, script_path], capture_output=True, text=True, startupinfo=startupinfo)

            if process.returncode == 0:
                self.log_message("[Success] " + process.stdout.strip())
                QMessageBox.information(self, "성공", "PDF 리포트가 생성되었습니다.\n(scan_result.pdf 확인)")
            else:
                error_msg = process.stderr.strip()
                self.log_message(f"[Error] {error_msg}")
                QMessageBox.warning(self, "실패", f"PDF 생성 실패:\n{error_msg}")

        except Exception as e:
            self.log_message(f"[Critical] 실행 오류: {str(e)}")
            
    def stop_scan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.timer.stop()
            self.log_message("[!!!] 중지 요청 중...")
            self.worker.stop_flag = True
            self.btn_stop.setEnabled(False)

    def reset_ui_state(self):
        self.log_console.clear()
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)
        self.btn_pdf.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)

    def connect_worker(self):
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.started_signal.connect(self.handle_scan_started)
        
    def closeEvent(self, event):
        if hasattr(self, 'worker') and self.worker is not None and self.worker.isRunning():
            self.log_message("[System] 프로그램 종료 요청. 스레드를 정리 중입니다...")
            self.worker.stop_flag = True
            if not self.worker.wait(2000):
                self.worker.terminate()
        event.accept()

    def handle_scan_started(self, total_count):
        self.log_message(f"[System] 실제 진단을 시작합니다. (대상: {total_count}개)")
        self.elapsed_seconds = 0
        self.time_label.setText(" 진행 시간: 00:00 | 남은 시간: 계산 중...")
        self.timer.start()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())