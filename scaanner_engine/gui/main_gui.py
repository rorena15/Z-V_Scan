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
        self.max_threads = 20
        self.key_path = key_path
        self.db_queue = queue.Queue()  # DB 쓰기 큐
        self.writer_thread = None
        self.writer_stop = False

    def process_single_ip(self, ip):
        if self.stop_flag:
            return

        scanner = AdvancedScanner()
        try:
            is_alive, os_type = scanner.host_discovery(ip)
            if not is_alive:
                return

            # DB 쓰기 대신 Queue에 넣음
            self.db_queue.put(('save_asset', ip, "Scanned_Asset", os_type))

            open_ports = scanner.syn_scan(ip)
            if open_ports:
                port_str = ", ".join(map(str, open_ports))
                self.log_signal.emit(f"[+] {ip} ({os_type}) -> Ports: {port_str}")

                for port in open_ports:
                    banner = scanner.grab_banner(ip, port)
                    self.db_queue.put(('save_open_port', ip, port, banner))  # asset_id 대신 ip로 임시 저장 (Writer에서 처리)

        except Exception as e:
            pass

    def db_writer(self):
        """단일 스레드에서 Queue에서 꺼내 DB에 쓰기"""
        db = DBConnector()
        
        while not self.writer_stop:
            try:
                item = self.db_queue.get(timeout=1)
                if item[0] == 'save_asset':
                    _, ip, hostname, os_type = item
                    asset_id = db.save_asset(ip, hostname=hostname, os_type=os_type)
                    # asset_id를 나중에 포트 저장에 사용할 수 있도록 (임시로 dict에 저장)
                    self.asset_ids[ip] = asset_id
                elif item[0] == 'save_open_port':
                    _, ip, port, banner = item
                    asset_id = self.asset_ids.get(ip)
                    if asset_id:
                        db.save_open_port(asset_id, port, banner)
            except queue.Empty:
                continue
            except Exception as e:
                self.log_signal.emit(f"[DB Writer Error] {str(e)}")

    def run(self):
        self.log_signal.emit(f"[*] 스캔 엔진 가동 (Max Threads: {self.max_threads})...")
        self.log_signal.emit(f"[*] 대상 IP 리스트를 계산 중입니다...")

        target_list = []
        try:
            if "/" in self.target_input:
                network = ipaddress.ip_network(self.target_input, strict=False)
                target_list = [str(ip) for ip in network.hosts()]
            else:
                target_list = [self.target_input]
        except ValueError:
            self.log_signal.emit(f"[Error] IP 형식이 올바르지 않습니다.")
            self.finish_signal.emit("입력 오류")
            return

        total_count = len(target_list)
        self.log_signal.emit(f"[*] 대상 식별 완료: {total_count}개 IP")
        self.started_signal.emit(total_count)

        # asset_id 저장용 dict (ip -> asset_id)
        self.asset_ids = {}

        # DB Writer 스레드 시작
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        processed_count = 0

        if self.mode == "NETWORK_SCAN":
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.process_single_ip, ip): ip for ip in target_list}

                for future in as_completed(futures):
                    if self.stop_flag:
                        executor.shutdown(wait=True)  # 완전 종료 대기
                        break
                    processed_count += 1
                    progress_percent = int((processed_count / total_count) * 100)
                    self.progress_signal.emit(progress_percent)

        elif self.mode == "AUDIT_VULN":
            self.log_signal.emit(f"[*] KISA 기반 정밀 보안 진단 시작 ({total_count} Hosts)...")
            for ip in target_list:
                if self.stop_flag:
                    break
                try:
                    inspector = SSHInspector(ip, username=self.user, password=self.pw, port=22)
                    if inspector.connect():
                        self.log_signal.emit(f"[+] SSH 접속 성공: {ip} -> 진단 수행 중...")
                        results = inspector.run_all_checks()

                        db = DBConnector()
                        asset_id = db.save_asset(ip, hostname="Audit_Target", os_type="Linux")
                        if asset_id:
                            self.asset_ids[ip] = asset_id
                            save_count = 0
                            for code, (status, detail) in results.items():
                                success = db.save_scan_result(asset_id, code, status, detail)
                                if success:
                                    save_count += 1
                                    if status in ["VULNERABLE", "취약"]:
                                        self.log_signal.emit(f"    ⚠️ [{code}] 취약: {detail}")
                                    else:
                                        self.log_signal.emit(f"    ✅ [{code}] 양호: {detail}")
                            self.log_signal.emit(f"    -> {ip} 진단 완료. (저장된 항목: {save_count}개)")
                        inspector.close()
                        db.conn.close()  # AUDIT 모드는 별도 DB 연결 사용
                    else:
                        self.log_signal.emit(f"[-] SSH 접속 실패: {ip}")
                except Exception as e:
                    self.log_signal.emit(f"[Error] {ip} 진단 중 예외 발생: {str(e)}")

                processed_count += 1
                progress_percent = int((processed_count / total_count) * 100)
                self.progress_signal.emit(progress_percent)

        # 작업 종료 후 Queue 비우기
        self.writer_stop = True
        if self.writer_thread:
            self.writer_thread.join(timeout=5)  # 최대 5초 대기

        if self.stop_flag:
            self.finish_signal.emit("작업이 강제 중단되었습니다.")
        else:
            self.finish_signal.emit("모든 작업이 완료되었습니다.")

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