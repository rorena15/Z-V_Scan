# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import sys
import os
import traceback
import ipaddress

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

# [수정] 정확한 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from utils.db_connector import DBConnector  # [중요] utils에서 직접 가져옴
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

    def __init__(self, mode, target_input, user=None, pw=None, key_path=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user = user
        self.pw = pw
        self.stop_flag = False 
        self.max_threads = 50
        self.key_path = key_path
        
    def process_single_ip(self, ip):
        """[네트워크 스캔] 포트 스캔 및 자산 식별"""
        if self.stop_flag: return

        scanner = AdvancedScanner()
        db = None 

        try:
            is_alive, os_type = scanner.host_discovery(ip)

            if is_alive:
                # DB 연결
                db = DBConnector()
                
                # [DB] 자산 정보 저장
                asset_id = db.save_asset(ip, hostname="Scanned_Asset", os_type=os_type)

                # 포트 스캔
                open_ports = scanner.syn_scan(ip)
                if open_ports:
                    port_str = ", ".join(map(str, open_ports))
                    self.log_signal.emit(f"[+] {ip} ({os_type}) -> Ports: {port_str}")
                
                    # [DB] 포트 정보 저장
                    for port in open_ports:
                        banner = scanner.grab_banner(ip, port)
                        db.save_open_port(asset_id, port, banner)

        except Exception as e:
            pass # 로그 너무 많아 생략
            
        finally:
            if db and hasattr(db, 'create_connection'): # DBConnector 안전 종료
                pass # SQLite는 with문이나 명시적 close가 필요 없을 수도 있으나, 커넥터 구현에 따름

    def run(self):
        self.log_signal.emit(f"[*] 스캔 엔진 가동 (Max Threads: {self.max_threads})...")
        
        target_list = []
        try:
            if "/" in self.target_input: 
                network = ipaddress.ip_network(self.target_input, strict=False)
                target_list = [str(ip) for ip in network.hosts()]
                self.log_signal.emit(f"[*] 대상 네트워크 로드 완료: {len(target_list)}개 IP")
            else:
                target_list = [self.target_input]
        except ValueError:
            self.log_signal.emit(f"[Error] IP 형식이 올바르지 않습니다.")
            self.finish_signal.emit("입력 오류")
            return

        total_count = len(target_list)
        processed_count = 0
        self.progress_signal.emit(0)

        # --- [모드 1] 네트워크 스캔 (Port Scan) ---
        if self.mode == "NETWORK_SCAN":
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.process_single_ip, ip): ip for ip in target_list}
                
                for future in as_completed(futures):
                    if self.stop_flag:
                        executor.shutdown(wait=False)
                        break 
                    processed_count += 1
                    if processed_count % 5 == 0 or processed_count == total_count:
                        self.progress_signal.emit(int((processed_count / total_count) * 100))

        # --- [모드 2] 취약점 정밀 진단 (Audit) ---
        elif self.mode == "AUDIT_VULN":
            self.log_signal.emit(f"[*] KISA 기반 정밀 보안 진단 시작 ({len(target_list)} Hosts)...")
            
            for ip in target_list:
                if self.stop_flag: break
                
                try:
                    # 1. SSH 연결 시도
                    inspector = SSHInspector(ip, username=self.user, password=self.pw, port=22)
                    if inspector.connect():
                        self.log_signal.emit(f"[+] SSH 접속 성공: {ip} -> 진단 수행 중...")
                        
                        # 2. 전체 진단 수행
                        results = inspector.run_all_checks()
                        
                        # 3. DB 저장
                        db = DBConnector()
                        # 자산 ID 확보 (중요)
                        asset_id = db.save_asset(ip, hostname="Audit_Target", os_type="Linux")
                        
                        if not asset_id:
                            self.log_signal.emit(f"[Error] DB 자산 등록 실패: {ip}")
                            continue

                        save_count = 0
                        for code, (status, detail) in results.items():
                            # [핵심] 결과 저장 호출
                            success = db.save_scan_result(asset_id, code, status, detail)
                            
                            if success:
                                save_count += 1
                                if status == "VULNERABLE" or status == "취약":
                                    self.log_signal.emit(f"    ⚠️ [{code}] 취약: {detail}")
                                else:
                                    self.log_signal.emit(f"    ✅ [{code}] 양호: {detail}")
                            else:
                                self.log_signal.emit(f"    [!] DB 저장 실패: {code} (DBConnector 확인 필요)")

                        self.log_signal.emit(f"    -> {ip} 진단 완료. (저장된 항목: {save_count}개)")
                        inspector.close()

                    else:
                        self.log_signal.emit(f"[-] SSH 접속 실패: {ip} (계정/방화벽/시뮬레이션 모드 확인)")
                
                except Exception as e:
                    self.log_signal.emit(f"[Error] {ip} 진단 중 예외 발생: {str(e)}")

                processed_count += 1
                self.progress_signal.emit(int((processed_count / total_count) * 100))

        if self.stop_flag:
            self.finish_signal.emit("작업이 강제 중단되었습니다.")
        else:
            self.finish_signal.emit("모든 작업이 완료되었습니다.")

# --- [메인 윈도우 UI] ---
class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Z-Vul Security Platform')
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
                background-color: #ff9800; /* 활성화(True) 상태: 주황색 */
                color: white;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:disabled {
                background-color: #dddddd; /* 비활성화(False) 상태: 회색 */
                color: #888888;            /* 텍스트도 흐리게 */
                border: 1px solid #cccccc;
            }
            QPushButton:hover {
                background-color: #e68900; /* 마우스 올렸을 때: 진한 주황 */
            }
            QPushButton:pressed {
                background-color: #cc7a00; /* 눌렀을 때: 더 진한 색 */
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
        # 1. 시간 표시 라벨 (우측 정렬)
        self.time_label = QLabel("Ready")
        self.time_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.time_label.setStyleSheet("color: #555; font-weight: bold; font-size: 12px;")
        progress_layout.addWidget(self.time_label)

        # 2. 프로그레스 바 (기존 코드 유지하되 스타일 조금 다듬기)
        self.pbar = QProgressBar(self)
        self.pbar.setValue(0)
        self.pbar.setTextVisible(True) # 퍼센트 글자 보이기
        self.pbar.setFormat("%p%")     # 포맷 설정 (기본값)
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
        
        layout.addLayout(progress_layout) # 메인 레이아웃에 추가
        
        # 로그 콘솔
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        layout.addWidget(QLabel("Execution Logs:"))
        layout.addWidget(self.log_console)
        central_widget.setLayout(layout)
        
        #타이머 설정
        self.timer = QTimer(self)
        self.timer.setInterval(1000) # 1000ms = 1초
        self.timer.timeout.connect(self.update_timer_display)
        self.elapsed_seconds = 0
        
    def update_timer_display(self):
        self.elapsed_seconds += 1
        
        # 초 -> 분:초 변환
        minutes = self.elapsed_seconds // 60
        seconds = self.elapsed_seconds % 60
        
        # 텍스트 갱신 (예: ⏱️ 진행 시간: 02:15)
        self.time_label.setText(f"진행 시간: {minutes:02d}:{seconds:02d}")
        
    def update_progress(self, val):
        self.pbar.setValue(val)

    def log_message(self, msg):
        self.log_console.append(msg)

    def scan_finished(self, msg):
        self.timer.stop() # [중요] 타이머 멈춤
        final_min = self.elapsed_seconds // 60
        final_sec = self.elapsed_seconds % 60
        self.time_label.setText(f"완료 (소요 시간: {final_min:02d}:{final_sec:02d})")
        QMessageBox.information(self, "완료", msg)
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        self.btn_pdf.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def start_network_scan(self):
        ip = self.ip_input.text()
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력하세요.")
            return
        self.reset_ui_state()
        self.elapsed_seconds = 0
        self.time_label.setText("진행 시간: 00:00")
        self.timer.start() # 타이머 START
        
        self.worker = ScanWorker("NETWORK_SCAN", ip)
        self.connect_worker()
        self.worker.start()

    def start_audit(self):
        ip = self.ip_input.text()
        user = self.user_input.text()
        pw = self.pw_input.text()
        key = self.key_input.text() # 키 입력 추가
        
        # 시뮬레이션 모드 테스트를 위해 IP가 localhost면 user/pw 검사 생략 가능
        if ip not in ["127.0.0.1", "localhost"] and (not user or not pw):
            QMessageBox.warning(self, "경고", "실제 서버 진단을 위해 계정/비밀번호가 필요합니다.\n(localhost 입력 시 시뮬레이션 모드 동작)")
            # 테스트 편의를 위해 리턴하지 않고 진행할 수도 있음 (여기선 리턴)
            # return 

        self.reset_ui_state()
        self.elapsed_seconds = 0
        self.time_label.setText("진행 시간: 00:00")
        self.timer.start() # 타이머 START
        
        self.worker = ScanWorker("AUDIT_VULN", ip, user=user, pw=pw, key_path=key)
        self.connect_worker()
        self.worker.start()

    def generate_pdf(self):
        import subprocess
        try:
            self.log_message("[System] PDF 리포트 생성을 요청합니다...")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(os.path.dirname(current_dir), 'output', 'pdf_report.py')
            
            # 윈도우 검은창 숨기기
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
            self.timer.stop() # 중지 시에도 타이머 멈춤
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
        
    def closeEvent(self, event):
        #[안전 종료] 창 닫기(X) 버튼을 눌렀을 때 호출됩니다.
        #실행 중인 스레드가 있다면 멈추고 기다린 후 종료합니다.
        # 워커 스레드가 존재하고, 현재 실행 중이라면
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.log_message("[System] 프로그램 종료 요청. 스레드를 정리 중입니다...")
            
            # 1. 스레드에게 멈추라고 신호 보냄
            self.worker.stop_flag = True
            
            # 2. 스레드가 루프를 빠져나와 run()이 끝날 때까지 기다림 (Blocking)
            # wait()를 안 하면 바로 종료되면서 에러가 다시 뜹니다.
            # 2000ms(2초) 동안 기다려보고 안 꺼지면 강제 종료 (GUI 멈춤 방지)
            if not self.worker.wait(2000):
                self.worker.terminate() # 2초 뒤에도 안 꺼지면 강제 종료 (최후의 수단)
                
        # 3. 안전하게 이벤트 수락 (창 닫기 진행)
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())