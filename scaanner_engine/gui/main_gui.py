import sys
import os
import traceback
import ipaddress
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from PyQt5.QtWidgets import (
                                QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                QTextEdit, QMessageBox, QGroupBox
                            )
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
# 우리가 만든 모듈 import
from core.advanced_scanner import AdvancedScanner
from core.audit_runner import run_server_audit, DBConnector
from core.ssh_inspector import SSHInspector
from output.pdf_report import PDFGenerator

def my_exception_hook(exctype, value, tb):
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    print(error_msg)  # 콘솔에도 출력
    # GUI로 에러 팝업 띄우기 (QApplication이 실행 중일 때만)
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText("치명적인 오류 발생")
    msg.setInformativeText(str(value))
    msg.setDetailedText(error_msg)
    msg.setWindowTitle("Error")
    msg.exec_()
# 기존의 기본 에러 처리기를 우리의 '안전장치'로 교체
sys.excepthook = my_exception_hook
# --- [백그라운드 워커 스레드] ---
# GUI가 멈추지 않게 스캔 로직을 별도 스레드로 분리합니다.
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)     
    finish_signal = pyqtSignal(str)  

    def __init__(self, mode, target_input, user=None, pw=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input # 변수명 변경 (ip -> input)
        self.user = user
        self.pw = pw
        self.stop_flag = False # 스캔 중단 기능 대비

    def run(self):
        self.log_signal.emit(f"[*] 작업 시작: {self.mode}")
        
        # 1. 대상 IP 리스트 생성 (단일 IP or CIDR 대역)
        target_list = []
        try:
            if "/" in self.target_input: # CIDR 표기법 (예: 192.168.0.0/24)
                network = ipaddress.ip_network(self.target_input, strict=False)
                # 네트워크 주소와 브로드캐스트 주소 제외하고 호스트만 추출
                target_list = [str(ip) for ip in network.hosts()]
                self.log_signal.emit(f"[*] 네트워크 대역 감지: {len(target_list)}개 호스트 스캔 예정")
            else:
                target_list = [self.target_input]
        except ValueError:
            self.log_signal.emit(f"[Error] 잘못된 IP 주소 형식입니다: {self.target_input}")
            self.finish_signal.emit("입력 오류")
            return

        try:
            if self.mode == "NETWORK_SCAN":
                scanner = AdvancedScanner()
                db = DBConnector()
                
                # 생성된 IP 리스트를 순회하며 스캔
                for ip in target_list:
                    if self.stop_flag: break # 중단 로직 (추후 버튼 연결 가능)
                    
                    # 진행 상황 로그 (너무 많으면 생략 가능)
                    # self.log_signal.emit(f"Checking {ip}...") 

                    # 1. 생존 확인
                    is_alive, os_type = scanner.host_discovery(ip)
                    
                    if is_alive:
                        self.log_signal.emit(f"[+] 호스트 발견: {ip} (OS: {os_type})")
                        
                        # 2. 포트 스캔
                        open_ports = scanner.syn_scan(ip)
                        if open_ports:
                            self.log_signal.emit(f"    ㄴ Open Ports: {open_ports}")
                        
                        # 3. 배너 그래빙 및 DB 저장
                        # 자산 먼저 저장 (Upsert)
                        asset_id = db.save_asset(ip, hostname="Scanned_Asset", os_type=os_type)
                        
                        for port in open_ports:
                            banner = scanner.grab_banner(ip, port)
                            db.save_open_port(asset_id, port, banner)
                            # self.log_signal.emit(f"       Port {port}: {banner}")

                self.log_signal.emit("[DB] 스캔 완료 및 저장 종료")

            elif self.mode == "AUDIT_VULN":
                # 취약점 진단은 보통 특정 타겟에 하므로 단일 IP만 지원하거나, 
                # 반복문으로 돌릴 수 있으나 시간이 오래 걸림. 여기선 리스트 첫 번째만 수행하거나 반복 지원.
                
                self.log_signal.emit(f"[*] 총 {len(target_list)}대 서버에 대한 취약점 진단 시도...")
                
                for ip in target_list:
                    inspector = SSHInspector(ip, username=self.user, password=self.pw)
                    if inspector.connect():
                        self.log_signal.emit(f"[+] SSH 연결 성공: {ip}")
                        status, detail = inspector.check_u01_root_login()
                        self.log_signal.emit(f"    [{ip}] U-01 결과: {status}")
                        
                        db = DBConnector()
                        asset_id = db.save_asset(ip, hostname="Audit_Target", os_type="Linux")
                        db.save_scan_result(asset_id, "U-01", status, detail)
                        inspector.close()
                    else:
                        self.log_signal.emit(f"[-] SSH 연결 실패: {ip}")

        except Exception as e:
            self.log_signal.emit(f"[Error] {str(e)}")
        
        self.finish_signal.emit("작업이 완료되었습니다.")

# --- [메인 윈도우 UI] ---
class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Asset-Watch Security Platform')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #f0f0f0;")

        # 메인 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        # 1. 상단 타이틀
        title_label = QLabel("지능형 취약점 진단 시스템 (Control Panel)")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # 2. 입력 그룹 (타겟 정보)
        input_group = QGroupBox("Target Configuration")
        input_layout = QHBoxLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Target IP (ex: 192.168.0.10)")
        
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("SSH User (root)")
        
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("SSH Password")
        self.pw_input.setEchoMode(QLineEdit.Password)

        input_layout.addWidget(QLabel("IP Address:"))
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(QLabel("User:"))
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(QLabel("PW:"))
        input_layout.addWidget(self.pw_input)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 3. 버튼 그룹
        btn_layout = QHBoxLayout()
        
        self.btn_scan = QPushButton("🔍 네트워크 스캔 (Port Scan)")
        self.btn_scan.setMinimumHeight(40)
        self.btn_scan.setStyleSheet("background-color: #007bff; color: white; font-weight: bold;")
        self.btn_scan.clicked.connect(self.start_network_scan)
        
        self.btn_audit = QPushButton("🛡️ 취약점 정밀진단 (SSH Audit)")
        self.btn_audit.setMinimumHeight(40)
        self.btn_audit.setStyleSheet("background-color: #dc3545; color: white; font-weight: bold;")
        self.btn_audit.clicked.connect(self.start_audit)

        self.btn_pdf = QPushButton("📄 PDF 리포트 생성")
        self.btn_pdf.setMinimumHeight(40)
        self.btn_pdf.setStyleSheet("background-color: #28a745; color: white; font-weight: bold;")
        self.btn_pdf.clicked.connect(self.generate_pdf)
        
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        layout.addLayout(btn_layout)

        # 4. 로그 콘솔
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        layout.addWidget(QLabel("Execution Logs:"))
        layout.addWidget(self.log_console)
        central_widget.setLayout(layout)


    def log_message(self, msg):
        self.log_console.append(msg)

    def scan_finished(self, msg):
        QMessageBox.information(self, "완료", msg)
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)

    def start_network_scan(self):
        ip = self.ip_input.text()
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력하세요.")
            return
        
        self.log_console.clear()
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)
        
        # 워커 스레드 시작
        self.worker = ScanWorker("NETWORK_SCAN", ip)
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.start()

    def start_audit(self):
        ip = self.ip_input.text()
        user = self.user_input.text()
        pw = self.pw_input.text()
        
        if not ip or not user or not pw:
            QMessageBox.warning(self, "경고", "SSH 진단을 위해 IP, 계정, 비밀번호가 모두 필요합니다.")
            return

        self.log_console.clear()
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)

        # 워커 스레드 시작
        self.worker = ScanWorker("AUDIT_VULN", ip, user=user, pw=pw)
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.start()
    def generate_pdf(self):
        import subprocess
        import sys
        import os

        try:
            self.log_message("[System] PDF 리포트 생성을 요청합니다...")
            
            # 1. 실행할 파일의 절대 경로 찾기
            # 현재 main_gui.py가 있는 폴더에서 -> 상위 폴더(scanner_engine) -> output -> pdf_report.py
            current_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(os.path.dirname(current_dir), 'output', 'pdf_report.py')
            
            # 2. subprocess로 실행 (터미널에서 python ... 입력하는 것과 동일한 효과)
            # GUI가 멈추지 않게 별도 프로세스로 실행합니다.
            if os.name == 'nt': # 윈도우의 경우
                # creationflags=0x08000000 (CREATE_NO_WINDOW)를 쓰면 검은 창 없이 실행 가능하지만
                # 디버깅을 위해 일단 기본값으로 둡니다.
                process = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
            else: # 맥/리눅스
                process = subprocess.run([sys.executable, script_path], capture_output=True, text=True)

            # 3. 결과 확인
            if process.returncode == 0:
                self.log_message("[Success] " + process.stdout.strip()) # "Report Generated..." 메시지 출력
                QMessageBox.information(self, "성공", "PDF 리포트가 성공적으로 생성되었습니다.\n프로젝트 폴더를 확인하세요.")
            else:
                # 에러가 났다면 그 이유를 로그창에 출력
                error_msg = process.stderr.strip()
                self.log_message(f"[Error] 생성 실패: {error_msg}")
                QMessageBox.warning(self, "실패", f"PDF 생성 중 에러가 발생했습니다:\n{error_msg}")

        except Exception as e:
            self.log_message(f"[Critical] 실행 오류: {str(e)}")
            QMessageBox.critical(self, "에러", str(e))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())