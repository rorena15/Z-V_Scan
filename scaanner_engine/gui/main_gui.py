import sys
import os
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
# --- [백그라운드 워커 스레드] ---
# GUI가 멈추지 않게 스캔 로직을 별도 스레드로 분리합니다.
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)     # 로그 출력을 위한 신호
    finish_signal = pyqtSignal(str)  # 작업 완료 신호

    def __init__(self, mode, target_ip, user=None, pw=None):
        super().__init__()
        self.mode = mode
        self.target_ip = target_ip
        self.user = user
        self.pw = pw

    def run(self):
        self.log_signal.emit(f"[*] 작업 시작: {self.mode} -> {self.target_ip}")
        
        try:
            if self.mode == "NETWORK_SCAN":
                scanner = AdvancedScanner()
                # 스캐너의 print 출력을 GUI 로그로 보내기 위해 로직을 약간 변형하거나
                # 여기서는 결과만 요약해서 보여주는 방식을 사용
                
                # 1. 생존 확인
                is_alive, os_type = scanner.host_discovery(self.target_ip)
                if is_alive:
                    self.log_signal.emit(f"[+] 호스트 발견: {self.target_ip} (OS: {os_type})")
                    
                    # 2. 포트 스캔
                    open_ports = scanner.syn_scan(self.target_ip)
                    self.log_signal.emit(f"[+] 열린 포트: {open_ports}")
                    
                    # 3. 배너 그래빙
                    for port in open_ports:
                        banner = scanner.grab_banner(self.target_ip, port)
                        self.log_signal.emit(f"    - Port {port}: {banner}")
                    
                    # DB 저장은 기존 모듈 활용
                    db = DBConnector()
                    asset_id = db.save_asset(self.target_ip, hostname="Scanned_GUI", os_type=os_type)
                    for port in open_ports:
                        db.save_open_port(asset_id, port, "Checked via GUI")
                    self.log_signal.emit("[DB] 자산 및 포트 정보 저장 완료")
                    
                else:
                    self.log_signal.emit("[-] 호스트가 응답하지 않습니다.")

            elif self.mode == "AUDIT_VULN":
                self.log_signal.emit("[*] 서버 취약점 진단(SSH) 시작...")
                inspector = SSHInspector(self.target_ip, username=self.user, password=self.pw)
                
                if inspector.connect():
                    self.log_signal.emit("[+] SSH 연결 성공")
                    
                    # U-01 점검
                    status, detail = inspector.check_u01_root_login()
                    self.log_signal.emit(f"[결과] U-01 (Root접속제한): {status}")
                    self.log_signal.emit(f"      ㄴ 상세: {detail}")
                    
                    # DB 저장
                    db = DBConnector()
                    asset_id = db.save_asset(self.target_ip, hostname="Audit_Target", os_type="Linux")
                    db.save_scan_result(asset_id, "U-01", status, detail)
                    self.log_signal.emit("[DB] 진단 결과 저장 완료")
                    
                    inspector.close()
                else:
                    self.log_signal.emit("[-] SSH 연결 실패. 아이디/비번을 확인하세요.")

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
        try:
            gen = PDFGenerator()
            filename = gen.generate_report()
            self.log_message(f"[Report] PDF 문서가 생성되었습니다: {filename}")
            QMessageBox.information(self, "성공", f"리포트 생성 완료!\n파일: {filename}")
        except Exception as e:
            QMessageBox.critical(self, "에러", str(e))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())