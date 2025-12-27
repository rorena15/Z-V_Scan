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
                                QTextEdit, QMessageBox, QGroupBox, QProgressBar
                            )
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
# 우리가 만든 모듈 import
from core.advanced_scanner import AdvancedScanner
from core.audit_runner import run_server_audit, DBConnector
from core.ssh_inspector import SSHInspector
from output.pdf_report import PDFGenerator
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# 기존의 기본 에러 처리기를 '안전장치'로 교체
sys.excepthook = my_exception_hook

# --- [백그라운드 워커 스레드] ---
# GUI가 멈추지 않게 스캔 로직을 별도 스레드로 분리합니다.

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
        """
        [멀티스레드용] 단일 IP 스캔 작업
        """
        if self.stop_flag: return

        # 스레드마다 독립적인 객체 생성
        scanner = AdvancedScanner()
        db = None # DB 객체 초기화

        try:
            # 1. 생존 확인 (ICMP/TCP Ping)
            is_alive, os_type = scanner.host_discovery(ip)

            if is_alive:
                # [최적화 2] 로그 다이어트: 발견된 것만 간결하게
                # self.log_signal.emit(f"[+] 발견: {ip} ({os_type})") -> 너무 잦으면 생략 가능
                
                # DB 연결 (필요할 때만 연결)
                db = DBConnector()
                
                # 자산 정보 저장
                asset_id = db.save_asset(ip, hostname="Scanned_Asset", os_type=os_type)

                # 2. 포트 스캔
                open_ports = scanner.syn_scan(ip)
                if open_ports:
                    # 포트가 발견되었을 때만 로그 전송 (GUI 부하 감소)
                    port_str = ", ".join(map(str, open_ports))
                    self.log_signal.emit(f"[+] {ip} ({os_type}) -> Ports: {port_str}")
                
                    # 3. 배너 그래빙 및 저장
                    for port in open_ports:
                        banner = scanner.grab_banner(ip, port)
                        db.save_open_port(asset_id, port, banner)

        except Exception as e:
            # 에러 발생 시 로그는 남기되 멈추지 않음
            # print(f"Error on {ip}: {e}") # 디버깅용
            pass
            
        finally:
            # [최적화 3] DB 연결 확실하게 종료 (Resource Leak 방지)
            if db:
                try:
                    # DBConnector에 close 메서드가 있다면 호출, 없다면 conn.close() 확인 필요
                    # 여기서는 db_connector.py의 구현에 따라 다르지만, 보통 소멸자나 명시적 close 필요
                    # 만약 DBConnector에 close()가 없다면 추가해야 함.
                    if hasattr(db, 'conn') and db.conn:
                        db.conn.close()
                except:
                    pass

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

        # --- NETWORK_SCAN 모드 ---
        if self.mode == "NETWORK_SCAN":
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.process_single_ip, ip): ip for ip in target_list}
                
                # 결과 모니터링
                for future in as_completed(futures):
                    # 비상 정지 체크
                    if self.stop_flag:
                        self.log_signal.emit("[!!!] 중지 신호 감지. 작업을 취소합니다...")
                        executor.shutdown(wait=False)
                        break 
                    
                    processed_count += 1
                    
                    # [최적화 4] UI 업데이트 빈도 조절 (Throttling)
                    # 매번 업데이트하면 GUI가 굳어버림. 5개 처리할 때마다 or 마지막에만 업데이트
                    if processed_count % 5 == 0 or processed_count == total_count:
                        progress = int((processed_count / total_count) * 100)
                        self.progress_signal.emit(progress)

        # --- AUDIT_VULN 모드 ---
        elif self.mode == "AUDIT_VULN":
            self.log_signal.emit(f"[*] KISA 기반 정밀 보안 진단 시작 ({len(target_list)} Hosts)...")
            
            for ip in target_list:
                if self.stop_flag: 
                    self.log_signal.emit("[!!!] 진단 중지됨.")
                    break
                
                try:
                    inspector = SSHInspector(ip, username=self.user, password=self.pw, key_path=self.key_path)
                    if inspector.connect():
                        self.log_signal.emit(f"[+] SSH 접속 성공: {ip} -> 진단 수행 중...")
                        
                        # [핵심 변경] 하나씩 부르는 게 아니라, 전체 진단 함수 호출
                        results = inspector.run_all_checks()
                        
                        # DB 연결
                        db = DBConnector()
                        # 자산 테이블에 먼저 등록 (Audit Target)
                        asset_id = db.save_asset(ip, hostname="Audit_Target", os_type="Linux")
                        
                        # 결과 순회하며 저장
                        for code, (status, detail) in results.items():
                            db.save_scan_result(asset_id, code, status, detail)
                            
                            # 로그 출력 (안전한 것보다 취약한 것을 눈에 띄게)
                            if status == "VULNERABLE":
                                self.log_signal.emit(f"    ⚠️ [{code}] 취약: {detail}")
                            else:
                                self.log_signal.emit(f"    ✅ [{code}] 양호: {detail}")

                        inspector.close()
                        if hasattr(db, 'conn') and db.conn: db.conn.close()

                    else:
                        self.log_signal.emit(f"[-] SSH 접속 실패: {ip} (계정/방화벽 확인 필요)")
                
                except Exception as e:
                    self.log_signal.emit(f"[Error] {ip} 진단 중 오류: {str(e)}")

                processed_count += 1
                progress = int((processed_count / total_count) * 100)
                self.progress_signal.emit(progress)

        # 종료 처리
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
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("SSH Key Path (Optional)")
        
        
        input_layout.addWidget(QLabel("IP Address:"))
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(QLabel("User:"))
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(QLabel("PW:"))
        input_layout.addWidget(self.pw_input)
        input_group.setLayout(input_layout)
        input_layout.addWidget(QLabel("Key:"))
        input_layout.addWidget(self.key_input)
        layout.addWidget(input_group)

        # 3. 버튼 그룹
        btn_layout = QHBoxLayout()
        # 스캔 버튼
        self.btn_scan = QPushButton("🔍 네트워크 스캔 (Port Scan)")
        self.btn_scan.setMinimumHeight(40)
        self.btn_scan.setStyleSheet("background-color: #007bff; color: white; font-weight: bold;")
        self.btn_scan.clicked.connect(self.start_network_scan)
        # 정밀 진단 버튼
        self.btn_audit = QPushButton("🛡️ 취약점 정밀진단 (SSH Audit)")
        self.btn_audit.setMinimumHeight(40)
        self.btn_audit.setStyleSheet("background-color: #dc3545; color: white; font-weight: bold;")
        self.btn_audit.clicked.connect(self.start_audit)
        # 리포트 생성
        self.btn_pdf = QPushButton("📄 PDF 리포트 생성")
        self.btn_pdf.setMinimumHeight(40)
        self.btn_pdf.setStyleSheet("background-color: #28a745; color: white; font-weight: bold;")
        self.btn_pdf.clicked.connect(self.generate_pdf)
        # 비상 중지 버튼
        self.btn_stop = QPushButton("🛑 작업 중지 (STOP)")
        self.btn_stop.setMinimumHeight(40)
        # 평소에는 비활성화 (스캔 중에만 켜짐)
        self.btn_stop.setEnabled(False) 
        # 눈에 띄는 주황색/빨간색 스타일
        self.btn_stop.setStyleSheet("""
            QPushButton { background-color: #ff9800; color: white; font-weight: bold; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
        """)
        self.btn_stop.clicked.connect(self.stop_scan) # 함수 연결

        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_audit)
        btn_layout.addWidget(self.btn_pdf)
        btn_layout.addWidget(self.btn_stop) # <--- 여기에 추가
        layout.addLayout(btn_layout)

        # 3.1 프로그래스 바
        
        self.pbar = QProgressBar(self)
        self.pbar.setValue(0) # 0% 초기화
        self.pbar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #007bff; /* 파란색 채움 */
                width: 20px;
            }
        """)
        layout.addWidget(self.pbar) # 화면에 추가
        
        # 4. 로그 콘솔
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        layout.addWidget(QLabel("Execution Logs:"))
        layout.addWidget(self.log_console)
        central_widget.setLayout(layout)
        
    def update_progress(self, val):
        self.pbar.setValue(val)

    def log_message(self, msg):
        self.log_console.append(msg)

    def scan_finished(self, msg):
        QMessageBox.information(self, "완료", msg)
        #버튼 원상 복귀
        self.btn_scan.setEnabled(True)
        self.btn_audit.setEnabled(True)
        self.btn_pdf.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def start_network_scan(self):
        ip = self.ip_input.text()
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력하세요.")
            return
        
        self.log_console.clear()
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)
        self.btn_pdf.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)
        
        # 워커 스레드 시작
        self.worker = ScanWorker("NETWORK_SCAN", ip)
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.start()

    def start_audit(self):
        ip = self.ip_input.text()
        user = self.user_input.text()
        pw = self.pw_input.text()
        key = self.key_input.text()
        
        if not ip or not user or not pw:
            QMessageBox.warning(self, "경고", "SSH 진단을 위해 IP, 계정, 비밀번호가 모두 필요합니다.")
            return

        self.log_console.clear()
        self.btn_scan.setEnabled(False)
        self.btn_audit.setEnabled(False)
        self.btn_pdf.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pbar.setValue(0)

        # 워커 스레드 시작
        self.worker = ScanWorker("AUDIT_VULN", ip, user=user, pw=pw)
        self.worker.log_signal.connect(self.log_message)
        self.worker.finish_signal.connect(self.scan_finished)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker = ScanWorker("AUDIT_VULN", ip, user=user, pw=pw, key_path=key)
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
            
    def stop_scan(self):
        # 워커가 존재하고 실행 중이라면
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.log_message("[!!!] 사용자 요청에 의해 작업을 중단하고 있습니다... (잠시만 기다려주세요)")
            
            # 워커 내부의 플래그를 True로 변경 -> 스레드들이 작업을 멈춤
            self.worker.stop_flag = True
            
            # 중지 버튼 즉시 비활성화 (중복 클릭 방지)
            self.btn_stop.setEnabled(False)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())