# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import threading
import queue
import socket
import ipaddress
import os
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
# 기존 core 및 utils 모듈 import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from core.windows_inspector import WindowsInspector
from core.vuln_matcher import VulnMatcher
from utils.db_connector import DBConnector
from utils.logger import AppLogger

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
        # [Fix] DB 쓰기 전담 소비자 스레드 (안전 버전)
        db = DBConnector()
        while True:
            try:
                # 1. 큐에서 데이터 가져오기 (타임아웃 설정으로 무한 대기 방지)
                try:
                    item = self.db_queue.get(timeout=1)
                except queue.Empty:
                    continue # 데이터 없으면 루프 재시작

                # 2. 종료 신호 확인
                if item is None:
                    self.db_queue.task_done()
                    break 
                
                # 3. 데이터 처리
                msg_type, data = item
                
                try:
                    if msg_type == "ASSET":
                        # [중요] 데이터 언패킹 (mac_addr 포함 확인)
                        ip, host, os_type, mac = data
                        asset_id = db.save_asset(ip, hostname=host, os_type=os_type, mac_addr=mac)
                        if asset_id: self.asset_ids[ip] = asset_id

                    elif msg_type == "PORT":
                        ip, port, banner = data
                        if ip in self.asset_ids: db.save_open_port(self.asset_ids[ip], port, banner)

                    elif msg_type == "VULN":
                        ip, v_info = data
                        if ip in self.asset_ids:
                            db.save_scan_result(self.asset_ids[ip], v_info['kisa'], 
                                "WARNING" if v_info['risk'] in ['Medium', 'Low'] else "VULNERABLE",
                                v_info['desc'], v_info['name'], v_info.get('remediation', '-'))

                    elif msg_type == "RESULT":
                        ip, code, status, detail, name, remediation = data
                        if ip in self.asset_ids:
                            db.save_scan_result(self.asset_ids[ip], code, status, detail, name, remediation)
                
                except Exception as inner_e:
                    AppLogger.log_error(f"DB Processing Error ({msg_type})", inner_e)

                finally:
                    # [핵심] 데이터를 성공적으로 꺼냈을 때만 완료 처리 (위치 이동됨)
                    self.db_queue.task_done()

            except Exception as e:
                AppLogger.log_error("DB Writer Fatal Error", e)

    def process_network_scan(self, ip):
        # 최신 DB Writer 형식에 맞춰 데이터 전송하도록 수정
        if self.stop_flag: return
        
        try:
            scanner = AdvancedScanner()
            # 1. 호스트 식별 (MAC 주소 확보)
            is_alive, os_type, mac, vendor = scanner.host_discovery(ip)
            
            if not is_alive:
                return

            # 호스트네임 조회 시도
            hostname = "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except: 
                pass
            self.db_queue.put(("ASSET", (ip, hostname, os_type, mac)))

            try:
                open_ports = scanner.tcp_scan(ip, self.ports)
            except Exception as e:
                # 화면에 빨간색으로 에러 표시
                self.log_signal.emit(f"[!] {ip} 포트 스캔 실패: {str(e)}") 
                # 파일 로그에 상세 기록
                AppLogger.log_error(f"Port Scan Error on {ip}", e) 
                open_ports = []
            
            port_str = "None"
            
            if open_ports:
                port_str = ", ".join(map(str, open_ports))
                
                # UI 알림 (MAC/Vendor 정보 포함)
                vendor_info = f"{mac} ({vendor})" if mac else "Unknown"
                self.log_signal.emit(f"[+] 발견: {ip} ({vendor}) ({os_type}) | Ports: {port_str}")
                
                for port in open_ports:
                    banner = scanner.grab_banner(ip, port)
                    
                    self.db_queue.put(("PORT", (ip, port, banner)))
                    
                    # [추가] 취약점 매칭 (VulnMatcher) - 리포트에 취약점 정보 나오게 하려면 필요
                    try:
                        vuln = VulnMatcher.match(port, banner)
                        if vuln['found']:
                            self.db_queue.put(("VULN", (ip, vuln)))
                    except:
                        pass

            else:
                self.log_signal.emit(f"[+] 발견: {ip} ({os_type}) | Ports: None")

            # UI 업데이트용 시그널 전송
            full_info_os = f"{os_type} | {mac} ({vendor})"
            self.asset_found_signal.emit(ip, full_info_os, port_str)

        except Exception as e:
            self.log_signal.emit(f"[!] {ip} 스캔 오류: {str(e)}")
            AppLogger.log_error(f"Worker Error on {ip}", e)

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
                        
                        # (상태, 상세내용, 항목명, 조치방안) 4개 튜플 구조로 변경
                        # 아까 VulnMatcher에 추가한 'remediation'을 여기서 DB로 전달해야 리포트에 나옴
                        vuln_results[v_info['kisa']] = (
                            status, 
                            f"[Port {v_info['service']}] {v_info['desc']}", 
                            v_info['name'],      # 항목명
                            v_info['remediation'] # 조치 방안 추가됨
                        )
                        
                        self.log_signal.emit(f"    🚨 외부 취약점 발견: {v_info['service']} ({v_info['kisa']})")

            # 외부 진단 결과가 있으면 먼저 DB 저장
            if vuln_results:
                self._save_results_to_db(ip, "Audit_Target", "Unknown", vuln_results)

        except Exception as e:
            self.log_signal.emit(f"[Warn] 포트 진단 중 오류: {e}")
            AppLogger.log_error(f"fail to port", e)
            

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
            AppLogger.log_error(f"Close SSH/WinRm", target_os)
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
            AppLogger.log_error(f"fail to inner scan ", e)

    def _detect_target_os(self, ip):
        #대상 OS 탐지
        def check_port(target_ip, port):
            try:
                with socket.create_connection((target_ip, port), timeout=2):
                    return True
            except:
                AppLogger.log_error(f"fail to scan os", ip)
                return False

        if check_port(ip, 5985):
            return "Windows"
        elif check_port(ip, 22):
            return "Linux"
        return "Unknown"

    def _audit_windows(self, ip):
        #Windows 시스템 진단
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
        #메인 실행 루프
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

        try:
            self.started_signal.emit(total_count)
            self.asset_ids = {}
            
            # DB Writer 스레드 시작
            self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
            self.writer_thread.start()

            processed_count = 0
            work_func = self.process_network_scan if self.mode == "NETWORK_SCAN" else self.process_audit_scan
            cur_threads = self.max_threads if self.mode == "NETWORK_SCAN" else self.audit_threads

            # 스레드 풀 실행
            with ThreadPoolExecutor(max_workers=cur_threads) as executor:
                # [메모리 최적화] 제너레이터를 리스트로 즉시 변환하지 않고 사용
                # 단, progress 표시를 위해 futures 딕셔너리는 필요함
                futures = {executor.submit(work_func, str(ip)): str(ip) for ip in target_gen}
                
                for future in as_completed(futures):
                    ip = futures[future]
                    
                    if self.stop_flag:
                        # [Fix] 중단 시 잔여 작업 취소 시도
                        executor.shutdown(wait=False, cancel_futures=True)
                        self.log_signal.emit("[!] 사용자 요청에 의해 스캔 중단됨.")
                        break
                    try:
                        future.result()
                    except Exception as e:
                    # 에러가 발생했다면 로그에 기록 
                        error_msg = f"[Thread Error] {ip} 처리 중 오류 발생: {e}"
                        AppLogger.log_error(error_msg)
                    processed_count += 1
                    # 진행률 업데이트 (부하를 줄이기 위해 1% 단위 또는 5건 단위로 갱신)
                    if total_count > 0 and (processed_count % 5 == 0 or processed_count >= total_count):
                        progress = int((processed_count / total_count) * 100)
                        self.progress_signal.emit(progress)

            if not self.stop_flag:
                self.progress_signal.emit(100)
        
        except Exception as e:
            # 예상치 못한 엔진 에러 캡처
            critical_msg = f"[Critical] 엔진 실행 중 오류 발생: {str(e)}"
            self.log_signal.emit(critical_msg)
            AppLogger.log_critical(critical_msg)
        
        finally:
            # [Fix] DB Writer 안전 종료 (Sentinel 패턴)
            # 큐에 None을 넣어야 db_writer의 get()이 깨어나서 루프를 종료함
            self.db_queue.put(None)
            
            if self.writer_thread:
                self.writer_thread.join(timeout=3)
                if self.writer_thread.is_alive():
                    AppLogger.log_error("DB Writer thread did not terminate cleanly.")
            
            self.finish_signal.emit("작업 완료")
