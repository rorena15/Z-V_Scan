# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import threading
import ipaddress
import queue
import os
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal

# 경로 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# 모듈 Import
from core.advanced_scanner import AdvancedScanner
from core.ssh_inspector import SSHInspector
from core.windows_inspector import WindowsInspector
from core.vuln_matcher import VulnMatcher
from utils.db_connector import DBConnector
from utils.logger import AppLogger
from core.discovery import HostDiscovery
from utils.auth_token import get_engine_token, REAL_KEY

class ScanWorker(QThread):
    # UI 업데이트를 위한 시그널 정의
    log_signal = Signal(str)
    finish_signal = Signal(str)
    progress_signal = Signal(int, int)
    started_signal = Signal(int)
    asset_found_signal = Signal(str, str, str) # IP, Hostname, Memo

    def __init__(self, mode, target_input, user=None, ports=None, db_queue=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user_info = user if user else {}
        self.custom_ports = ports
        self.stop_flag = False
        self.db_queue = db_queue if db_queue else queue.Queue()
        self.writer_thread = None
        self.ports = ports
        self._security_token = get_engine_token()

    def stop(self):
        #스캔 중단 요청
        self.stop_flag = True
        self.log_signal.emit("[-] Stopping scan worker...")

    def db_writer(self):
        # DB 쓰기 전용 스레드
        db = DBConnector()
        while True:
            item = self.db_queue.get()
            if item is None: # 종료 신호
                break
            
            try:
                msg_type, data = item
                if msg_type == "ASSET":
                    # Data Unpacking: (ip, hostname, os_type, ports_str, mac_addr)
                    # 순서: 0=IP, 1=Host, 2=OS, 3=Ports, 4=Mac
                    db.save_asset(
                        data[0], 
                        hostname=data[1], 
                        os_type=data[2], 
                        open_ports=data[3],  # [수정] 포트 정보 전달
                        mac_addr=data[4]
                    )
                    
                elif msg_type == "SCAN_RESULT":
                    # data = (ip, code, name, risk, status, desc, remediation)
                    asset_id = db.get_asset_id(data[0])
                    if asset_id:
                        db.save_result(asset_id, data[1], data[2], data[3], data[4], data[5], data[6])
            except Exception as e:
                AppLogger.log_error("DB Writer Error", e)
            finally:
                self.db_queue.task_done()

    def parse_targets(self):
        #IP 대역 파싱 (CIDR, Range, Single IP)
        targets = []
        try:
            raw_list = self.target_input.split(',')
            for raw in raw_list:
                raw = raw.strip()
                if '/' in raw: # CIDR (192.168.1.0/24)
                    net = ipaddress.ip_network(raw, strict=False)
                    for ip in net.hosts():
                        targets.append(str(ip))
                elif '-' in raw: # Range (192.168.0.1-10)
                    parts = raw.split('-')
                    start_ip = parts[0]
                    end_part = parts[1]
                    if '.' not in end_part:
                        base = ".".join(start_ip.split('.')[:-1])
                        start_last = int(start_ip.split('.')[-1])
                        end_last = int(end_part)
                        for i in range(start_last, end_last + 1):
                            targets.append(f"{base}.{i}")
                    else:
                        targets.append(raw)
                else:
                    targets.append(raw)
        except Exception as e:
            self.log_signal.emit(f"[!] Target Parse Error: {e}")
            AppLogger.log_error("Target Parsing Failed", e)
        
        return sorted(list(set(targets)))

    def scan_target(self, ip):
        #[개별 IP 스캔 작업]
        if self.stop_flag: return
        
        # 스레드마다 독립적인 스캐너 인스턴스 생성 (Thread-Safe)
        scanner = AdvancedScanner()
        
        # 0. 호스트 상세 정보 재확인 (OS, MAC)
        is_alive, os_type, mac_addr, vendor = scanner.host_discovery(ip)
        
        hostname = "Unknown"
        if vendor != "Unknown":
            hostname = f"({vendor}) Device"
        
        # ----------------------------------------------------
        # [Phase 1] TCP Port Scan & Service Analysis
        # (구조 유지하되, DB 저장 전에 포트를 구하기 위해 순서만 위로 올림)
        # ----------------------------------------------------
        
        # [Fix 1] Full Scan 시 리스트 대신 range 사용 (메모리/에러 해결)
        if self.mode == "FULL" and self.ports is None:
            target_ports = range(1, 65536)
        elif self.ports: # __init__에서 받은 ports 사용
            target_ports = self.ports
        elif self.custom_ports: # 호환성 유지
            target_ports = scanner.parse_ports(self.custom_ports)
        else:
            target_ports = scanner.default_ports
            
        # 실제 스캔 수행
        open_ports = scanner.tcp_scan(ip, ports=target_ports)

        # [Fix 2] DB 저장을 위해 리스트 -> 문자열 변환
        ports_str = ""
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))

        # ----------------------------------------------------
        # [자산 정보 업데이트]
        # 포트 정보(ports_str)를 포함하여 DB에 저장
        # ----------------------------------------------------
        self.asset_found_signal.emit(ip, hostname, f"OS: {os_type}")
        
        # [Fix 3] ports_str 추가 (받는 쪽 db_writer에서 인자 5개로 맞춰야 함)
        self.db_queue.put(("ASSET", (ip, hostname, os_type, ports_str, mac_addr)))

        # ----------------------------------------------------
        # [스캔 결과 분석 및 저장]
        # ----------------------------------------------------
        if not open_ports:
            # 포트가 없으면 Ping만 되는 장비 (정보 기록)
            self.db_queue.put(("SCAN_RESULT", (ip, "INFO-00", "Host Alive", "Info", "Safe", "ICMP Ping Response Only", "-")))
        
        for port in open_ports:
            if self.stop_flag: break
            
            # 배너 수집 (Nmap -sV 기능)
            banner = scanner.grab_banner(ip, port)
            
            # 취약점 DB 매칭
            match_res = VulnMatcher.match(port, banner)
            
            status = "VULNERABLE" if match_res.get('risk') in ['High', 'Critical'] else "WARNING"
            if match_res.get('risk') == 'Info': status = "Safe"
            
            self.db_queue.put(("SCAN_RESULT", (
                ip, 
                f"TCP-{port}", 
                match_res.get('name', f"Open Port {port}"),
                match_res.get('risk', 'Low'),
                status,
                match_res.get('desc', banner),
                match_res.get('remediation', '-')
            )))

        # ----------------------------------------------------
        # [Phase 2] UDP Service Scan (Nmap -sU 기능)
        # ----------------------------------------------------
        # FAST 모드가 아닐 때만 수행 (시간 소요 방지)
        if self.mode != "FAST" and not self.stop_flag:
            udp_results = scanner.udp_scan(ip) # Default UDP ports (53, 161 etc)
            
            for u_port, u_msg, u_len in udp_results:
                udp_desc = f"UDP Port {u_port} is Open/Response. Payload Size: {u_len} bytes"
                
                self.db_queue.put(("SCAN_RESULT", (
                    ip,
                    f"UDP-{u_port}",
                    f"UDP Service Open ({u_port})",
                    "Info", 
                    "WARNING", 
                    udp_desc,
                    "불필요한 경우 해당 UDP 서비스를 비활성화하십시오."
                )))

        # ----------------------------------------------------
        # [Phase 3] Deep Inspection (Authenticated Audit)
        # ----------------------------------------------------
        # 인증 정보가 있는 경우 내부 설정 진단 수행
        if self.user_info.get(ip) and not self.stop_flag:
            creds = self.user_info[ip]
            username = creds['user']
            
            # Windows (SMB 445 or RPC 135 Open)
            if (445 in open_ports or 135 in open_ports) and "Windows" in os_type:
                inspector = WindowsInspector(ip, username)
                if inspector.connect():
                    results = inspector.run_all_checks()
                    for code, (status, detail, name, remediation) in results.items():
                        risk = "High" if status == "VULNERABLE" else "Info"
                        self.db_queue.put(("SCAN_RESULT", (ip, code, name, risk, status, detail, remediation)))

            # Linux (SSH 22 Open)
            elif 22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
                inspector = SSHInspector(ip, username)
                if inspector.connect():
                    results = inspector.run_all_checks()
                    for code, (status, detail, name, remediation) in results.items():
                        risk = "High" if status == "VULNERABLE" else "Info"
                        self.db_queue.put(("SCAN_RESULT", (ip, code, name, risk, status, detail, remediation)))

    def run(self):
        if self._security_token != REAL_KEY:
            self.log_signal.emit("[CRITICAL] Unauthorized Access Detected.")
            AppLogger.log_critical("Core Engine Security Violation: Invalid Caller.")
            self.finish_signal.emit("Security Error")
            return
        
        # DB 쓰기 스레드 시작
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        try:
            # 1. 타겟 파싱
            target_ips = self.parse_targets()
            
            # 타겟이 없으면 조용히 종료 (로그 X)
            if not target_ips:
                self.finish_signal.emit("No Targets")
                return

            # 2. 호스트 활성 여부 확인 (ICMP Ping)
            # CUSTOM 모드가 아닐 때만 Discovery 수행
            live_hosts = target_ips
            if self.mode != "CUSTOM": 
                discovery = HostDiscovery()
                live_hosts = discovery.scan_network(target_ips)
                
                dead_count = len(target_ips) - len(live_hosts)
                if dead_count > 0:
                    self.log_signal.emit(f"[-] {dead_count} hosts seem down. Skipping.")

            # [핵심] 최종적으로 살아있는 호스트 수 계산
            real_total_count = len(live_hosts)
            
            # [Fix] 여기서 딱 한 번만 시작 신호를 보냅니다. (중복 로그 해결)
            self.started_signal.emit(real_total_count) 
            
            # 살아있는 호스트가 없으면 종료
            if real_total_count == 0:
                self.log_signal.emit("[!] No live hosts found.")
                self.finish_signal.emit("No Live Hosts")
                return

            # 3. 스레드풀 스캔 시작
            max_workers = 10 if self.mode == "FULL" else 30 
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.scan_target, ip): ip for ip in live_hosts}
                
                processed_count = 0
                for future in as_completed(futures):
                    ip = futures[future]
                    # 중단 요청 확인
                    if self.stop_flag:
                        executor.shutdown(wait=False, cancel_futures=True)
                        self.log_signal.emit("[!] 사용자 요청에 의해 스캔 중단됨.")
                        break
                    
                    try:
                        future.result()
                    except Exception as e:
                        AppLogger.log_error(f"[Thread Error] {ip}", e)
                    
                    processed_count += 1
                    
                    if real_total_count > 0:
                        progress = int((processed_count / real_total_count) * 100)
                        self.progress_signal.emit(progress, processed_count)

            # 정상 완료 시 100% 찍기
            if not self.stop_flag:
                self.progress_signal.emit(100, real_total_count)
            
        except Exception as e:
            critical_msg = f"[Critical] 엔진 실행 중 오류 발생: {str(e)}"
            self.log_signal.emit(critical_msg)
            AppLogger.log_critical(critical_msg)
        
        finally:
            # DB 스레드 정리 및 종료 신호
            self.db_queue.put(None)
            if self.writer_thread:
                self.writer_thread.join(timeout=3)
            self.finish_signal.emit("Scan Process Terminated")