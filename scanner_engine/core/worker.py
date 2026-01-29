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
from utils.auth_token import get_engine_token
from core.config import AppConfig

class ScanWorker(QThread):
    # UI 업데이트를 위한 시그널
    log_signal = Signal(str)
    finish_signal = Signal(str)
    progress_signal = Signal(int, int)
    started_signal = Signal(int)
    asset_found_signal = Signal(str, str, str, str) # IP, Hostname, OS, Ports

    def __init__(self, mode, target_input, user=None, ports=None, db_queue=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user_info = user if isinstance(user, dict) else {}
        self.custom_ports = ports
        self.stop_flag = False
        self.db_queue = db_queue if db_queue else queue.Queue()
        self.writer_thread = None
        self._security_token = get_engine_token()

    def stop(self):
        self.stop_flag = True
        self.log_signal.emit("[-] Stopping scan worker...")

    # ----------------------------------------------------------------------
    # [Module 1] DB Writer Loop (Consumer)
    # ----------------------------------------------------------------------
    def db_writer(self):
        """DB 쓰기 전용 스레드: 큐에서 데이터를 꺼내 DB에 저장"""
        db = DBConnector()
        while True:
            item = self.db_queue.get()
            if item is None: # 종료 신호
                break
            
            try:
                msg_type, data = item
                if msg_type == "ASSET":
                    self._save_asset_to_db(db, data)
                elif msg_type == "SCAN_RESULT":
                    self._save_result_to_db(db, data)
            except Exception as e:
                AppLogger.log_error("DB Writer Error", e)
            finally:
                self.db_queue.task_done()

    def _save_asset_to_db(self, db, data):
        # Data: (ip, hostname, os_type, ports_str, mac_addr)
        db.save_asset(
            data[0], hostname=data[1], os_type=data[2], 
            open_ports=data[3], mac_addr=data[4]
        )

    def _save_result_to_db(self, db, data):
        # [핵심 수정] 9개 인자 언패킹 (증적, KISA 코드 포함)
        # Data: (ip, code, name, risk, status, detail, remediation, raw_output, kisa_code)
        try:
            if len(data) >= 9:
                ip, code, name, risk, status, detail, remediation, raw_output, kisa_code = data[:9]
            else:
                # 구버전 호환성 (7개 인자일 경우)
                ip, code, name, risk, status, detail, remediation = data[:7]
                raw_output, kisa_code = "", ""

            asset_id = db.get_asset_id(ip)
            if asset_id:
                db.save_result(
                    asset_id, code, name, risk, status, detail, 
                    remediation, raw_output, kisa_code
                )
        except ValueError as e:
            AppLogger.log_error(f"DB Save Mismatch: {data}", e)

    # ----------------------------------------------------------------------
    # [Module 2] Target Parsing Logic
    # ----------------------------------------------------------------------
    def parse_targets(self):
        targets = []
        try:
            raw_list = self.target_input.split(',')
            for raw in raw_list:
                raw = raw.strip()
                if '/' in raw: # CIDR
                    net = ipaddress.ip_network(raw, strict=False)
                    for ip in net.hosts():
                        targets.append(str(ip))
                elif '-' in raw:
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
                else: # Single IP
                    targets.append(raw)
        except Exception as e:
            self.log_signal.emit(f"[!] Target Parse Error: {e}")
            AppLogger.log_error("Target Parsing Failed", e)
        
        return sorted(list(set(targets)))

    # ----------------------------------------------------------------------
    # [Module 3] Scanning Phases (Modularized)
    # ----------------------------------------------------------------------
    def scan_target(self, ip):
        """단일 타겟에 대한 전체 스캔 프로세스 오케스트레이션"""
        if self.stop_flag: return
        
        scanner = AdvancedScanner()
        
        # 1. 호스트 생존 확인 (Discovery)
        is_alive, os_type, hostname, mac_addr = self._phase_host_discovery(ip, scanner)
        if not is_alive and self.mode != "CUSTOM":
            return # 죽은 호스트는 스킵

        # 2. TCP 포트 스캔 (Port Scan & Banner Grab)
        open_ports = self._phase_tcp_scan(ip, scanner, os_type, hostname, mac_addr)

        # 3. UDP 스캔 (UDP Scan)
        self._phase_udp_scan(ip, scanner)

        # 4. 정밀 진단 (Authenticated Audit)
        self._phase_audit(ip, open_ports, os_type)

    def _phase_host_discovery(self, ip, scanner):
        """1단계: 호스트 생존 여부 및 OS 탐지"""
        is_alive, os_type, mac_addr, vendor = scanner.host_discovery(ip)
        
        hostname = "Unknown"
        if vendor != "Unknown":
            hostname = f"({vendor}) Device"
            
        return is_alive, os_type, hostname, mac_addr

    def _phase_tcp_scan(self, ip, scanner, os_type, hostname, mac_addr):
        """2단계: TCP 포트 스캔 및 취약점 매칭"""
        target_ports = self._get_target_ports(scanner)
        open_ports = []
        chunk_size = 500
        
        if not isinstance(target_ports, list):
            target_ports = list(target_ports)

        # 스캔 수행
        for i in range(0, len(target_ports), chunk_size):
            if self.stop_flag: break
            chunk = target_ports[i : i + chunk_size]
            found = scanner.tcp_scan(ip, ports=chunk)
            open_ports.extend(found)

        ports_str = ", ".join(map(str, open_ports)) if open_ports else ""
        
        # 자산 정보 등록
        self.asset_found_signal.emit(ip, hostname, f"OS: {os_type}", f"Ports: {ports_str}")
        self.db_queue.put(("ASSET", (ip, hostname, os_type, ports_str, mac_addr)))

        if not open_ports:
            # 포트 없음 -> 증적 없음
            self.db_queue.put(("SCAN_RESULT", (
                ip, "INFO-00", "Host Alive", "Info", "Safe", 
                "ICMP Ping Response Only", "-", "", ""
            )))
            return []

        # 배너 그래빙 및 취약점 매칭
        for port in open_ports:
            if self.stop_flag: break
            banner = scanner.grab_banner(ip, port)
            match_res = VulnMatcher.match(port, banner)
            
            if not isinstance(match_res, dict):
                match_res = {}

            status = "VULNERABLE" if match_res.get('risk') in ['High', 'Critical'] else "WARNING"
            if match_res.get('risk') == 'Info': status = "Safe"
            
            # [데이터 매핑] 
            # raw_output -> banner (증적)
            # kisa_code -> match_res['kisa']
            self.db_queue.put(("SCAN_RESULT", (
                ip, 
                f"TCP-{port}", 
                match_res.get('name', f"Open Port {port}"),
                match_res.get('risk', 'Low'),
                status,
                match_res.get('desc', banner),
                match_res.get('remediation', '-'),
                banner,                     # raw_output
                match_res.get('kisa', '')   # kisa_code
            )))
            
        return open_ports

    def _phase_udp_scan(self, ip, scanner):
        """3단계: UDP 스캔"""
        if self.mode != "FAST" and not self.stop_flag:
            udp_results = scanner.udp_scan(ip)
            for u_port, u_msg, u_len in udp_results:
                udp_desc = f"UDP Port {u_port} is Open/Response. Payload Size: {u_len} bytes"
                self.db_queue.put(("SCAN_RESULT", (
                    ip,
                    f"UDP-{u_port}",
                    f"UDP Service Open ({u_port})",
                    "Info", 
                    "WARNING", 
                    udp_desc,
                    "불필요한 경우 해당 UDP 서비스를 비활성화하십시오.",
                    udp_desc, # raw_output
                    ""        # kisa_code (UDP는 매핑 없음)
                )))

    def _phase_audit(self, ip, open_ports, os_type):
        """4단계: 인증 기반 정밀 진단 (Inspector)"""
        # 사용자 자격 증명 확인
        if not (self.user_info and self.user_info.get(ip)) or self.stop_flag:
            return

        creds = self.user_info[ip]
        username = creds.get('user', '') if isinstance(creds, dict) else ''
        
        inspector = None
        
        # Windows 진단 조건
        if (445 in open_ports or 135 in open_ports) and "Windows" in os_type:
            inspector = WindowsInspector(ip, username)

        # Linux 진단 조건
        elif 22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
            inspector = SSHInspector(ip, username)
            
        # 진단 수행
        if inspector and inspector.connect():
            results = inspector.run_all_checks()
            
            # Inspector 결과 처리 (튜플 크기에 따라 유연하게 대응)
            for code, res_tuple in results.items():
                # 기본값
                status, detail, name, remediation = "Safe", "", code, ""
                raw_output, kisa_code = "", ""
                
                if len(res_tuple) >= 6:
                    status, detail, name, remediation, raw_output, kisa_code = res_tuple[:6]
                elif len(res_tuple) == 4:
                    status, detail, name, remediation = res_tuple
                
                risk = "High" if status == "VULNERABLE" else "Info"
                
                self.db_queue.put(("SCAN_RESULT", (
                    ip, code, name, risk, status, detail, 
                    remediation, raw_output, kisa_code
                )))

    def _get_target_ports(self, scanner):
        """스캔 모드에 따른 타겟 포트 리스트 반환"""
        if self.mode == "FULL" and self.custom_ports is None:
            return range(1, 65536)
        elif self.custom_ports:
            return scanner.parse_ports(self.custom_ports)
        else:
            return scanner.default_ports

    # ----------------------------------------------------------------------
    # [Module 4] Main Run Loop
    # ----------------------------------------------------------------------
    def run(self):
        # 1. 보안 토큰 검증
        if self._security_token != AppConfig.ENGINE_ACCESS_TOKEN:
            self.log_signal.emit("[CRITICAL] Unauthorized Access Detected.")
            self.finish_signal.emit("Security Error")
            return
        
        # 2. DB Writer 시작
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        try:
            # 3. 타겟 파싱
            target_ips = self.parse_targets()
            if not target_ips:
                self.finish_signal.emit("No Targets")
                return

            # 4. Host Discovery
            live_hosts = target_ips
            if self.mode != "CUSTOM": 
                discovery = HostDiscovery()
                live_hosts = discovery.scan_network(target_ips)
                
                dead_count = len(target_ips) - len(live_hosts)
                if dead_count > 0:
                    self.log_signal.emit(f"[-] {dead_count} hosts seem down. Skipping.")

            real_total_count = len(live_hosts)
            self.started_signal.emit(real_total_count) 
            
            if real_total_count == 0:
                self.log_signal.emit("[!] No live hosts found.")
                self.finish_signal.emit("No Live Hosts")
                return

            # 5. Thread Pool Execution
            max_workers = 10 if self.mode == "FULL" else 30 
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.scan_target, ip): ip for ip in live_hosts}
                
                processed_count = 0
                for future in as_completed(futures):
                    ip = futures[future]
                    
                    if self.stop_flag:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        future.result()
                    except Exception as e:
                        AppLogger.log_error(f"[Thread Error] {ip}", e)
                    
                    processed_count += 1
                    if real_total_count > 0:
                        progress = int((processed_count / real_total_count) * 100)
                        self.progress_signal.emit(progress, processed_count)

            if not self.stop_flag:
                self.progress_signal.emit(100, real_total_count)
            
        except Exception as e:
            self.log_signal.emit(f"[Critical] Error: {str(e)}")
            AppLogger.log_critical(f"Worker Error: {e}")
        
        finally:
            self.db_queue.put(None) # Writer 종료 신호
            if self.writer_thread:
                self.writer_thread.join(timeout=3)
            self.finish_signal.emit("Scan Process Terminated")