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
    # UI 업데이트를 위한 시그널
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
        self.stop_flag = True
        self.log_signal.emit("[-] Stopping scan worker...")

    def db_writer(self):
        # [수정] DB 쓰기 스레드: 증적(Raw Output) 데이터 처리 추가
        db = DBConnector()
        while True:
            item = self.db_queue.get()
            if item is None: # 종료 신호
                break
            
            try:
                msg_type, data = item
                if msg_type == "ASSET":
                    # Data: (ip, hostname, os_type, ports_str, mac_addr)
                    db.save_asset(
                        data[0], 
                        hostname=data[1], 
                        os_type=data[2], 
                        open_ports=data[3],
                        mac_addr=data[4]
                    )
                    
                elif msg_type == "SCAN_RESULT":
                    # [확장] Data: (ip, code, name, risk, status, desc, remediation, raw_output, kisa_code)
                    # Inspector 결과는 9개 요소, Port Scan 결과는 7개 요소일 수 있음 (유연성 처리)
                    
                    ip = data[0]
                    asset_id = db.get_asset_id(ip)
                    
                    if asset_id:
                        if len(data) >= 9:
                            # [KISA Inspector Result] 증적 포함
                            # (ip, code, name, risk, status, detail, remediation, raw_output, kisa_code)
                            db.save_result(
                                asset_id, 
                                data[1], # code (내부 ID)
                                data[2], # name
                                data[3], # risk
                                data[4], # status
                                data[5], # detail (요약)
                                data[6], # remediation
                                raw_output=data[7], # [NEW] 증적
                                kisa_code=data[8]   # [NEW] KISA 코드 (W-01 등)
                            )
                        else:
                            # [Port Scan / Legacy Result] 증적 없음 (기존 방식 유지)
                            # (ip, code, name, risk, status, detail, remediation)
                            db.save_result(
                                asset_id, 
                                data[1], data[2], data[3], data[4], data[5], data[6],
                                raw_output="", # 기본값
                                kisa_code=""   # 기본값
                            )

            except Exception as e:
                AppLogger.log_error("DB Writer Error", e)
            finally:
                self.db_queue.task_done()

    def parse_targets(self):
        targets = []
        try:
            raw_list = self.target_input.split(',')
            for raw in raw_list:
                raw = raw.strip()
                if '/' in raw:
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
                else:
                    targets.append(raw)
        except Exception as e:
            self.log_signal.emit(f"[!] Target Parse Error: {e}")
            AppLogger.log_error("Target Parsing Failed", e)
        
        return sorted(list(set(targets)))

    def scan_target(self, ip):
        if self.stop_flag: return
        
        scanner = AdvancedScanner()
        is_alive, os_type, mac_addr, vendor = scanner.host_discovery(ip)
        
        if not is_alive and self.mode != "CUSTOM":
            return
        
        hostname = "Unknown"
        if vendor != "Unknown":
            hostname = f"({vendor}) Device"
        
        # [Phase 1] TCP Port Scan
        if self.mode == "FULL" and self.ports is None:
            target_ports = range(1, 65536)
        elif self.ports:
            target_ports = self.ports
        elif self.custom_ports:
            target_ports = scanner.parse_ports(self.custom_ports)
        else:
            target_ports = scanner.default_ports
            
        open_ports = []
        chunk_size = 500
        
        if not isinstance(target_ports, list):
            target_ports = list(target_ports)

        total_len = len(target_ports)
        for i in range(0, total_len, chunk_size):
            if self.stop_flag: return
            chunk = target_ports[i : i + chunk_size]
            found = scanner.tcp_scan(ip, ports=chunk)
            open_ports.extend(found)

        ports_str = ""
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))

        self.asset_found_signal.emit(ip, hostname, f"OS: {os_type}")
        self.db_queue.put(("ASSET", (ip, hostname, os_type, ports_str, mac_addr)))

        if not open_ports:
            # 포트 없음 (7개 요소 전송)
            self.db_queue.put(("SCAN_RESULT", (ip, "INFO-00", "Host Alive", "Info", "Safe", "ICMP Ping Response Only", "-")))
        
        for port in open_ports:
            if self.stop_flag: break
            banner = scanner.grab_banner(ip, port)
            match_res = VulnMatcher.match(port, banner)
            
            status = "VULNERABLE" if match_res.get('risk') in ['High', 'Critical'] else "WARNING"
            if match_res.get('risk') == 'Info': status = "Safe"
            
            # 포트 스캔 결과 (7개 요소 전송)
            self.db_queue.put(("SCAN_RESULT", (
                ip, 
                f"TCP-{port}", 
                match_res.get('name', f"Open Port {port}"),
                match_res.get('risk', 'Low'),
                status,
                match_res.get('desc', banner),
                match_res.get('remediation', '-')
            )))

        # [Phase 2] UDP Scan
        if self.mode != "FAST" and not self.stop_flag:
            udp_results = scanner.udp_scan(ip)
            for u_port, u_msg, u_len in udp_results:
                udp_desc = f"UDP Port {u_port} is Open/Response. Payload Size: {u_len} bytes"
                # UDP 결과 (7개 요소 전송)
                self.db_queue.put(("SCAN_RESULT", (
                    ip,
                    f"UDP-{u_port}",
                    f"UDP Service Open ({u_port})",
                    "Info", 
                    "WARNING", 
                    udp_desc,
                    "불필요한 경우 해당 UDP 서비스를 비활성화하십시오."
                )))

        # [Phase 3] Deep Inspection (Authenticated Audit)
        if self.user_info.get(ip) and not self.stop_flag:
            creds = self.user_info[ip]
            username = creds['user']
            
            # [수정됨] Inspector 호출 및 결과 처리 (6개 Unpacking -> 9개 Packing)
            
            # Windows (SMB 445 or RPC 135)
            if (445 in open_ports or 135 in open_ports) and "Windows" in os_type:
                inspector = WindowsInspector(ip, username)
                if inspector.connect():
                    results = inspector.run_all_checks()
                    for code, (status, detail, name, remediation, raw_output, kisa_code) in results.items():
                        risk = "High" if status == "VULNERABLE" else "Info"
                        # [중요] 9개 요소를 튜플로 묶어서 큐에 넣음
                        self.db_queue.put(("SCAN_RESULT", (
                            ip, code, name, risk, status, detail, remediation, raw_output, kisa_code
                        )))

            # Linux (SSH 22)
            elif 22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
                inspector = SSHInspector(ip, username)
                if inspector.connect():
                    results = inspector.run_all_checks()
                    for code, (status, detail, name, remediation, raw_output, kisa_code) in results.items():
                        risk = "High" if status == "VULNERABLE" else "Info"
                        # [중요] 9개 요소를 튜플로 묶어서 큐에 넣음
                        self.db_queue.put(("SCAN_RESULT", (
                            ip, code, name, risk, status, detail, remediation, raw_output, kisa_code
                        )))

    def run(self):
        if self._security_token != REAL_KEY:
            self.log_signal.emit("[CRITICAL] Unauthorized Access Detected.")
            self.finish_signal.emit("Security Error")
            return
        
        self.writer_thread = threading.Thread(target=self.db_writer, daemon=True)
        self.writer_thread.start()

        try:
            target_ips = self.parse_targets()
            if not target_ips:
                self.finish_signal.emit("No Targets")
                return

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
            self.db_queue.put(None)
            if self.writer_thread:
                self.writer_thread.join(timeout=3)
            self.finish_signal.emit("Scan Process Terminated")