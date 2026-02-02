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
    # [수정] 문자열 5개를 보내겠다고 선언 (IP, Host, OS, MAC, Vendor)
    asset_found_signal = Signal(str, str, str, str, str)

    def __init__(self, mode, target_input, user=None, ports=None, db_queue=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user_info = {}
        self.default_user = None
        
        if isinstance(user, dict):
            self.user_info = user
        elif isinstance(user, str) and user:
            self.default_user = user # 단일 타겟용 기본 계정 저장
            
        self.custom_ports = ports
        self.stop_flag = False
        self.db_queue = db_queue if db_queue else queue.Queue()
        self.writer_thread = None
        self.ports = ports
        self._security_token = get_engine_token()

    def run(self):
        if self._security_token != AppConfig.ENGINE_ACCESS_TOKEN:
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

            live_hosts = []
            sim_ips = ["0.0.0.0", "localhost", "127.0.0.1", "127.0.0.2"]

            if self.mode != "CUSTOM":
                # 1. 실제 스캔 (시뮬레이션 IP 제외)
                real_targets = [ip for ip in target_ips if ip not in sim_ips]
                if real_targets:
                    discovery = HostDiscovery()
                    live_hosts = discovery.scan_network(real_targets)
                
                # 2. 시뮬레이션 IP는 무조건 생존 처리
                for sim in sim_ips:
                    if sim in target_ips:
                        self.log_signal.emit(f"[Simulation] Force activating target: {sim}")
                        live_hosts.append(sim)
            else:
                live_hosts = target_ips

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
        
        # [핵심] 시뮬레이션 타겟 확인
        is_sim = ip in ["0.0.0.0", "127.0.0.2", "localhost", "127.0.0.1"]
        
        scanner = AdvancedScanner()
        
        # 1. Host Discovery & OS Detection (가짜 데이터 주입)
        if is_sim:
            is_alive = True
            # IP에 따라 가짜 OS 구분
            if ip in ["0.0.0.0", "127.0.0.2"]:
                os_type = "Windows Server 2019"
                vendor = "Microsoft"
            else:
                os_type = "Ubuntu Linux 20.04"
                vendor = "Ubuntu"
            mac_addr = "00:00:00:00:00:00"
        else:
            is_alive, os_type, mac_addr, vendor = scanner.host_discovery(ip)
        
        if not is_alive and self.mode != "CUSTOM": return
        
        hostname = f"({vendor}) Device" if vendor != "Unknown" else "Unknown Device"
        
        # [Phase 1] TCP Port Scan (가짜 포트 주입)
        open_ports = []
        if is_sim:
            # 시뮬레이션이면 OS에 맞는 핵심 포트 강제 오픈
            if "Windows" in os_type:
                open_ports = [135, 445, 3389, 80]
            else:
                open_ports = [22, 80, 3306]
            self.log_signal.emit(f"[Simulation] Injecting fake ports for {ip}: {open_ports}")
        else:
            # 실제 스캔 로직
            if self.mode == "FULL" and self.ports is None: target_ports = range(1, 65536)
            elif self.ports: target_ports = self.ports
            elif self.custom_ports: target_ports = scanner.parse_ports(self.custom_ports)
            else: target_ports = scanner.default_ports
            
            target_ports = list(target_ports)
            for i in range(0, len(target_ports), 500):
                if self.stop_flag: return
                open_ports.extend(scanner.tcp_scan(ip, ports=target_ports[i:i+500]))

        ports_str = ", ".join(map(str, open_ports)) if open_ports else ""
        self.asset_found_signal.emit(ip, hostname, os_type, mac_addr, vendor)
        self.db_queue.put(("ASSET", (ip, hostname, os_type, ports_str, mac_addr)))

        if not open_ports:
            self.db_queue.put(("SCAN_RESULT", (ip, "INFO-00", "Host Alive", "Info", "Safe", "ICMP Ping Response Only", "-")))
        
        # 포트별 배너 및 기본 취약점 확인
        for port in open_ports:
            if self.stop_flag: break
            banner = f"Simulation Banner on {port}" if is_sim else scanner.grab_banner(ip, port)
            match_res = VulnMatcher.match(port, banner)
            
            if not isinstance(match_res, dict): match_res = {}
            
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

        # [Phase 2] UDP Scan (시뮬레이션은 생략 가능)
        if not is_sim and self.mode != "FAST" and not self.stop_flag:
            udp_results = scanner.udp_scan(ip)
            for u_port, u_msg, u_len in udp_results:
                self.db_queue.put(("SCAN_RESULT", (
                    ip, f"UDP-{u_port}", f"UDP Service ({u_port})", "Info", "WARNING", f"Payload: {u_len} bytes", "-"
                )))

        # [Phase 3] Deep Inspection (증적 확보)
        should_inspect = False
        username = ""

        # 시뮬레이션이거나, 계정 정보가 있으면 진단 수행
        if is_sim:
            should_inspect = True
            username = "Administrator" if "Windows" in os_type else "root"
        elif (self.user_info.get(ip) or self.default_user):
            should_inspect = True
            # IP별 계정이 없으면 기본 계정 사용
            username = self.user_info.get(ip, {}).get('user', self.default_user)

        if should_inspect and not self.stop_flag:
            inspector = None
            # Windows 진단 조건
            if (445 in open_ports or 135 in open_ports) and "Windows" in os_type:
                inspector = WindowsInspector(ip, username)
            # Linux 진단 조건
            elif 22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
                inspector = SSHInspector(ip, username)
            
            if inspector and inspector.connect():
                results = inspector.run_all_checks()
                for code, (status, detail, name, remediation, raw_output, kisa_code) in results.items():
                    risk = "High" if status == "VULNERABLE" else "Info"
                    # [중요] 9개 요소 (증적 포함) 전송
                    self.db_queue.put(("SCAN_RESULT", (
                        ip, code, name, risk, status, detail, remediation, raw_output, kisa_code
                    )))
