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
import re
import sys
import time
import uuid

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
from core.database_inspector import DatabaseInspector
from core.vuln_matcher import VulnMatcher
from utils.db_connector import DBConnector
from utils.logger import AppLogger
from utils.os_utils import OSUtils
from core.discovery import HostDiscovery
from utils.auth_token import get_engine_token
from core.config import AppConfig

class ScanWorker(QThread):
    # UI 업데이트를 위한 시그널
    log_signal = Signal(str)
    finish_signal = Signal(str)
    progress_signal = Signal(int, int)
    started_signal = Signal(int)
    # [UI/UX 개선 - hostname 출처 배지] IP, Host, OS, MAC, Vendor, hostname 출처(역DNS/매핑/추정)
    asset_found_signal = Signal(str, str, str, str, str, str)

    def __init__(self, mode, target_input, user=None, db_user=None, ports=None, db_queue=None, ot_mode=False, demo_mode=False, operator="", max_workers=None, imported_hostname_map=None, oracle_service_name=None):
        super().__init__()
        self.mode = mode
        self.target_input = target_input
        self.user_info = {}
        self.default_user = None
        # [P0: 자산 매핑] 엑셀/CSV로 가져온 {ip: hostname}. 역DNS가 실패했을 때
        # vendor placeholder로 떨어지기 전 마지막 폴백으로 쓴다(discover_target 참고).
        self.imported_hostname_map = imported_hostname_map or {}
        # [Oracle 서비스명] 비어있으면 DatabaseInspector가 자체 기본값(ORCL)으로 폴백한다.
        self.oracle_service_name = oracle_service_name
        # [DB 전용 계정] SSH/WinRM 계정과 DB 계정이 다를 때만 채워짐. 없으면(None)
        # DatabaseInspector가 지금까지처럼 OS 진단과 같은 계정을 그대로 재사용한다.
        self.default_db_user = db_user

        if isinstance(user, dict):
            self.user_info = user
        elif isinstance(user, str) and user:
            self.default_user = user # 단일 타겟용 기본 계정 저장

        self.custom_ports = ports
        self.stop_flag = False
        self.db_queue = db_queue if db_queue else queue.Queue()
        self.writer_thread = None
        self.ports = ports
        # [OT/저속 모드] 켜면 동시 스캔 대상 수를 줄이고, 진단 명령 사이에 적응형 딜레이를 적용
        self.ot_mode = ot_mode
        # [Phase 3: 병렬처리량 수동 제어] None이면 mode/ot_mode 기반 기존 자동 로직을 사용
        self.max_workers_override = max_workers
        # [실전 안전장치] 기본값 False. True일 때만 127.0.0.1 등 데모 IP/접속 실패 시 가상 데이터를 사용하며,
        # False면 접속 실패는 항상 정직하게 실패로 보고된다 (실제 현장 진단용 기본값).
        self.demo_mode = demo_mode
        # [Phase 2: 스캔 이력 보존] 이 실행(run)을 식별하는 세션 ID - 같은 자산을 여러 번 스캔해도
        # 회차별로 구분해 이력을 남길 수 있게 한다.
        self.session_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        # [Phase 2: 운영자 태깅] 스캔을 수행한 운영자 식별값 - 결과에 함께 기록된다.
        self.operator = operator or ""
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
            # [실전 안전장치] 데모 모드가 꺼져 있으면 이 IP들도 그냥 일반 대상으로 취급되어
            # 정상적으로 살아있는지 확인을 거친다 (강제로 살아있다고 처리하지 않음)
            sim_ips = ["0.0.0.0", "localhost", "127.0.0.1", "127.0.0.2"] if self.demo_mode else []

            if self.mode != "CUSTOM":
                # 1. 실제 스캔 (시뮬레이션 IP 제외)
                real_targets = [ip for ip in target_ips if ip not in sim_ips]
                if real_targets:
                    # [버그 수정] OT 모드에서는 생존확인 단계의 동시 연결 시도 수도 낮춘다
                    # [Phase 3] 사용자가 병렬처리량을 직접 지정했으면 생존확인 단계에도 동일하게 적용
                    if self.max_workers_override is not None:
                        discovery_workers = max(1, self.max_workers_override)
                    else:
                        discovery_workers = 3 if self.ot_mode else 50
                    discovery = HostDiscovery(max_workers=discovery_workers)
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

            # [Phase 3] 사용자가 병렬처리량을 직접 지정했으면 그 값을 우선 사용
            if self.max_workers_override is not None:
                max_workers = max(1, self.max_workers_override)
            else:
                max_workers = 10 if self.mode == "FULL" else 30
                if self.ot_mode:
                    # [OT/저속 모드] 동시에 여러 호스트를 두드리는 것 자체가 부하이므로 동시성을 크게 낮춤
                    max_workers = min(max_workers, 3)
            if self.ot_mode:
                self.log_signal.emit(f"[OT 모드] 저속/적응형 스로틀링 활성화 - 동시 스캔 대상 수: {max_workers}")

            # [Phase 1] Discovery/Audit 분리: 모드에 따라 서로 다른 메서드로 디스패치
            target_fn = self.audit_target if self.mode == "AUDIT_VULN" else self.discover_target

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(target_fn, ip): ip for ip in live_hosts}
                
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
                elif msg_type == "HOSTNAME_UPDATE":
                    self._save_hostname_update_to_db(db, data)
            except Exception as e:
                AppLogger.log_error("DB Writer Error", e)
            finally:
                self.db_queue.task_done()

    def _save_asset_to_db(self, db, data):
        # Data: (ip, hostname, os_type, ports_str, mac_addr, vendor, hostname_source)
        db.save_asset(
            data[0], hostname=data[1], os_type=data[2],
            open_ports=data[3], mac_addr=data[4], vendor=data[5], hostname_source=data[6]
        )

    def _save_hostname_update_to_db(self, db, data):
        # [Excel/PDF hostname 정확도] Discovery 단계에서는 "(vendor) Device" 같은 추정
        # placeholder만 알 수 있고, Audit(SSH/WinRM 인증 접속) 단계에서 uname -a / systeminfo로
        # 실제 hostname을 확인할 수 있다. save_asset()을 다시 부르면 os_type/open_ports가
        # 기본값으로 덮어써지므로, hostname 컬럼만 안전하게 갱신하는 update_asset_field를 쓴다.
        # 이 경로로 덮어써진 hostname은 인증 접속으로 실제 확인된 값이므로 출처를 "실측"으로 남긴다.
        ip, real_hostname = data
        asset_id = db.get_asset_id(ip)
        if asset_id:
            db.update_asset_field(asset_id, "hostname", real_hostname)
            db.update_asset_field(asset_id, "hostname_source", "실측")

    @staticmethod
    def _extract_real_hostname(os_info):
        """SYS-OS_INFO 원문(uname -a 또는 systeminfo)에서 실제 hostname을 추출한다.
        추출 실패 시 None을 반환하며, 이 경우 기존 hostname(placeholder 포함)은 그대로 둔다."""
        if not os_info:
            return None
        m = re.search(r'Host Name:\s*(\S+)', os_info)
        if m:
            return m.group(1)
        m = re.match(r'^\s*Linux\s+(\S+)', os_info)
        if m:
            return m.group(1)
        return None

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
                    remediation, raw_output, kisa_code,
                    session_id=self.session_id, operator=self.operator
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

        # [보안] 셸 메타문자 등 비정상 문자가 포함된 타겟은 이후 단계(arp/ping/ssh 등)에서
        # Command Injection으로 이어질 수 있으므로 여기서 걸러낸다.
        safe_targets = [t for t in targets if OSUtils.is_safe_host(t)]
        rejected = set(targets) - set(safe_targets)
        for bad in rejected:
            self.log_signal.emit(f"[!] Rejected invalid target (unsafe characters): {bad}")
            AppLogger.log_error(f"Rejected invalid target: {bad}")

        return sorted(list(set(safe_targets)))

    # ----------------------------------------------------------------------
    # [Module 3] Scanning Phases (Modularized)
    # ----------------------------------------------------------------------
    def discover_target(self, ip):
        """
        [Phase 1 리팩터링] Discovery 전용: 순수 자산 식별(생존/OS/포트/배너)만 수행.
        계정 정보가 있어도 여기서는 딥 인스펙션(KISA 점검)을 절대 하지 않는다.
        Return: {"os_type": str, "open_ports": list[int]} 또는 중단 시 None
        """
        if self.stop_flag: return None

        # [핵심] 시뮬레이션 타겟 확인 (데모 모드가 꺼져 있으면 이 IP들도 실제 대상처럼 취급)
        is_sim = self.demo_mode and (ip in ["0.0.0.0", "127.0.0.2", "localhost", "127.0.0.1"])

        scanner = AdvancedScanner()

        # 1. Host Discovery & OS Detection (가짜 데이터 주입)
        icmp_alive = None
        if is_sim:
            if ip in ["0.0.0.0", "127.0.0.2"]:
                os_type = "Windows Server 2019"
                vendor = "Microsoft"
            else:
                os_type = "Ubuntu Linux 20.04"
                vendor = "Ubuntu"
            mac_addr = "00:00:00:00:00:00"
        else:
            # [버그 수정: 이중 생존확인 통합] run()의 HostDiscovery(TCP 445/22/80/135)가
            # 이미 생존을 확인한 IP만 여기 도달한다. host_discovery()의 ICMP 결과는
            # OS 추정(TTL)용 "참고 정보"로만 쓰고, ICMP가 차단됐다고 자산을 스킵하지 않는다
            # (예전에는 ICMP 차단망에서 TCP로 확인된 자산이 조용히 스킵되는 문제가 있었음).
            # [버그 수정] 이 값을 예전엔 밑줄(_icmp_alive)로 버려놓고, 밑에서 열린 포트가
            # 없을 때 항상 "ICMP Ping Response Only"라고 근거를 고정해서 남겼다 - 실제로는
            # 이 호스트가 TCP(445/22/80/135 중 하나가 연결거부=생존)로 확인됐고 ICMP는
            # 막혀있는 경우에도 똑같이 "ICMP 응답"이라고 거짓 증적이 남는 문제가 실측으로
            # 확인됐다. 값을 그대로 써서 실제로 ICMP가 응답했는지를 증적에 정확히 남긴다.
            icmp_alive, os_type, mac_addr, vendor = scanner.host_discovery(ip)

        # [역DNS] 인증 정보 없이도 hostname을 채울 수 있으면 vendor 기반 placeholder 대신 사용.
        # 실패(PTR 레코드 없음 등)하면 [P0: 자산 매핑] 사용자가 가져온 자산목록에 이 IP의
        # 이름이 있는지 확인하고, 그것도 없을 때만 "(Vendor) Device" placeholder로 폴백한다.
        # 이후 인증 딥 인스펙션이 성공하면 _extract_real_hostname()이 다시 덮어쓴다.
        resolved_hostname = None if is_sim else scanner.resolve_hostname(ip)
        imported_hostname = self.imported_hostname_map.get(ip)
        if resolved_hostname:
            hostname = resolved_hostname
            hostname_source = "역DNS"
        elif imported_hostname:
            hostname = imported_hostname
            hostname_source = "매핑"
        else:
            hostname = f"({vendor}) Device" if vendor != "Unknown" else "Unknown Device"
            hostname_source = "추정"

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
            if self.ports: target_ports = self.ports
            elif self.custom_ports: target_ports = scanner.parse_ports(self.custom_ports)
            else: target_ports = scanner.default_ports

            target_ports = list(target_ports)
            scan_delay = 0.05 if self.ot_mode else 0  # OT 모드: 포트당 소폭의 대기시간으로 연결 시도 폭주 방지
            for i in range(0, len(target_ports), 500):
                if self.stop_flag: return None
                open_ports.extend(scanner.tcp_scan(ip, ports=target_ports[i:i+500], delay=scan_delay))

        ports_str = ", ".join(map(str, open_ports)) if open_ports else ""
        self.asset_found_signal.emit(ip, hostname, os_type, mac_addr, vendor, hostname_source)
        self.db_queue.put(("ASSET", (ip, hostname, os_type, ports_str, mac_addr, vendor, hostname_source)))

        if not open_ports:
            if icmp_alive:
                alive_note = "ICMP Ping Response"
            elif icmp_alive is False:
                alive_note = "TCP Connect/Refused on Discovery Port (ICMP Blocked)"
            else:
                alive_note = "TCP Connect/Refused on Discovery Port"
            self.db_queue.put(("SCAN_RESULT", (
                ip, "INFO-00", "Host Alive", "Info", "Safe",
                f"{alive_note} - No Open Ports in Scanned Range", "-", "", ""
            )))

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
                match_res.get('remediation', '-'),
                banner,                     # raw_output
                match_res.get('kisa', '')   # kisa_code
            )))

        # [Phase 2] UDP Scan (시뮬레이션은 생략 가능)
        if not is_sim and not self.stop_flag:
            # [버그 수정] OT 모드 딜레이가 UDP 스캔에는 적용되지 않던 문제
            udp_delay = 0.05 if self.ot_mode else 0
            udp_results = scanner.udp_scan(ip, delay=udp_delay)
            for u_port, u_msg, u_len in udp_results:
                udp_desc = f"UDP Port {u_port} is Open/Response. Payload Size: {u_len} bytes"
                self.db_queue.put(("SCAN_RESULT", (
                    ip, f"UDP-{u_port}", f"UDP Service ({u_port})", "Info", "WARNING",
                    udp_desc, "불필요한 경우 해당 UDP 서비스를 비활성화하십시오.",
                    udp_desc,  # raw_output
                    ""         # kisa_code (UDP는 매핑 없음)
                )))

        return {"os_type": os_type, "open_ports": open_ports}

    def audit_target(self, ip):
        """
        [Phase 1 리팩터링] Audit 전용: 계정 기반 딥 인스펙션(KISA 점검)만 수행.
        [버그 수정] 딥 인스펙션 진입 여부는 "계정정보 유무"가 아니라 run()에서
        self.mode == 'AUDIT_VULN'일 때만 이 메서드가 호출된다는 사실 자체로 결정된다.
        가능하면 TBL_ASSETS에 저장된 이전 Discovery 결과(os_type/open_ports)를 재사용해
        포트스캔을 다시 하지 않는다 (처음 진단하는 자산이면 1회 Discovery를 수행한다).
        """
        if self.stop_flag: return

        is_sim = self.demo_mode and (ip in ["0.0.0.0", "127.0.0.2", "localhost", "127.0.0.1"])

        cached = None
        if not is_sim:
            db = DBConnector()
            cached = db.get_discovery_info(ip)

        if cached:
            os_type = cached["os_type"]
            open_ports = cached["open_ports"]
        else:
            # 사전 Discovery 이력이 없는 자산 (또는 시뮬레이션) - 1회 Discovery로 채운다
            discovered = self.discover_target(ip)
            if discovered is None or self.stop_flag: return
            os_type = discovered["os_type"]
            open_ports = discovered["open_ports"]

        if self.stop_flag: return

        if is_sim:
            username = "Administrator" if "Windows" in os_type else "root"
        else:
            # IP별 계정이 없으면 기본 계정 사용
            username = self.user_info.get(ip, {}).get('user', self.default_user)

        os_inspector = None  # SYSTEM Detail 부록 수집 대상 (Windows/Linux 대표 1개만)
        inspectors = []
        # Windows 진단 조건
        if (445 in open_ports or 135 in open_ports) and "Windows" in os_type:
            os_inspector = WindowsInspector(ip, username, throttle=self.ot_mode, demo_mode=self.demo_mode)
            inspectors.append(os_inspector)
        # Linux 진단 조건
        elif 22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
            os_inspector = SSHInspector(ip, username, throttle=self.ot_mode, demo_mode=self.demo_mode)
            inspectors.append(os_inspector)

        # DB 진단 조건 (OS 진단과 별개로, 열린 DB 포트가 있으면 추가 수행)
        # [DB 전용 계정] SSH/WinRM 계정과 DB 계정이 다를 수 있어(예: DBA가 별도 관리하는
        # 감사 계정), db_user가 지정된 경우에만 그 계정을 쓰고 아니면 기존처럼 OS 계정을 재사용한다.
        db_username = self.default_db_user or username
        if 3306 in open_ports:
            inspectors.append(DatabaseInspector(ip, db_username, "mysql", throttle=self.ot_mode, demo_mode=self.demo_mode))
        if 5432 in open_ports:
            inspectors.append(DatabaseInspector(ip, db_username, "postgresql", throttle=self.ot_mode, demo_mode=self.demo_mode))
        if 1433 in open_ports:
            inspectors.append(DatabaseInspector(ip, db_username, "mssql", throttle=self.ot_mode, demo_mode=self.demo_mode))
        if 1521 in open_ports:
            inspectors.append(DatabaseInspector(ip, db_username, "oracle", throttle=self.ot_mode, demo_mode=self.demo_mode, service_name=self.oracle_service_name))

        # 웹 서비스 진단 조건 (Apache/Nginx 설정 점검, SSH 접속 가능한 Linux 대상만)
        if (80 in open_ports or 443 in open_ports or 8080 in open_ports) and \
           22 in open_ports and ("Linux" in os_type or "Unix" in os_type or os_type == "Unknown"):
            inspectors.append(SSHInspector(ip, username, ruleset="web_rules.json", throttle=self.ot_mode, demo_mode=self.demo_mode))

        for inspector in inspectors:
            if self.stop_flag: break
            if not inspector.connect():
                # [실전 안전장치] 접속 실패를 조용히 건너뛰면 "취약점 없음"과 구분이 안 되므로,
                # 점검 자체를 수행하지 못했다는 사실을 보고서에 명시적으로 남긴다.
                tag = getattr(inspector, 'ruleset', None) or getattr(inspector, 'engine', type(inspector).__name__)
                self.db_queue.put(("SCAN_RESULT", (
                    ip, f"CONN-{tag}", "원격 접속/인증 실패", "High", "ERROR",
                    "원격 접속에 실패하여 이 항목들을 점검하지 못했습니다 (계정/네트워크/방화벽 확인 필요)",
                    "-", "-", ""
                )))
                continue

            # [SYSTEM Detail] OS 대표 인스펙터 1개에서만 시스템/IP/PORT/서비스 원시 정보 수집
            if inspector is os_inspector and hasattr(inspector, 'get_system_detail'):
                detail_info = inspector.get_system_detail()
                for key, label in (("os_info", "시스템 정보"), ("ip_info", "IP 정보"),
                                    ("port_info", "PORT 정보"), ("service_info", "서비스 정보")):
                    self.db_queue.put(("SCAN_RESULT", (
                        ip, f"SYS-{key.upper()}", label, "Info", "Safe",
                        "SYSTEM Detail 부록 (판정 대상 아님)", "-", detail_info.get(key, ""), ""
                    )))

                # [Excel/PDF hostname 정확도] Discovery의 vendor 추정 placeholder를
                # 실제 인증 접속으로 확인한 hostname으로 교체 (실패 시 조용히 건너뜀)
                real_hostname = self._extract_real_hostname(detail_info.get("os_info", ""))
                if real_hostname:
                    self.db_queue.put(("HOSTNAME_UPDATE", (ip, real_hostname)))

                # [PC vs Windows 서버 자동 분류] systeminfo의 OS 이름으로 룰셋 재선택
                # ("Server"가 없으면 업무용 PC로 간주하여 PC-01~18 룰셋 적용)
                if isinstance(inspector, WindowsInspector) and "Server" not in detail_info.get("os_info", ""):
                    inspector.set_ruleset("pc_rules.json")

            results = inspector.run_all_checks()
            for code, (status, detail, name, remediation, raw_output, kisa_code, importance) in results.items():
                if status == "VULNERABLE":
                    # KISA 중요도(상/중/하)를 위험도로 변환하여 리포트 통계에 정확히 반영
                    risk = {"상": "Critical", "중": "High", "하": "Medium"}.get(importance, "High")
                elif status == "PARTIAL":
                    # 부분만족: 세부기준 일부만 충족 = 미충족(VULNERABLE) 대비 한 단계 낮은 위험도
                    risk = {"상": "High", "중": "Medium", "하": "Low"}.get(importance, "Medium")
                else:
                    risk = "Info"
                # [중요] 9개 요소 (증적 포함) 전송
                self.db_queue.put(("SCAN_RESULT", (
                    ip, code, name, risk, status, detail, remediation, raw_output, kisa_code
                )))

            if hasattr(inspector, 'close'):
                inspector.close()
