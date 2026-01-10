# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import socket
import sys
import os
import subprocess
import re
import ssl
import json 
import struct # UDP 패킷 구조체 생성용

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    def __init__(self):
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
        
        # [Strategy 1] TCP Service Probes (Service Trigger)
        self.PROBES = {
            80: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            8080: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            443: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            21: None, 22: None, 23: None, 
            25: b"EHLO z-vulnscan\r\n", 
        }

        # [Strategy 3] UDP Payloads (Nmap Style)
        # UDP는 연결 과정이 없으므로, 애플리케이션이 반응할 수 있는 '진짜 데이터'를 보내야 함
        self.UDP_PROBES = {
            53:  b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01", # DNS Query (Transaction ID aaaa)
            123: b"\xe3\x00\x06\xec" + b"\x00"*44, # NTP v4 Client Request
            137: b"\x80\x96\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01", # NetBIOS Status
            161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", # SNMP v1 public get-next
            1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n" # SSDP (UPnP)
        }

        self.SIGNATURES = [] 
        self.load_signatures()

        #Service Fingerprints (정규식 DB)
    def load_signatures(self):
        #[Hybrid Loader]
        #1. 외부(External) rules 폴더에 파일이 있으면 우선 사용 (Custom/Update)
        #2. 없으면 내부(Internal) _MEIPASS 리소스를 사용 (Default/Fallback)
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        external_path = os.path.join(base_dir, 'rules', 'signatures.json')
        
        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', 'signatures.json')
        else:
            internal_path = external_path

        # 외부 파일 우선 로드 정책
        target_path = external_path if os.path.exists(external_path) else internal_path
        
        if target_path and os.path.exists(target_path):
            try:
                with open(target_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        if 'pattern' in item and 'service' in item:
                            self.SIGNATURES.append((
                                item['pattern'], 
                                item['service'], 
                                item.get('category', 'General')
                            ))
                AppLogger.log_info(f"[Config] Loaded {len(self.SIGNATURES)} signatures.")
            except Exception as e:
                AppLogger.log_error(f"[Config] Failed to parse signatures.json", e)
                self._load_hardcoded_defaults()
        else:
            self._load_hardcoded_defaults()

    def _load_hardcoded_defaults(self):
        #파일 로드 실패 시 사용하는 비상용 데이터
        self.SIGNATURES = [
            (r'^SSH-[\d.]+-OpenSSH_([\w.]+)', "OpenSSH", "SSH"),
            (r'Server:\s*Apache/([\d.]+)', "Apache httpd", "HTTP"),
            (r'Server:\s*nginx/([\d.]+)', "Nginx", "HTTP"),
            (r'.*(\d+\.\d+\.\d+-MariaDB).*', "MariaDB", "MySQL"),
        ]

    @staticmethod
    def parse_ports(port_str):
        if not re.match(r'^[\d,-]+$', port_str):
            AppLogger.log_error(f"Invalid port format: {port_str}")
            return []
        ports = set()
        try:
            parts = port_str.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    s, e = map(int, part.split('-'))
                    for p in range(s, e + 1): ports.add(p)
                else:
                    ports.add(int(part))
        except: pass
        return sorted(list(ports))

    def estimate_os_from_ttl(self, ttl):
        if ttl is None: return "Unknown"
        try:
            ttl = int(ttl)
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            elif ttl > 128: return "Network Device"
            else: return "Unknown"
        except:
            return "Unknown"

    def get_mac_address(self, ip):
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]: return "Localhost"
        mac_address = "Unknown"
        try:
            cmd = f"arp -a {ip}" if OSUtils.is_windows() else f"arp -n {ip}"
            kwargs = OSUtils.get_hidden_kwargs() if OSUtils.is_windows() else {}
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1, shell=True, **kwargs)
            if proc.returncode == 0:
                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", proc.stdout)
                if mac_match: mac_address = mac_match.group(0).upper().replace("-", ":")
        except: pass
        return mac_address

    def host_discovery(self, ip):
        is_alive = False
        detected_os = "Unknown"
        mac_address = "Unknown"
        vendor = "Unknown"
        try:
            cmd, kwargs = OSUtils.get_ping_command(ip)
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, **kwargs)
            if proc.returncode == 0:
                is_alive = True
                try: output = proc.stdout.decode('cp949', errors='ignore') 
                except: output = proc.stdout.decode('utf-8', errors='ignore')
                
                ttl_match = re.search(r'ttl[=< ]?(\d+)', output, re.IGNORECASE)
                if ttl_match: detected_os = self.estimate_os_from_ttl(int(ttl_match.group(1)))
                
                mac_address = self.get_mac_address(ip)
                vendor = OUILookup.lookup(mac_address)
        except: pass
        return is_alive, detected_os, mac_address, vendor

    def tcp_scan(self, ip, ports=None):
        target_ports = ports if ports else self.default_ports
        open_ports = []
        timeout = 0.2
        for port in target_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0: open_ports.append(port)
            except: pass
        return open_ports

    def udp_scan(self, ip, ports=None):
        #UDP 포트 스캔: 연결이 없으므로 페이로드를 보내고 응답을 기다림.
        #- 응답 있음 -> Open
        #- ICMP Unreachable -> Closed (Python Socket에서 감지 어려움, 보통 Timeout으로 처리)
        #- 응답 없음(Timeout) -> Open|Filtered (여기선 보수적으로 'Open?' 또는 무시)
        # 기본 점검할 UDP 포트 (DNS, NTP, NetBIOS, SNMP, UPnP)
        target_ports = ports if ports else [53, 123, 137, 161, 1900] 
        open_ports = []
        timeout = 1.0 # UDP는 패킷 손실 가능성이 있어 TCP보다 길게 설정
        for port in target_ports:
            # 해당 포트에 맞는 페이로드 가져오기 (없으면 빈 패킷)
            payload = self.UDP_PROBES.get(port, b"")
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(payload, (ip, port))
                    
                    # 응답 대기
                    try:
                        data, _ = s.recvfrom(1024)
                        # 데이터가 왔다는 건 확실히 열려있다는 뜻
                        open_ports.append((port, "UDP-Open", len(data)))
                    except socket.timeout:
                        # UDP는 응답 없는게 정상이거나(Drop), 열려있는데 무시하는 경우임
                        pass
                    except ConnectionResetError:
                        # Windows에서 ICMP Port Unreachable을 받으면 이 에러가 남 -> 확실히 Closed
                        pass
            except:
                pass
                
        return open_ports
    
    def analyze_banner(self, banner, port):
        #Hybrid Mode: 서명이 매칭되면 예쁘게 출력하고,
        #매칭되지 않으면 원본 배너를 보존하여 정보 손실을 방지합니다.
        service = "Unknown"
        version = ""
        is_matched = False
        
        # 1. 정규식 매칭 시도
        for pattern, product_name, category in self.SIGNATURES:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service = product_name
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)
                is_matched = True
                break
        
        # 2. [보완점] 매칭 실패 시 원본 정보 보존
        if not is_matched:
            # 원본 배너가 너무 길면 자름
            raw_info = banner[:40] + "..." if len(banner) > 40 else banner
            # 포트별 기본 서비스명 가져오기
            common_ports = {21:'FTP', 22:'SSH', 23:'Telnet', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 8080:'HTTP-Proxy'}
            base_service = common_ports.get(port, 'TCP')
            
            # "HTTP (Server: Apache/2.4)" 형태로 원본 보존
            return f"{base_service} ({raw_info})"

        # 3. 매칭 성공 시 깔끔한 포맷
        final_info = f"{service}"
        if version:
            final_info += f" {version}"
            
        return final_info

    def grab_banner(self, ip, port):
        banner_raw = ""
        probe_data = self.PROBES.get(port, b"\r\n") 
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try: sock = context.wrap_socket(sock, server_hostname=ip)
                except: pass 

            sock.connect((ip, port))
            if probe_data: sock.send(probe_data)
            
            raw_data = sock.recv(2048)
            banner_raw = raw_data.decode('utf-8', errors='ignore').strip()
            
        except: pass
        finally: sock.close()

        if banner_raw:
            return self.analyze_banner(banner_raw, port)
        else:
            return "Unknown (No Banner)"