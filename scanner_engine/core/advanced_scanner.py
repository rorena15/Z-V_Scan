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

# 상위 디렉토리(프로젝트 루트)를 시스템 경로에 추가
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    #[Z-VulnScan Pro Advanced Scanner Engine]
    #Features:
    #1. TCP Connect Scan & Service Fingerprinting
    #2. UDP Payload Scan (Nmap -sU Style)
    #3. HTTP Title Extraction (Asset Identification)
    #4. Passive OS Fingerprinting (TTL)
    
    def __init__(self):
        # 기본 스캔 대상 포트
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
        
        # [Strategy 1] TCP Service Probes
        # [Update v4.4] HTTP Title 수집을 위해 HEAD -> GET 변경
        self.PROBES = {
            80: b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            8080: b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            443: b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            21: None, 
            22: None, 
            23: None, 
            25: b"EHLO z-vulnscan\r\n", 
        }

        # [Strategy 3] UDP Payloads
        self.UDP_PROBES = {
            53:  b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01", 
            123: b"\xe3\x00\x06\xec" + b"\x00"*44, 
            137: b"\x80\x96\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01", 
            161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 
            1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n" 
        }

        self.SIGNATURES = [] 
        self.load_signatures()
    
    def get_system_vendor(self):
        try:
            # 윈도우가 아니면 실행 안 함
            if not OSUtils.is_windows():
                return None

            # creationflags=0x08000000 : CMD 창 깜빡임 방지
            cmd = "wmic csproduct get vendor"
            output = subprocess.check_output(cmd, shell=True, creationflags=0x08000000).decode('utf-8', errors='ignore')
            
            lines = output.strip().splitlines()
            for line in lines:
                cleaned = line.strip()
                if not cleaned or "Vendor" in cleaned:
                    continue
                return cleaned # 진짜 벤더 이름 반환 (예: innotek GmbH)
                
        except:
            pass
        return None

    def load_signatures(self):
        #[Hybrid Loader] 외부 JSON 룰 우선, 없으면 내부 기본값
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
        self.SIGNATURES = [
            (r'^SSH-[\d.]+-OpenSSH_([\w.]+)', "OpenSSH", "SSH"),
            (r'Server:\s*Apache/([\d.]+)', "Apache httpd", "HTTP"),
            (r'Server:\s*nginx/([\d.]+)', "Nginx", "HTTP"),
            (r'Server:\s*Microsoft-IIS/([\d.]+)', "Microsoft IIS", "HTTP"),
            (r'.*(\d+\.\d+\.\d+-MariaDB).*', "MariaDB", "MySQL"),
        ]
    
    @staticmethod
    def parse_ports(port_str):
        if not re.match(r'^[\d,-]+$', port_str): return []
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
        except: return "Unknown"

    def get_mac_address(self, ip):
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]: return "Localhost"
        mac_address = "Unknown"
        try:
            cmd = f"arp -a {ip}" if OSUtils.is_windows() else f"arp -n {ip}"
            kwargs = OSUtils.get_hidden_kwargs() if OSUtils.is_windows() else {}
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1, shell=True, **kwargs)
            if proc.returncode == 0:
                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", proc.stdout)
                if mac_match: 
                    mac_address = mac_match.group(0).upper().replace("-", ":")
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
                
                #만약 MAC으로 벤더를 못 찾았고, 내 로컬 PC(localhost)를 스캔 중이라면 wmic 시도
                if vendor == "Unknown" and ip in ["127.0.0.1", "localhost", socket.gethostbyname(socket.gethostname())]:
                    wmic_vendor = self.get_system_vendor()
                    if wmic_vendor:
                        vendor = wmic_vendor

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
                    if s.connect_ex((ip, port)) == 0: 
                        open_ports.append(port)
            except: pass
        return open_ports

    def udp_scan(self, ip, ports=None):
        target_ports = ports if ports else [53, 123, 137, 161, 1900] 
        open_ports = []
        timeout = 1.0

        for port in target_ports:
            payload = self.UDP_PROBES.get(port, b"")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(payload, (ip, port))
                    try:
                        data, _ = s.recvfrom(1024)
                        open_ports.append((port, "UDP-Open", len(data)))
                    except (socket.timeout, ConnectionResetError):
                        pass
            except:
                pass
        return open_ports

    def extract_http_title(self, banner):
        #HTML 본문에서 <title> 태그 내용 추출
        try:
            # 정규식: <title>...</title> (대소문자 무시, 줄바꿈 포함)
            match = re.search(r'<title[^>]*>(.*?)</title>', banner, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # HTML 엔티티 제거 및 길이 제한
                title = re.sub(r'<[^>]+>', '', title) # 태그 제거
                title = title.replace("\n", "").replace("\r", "")
                return title[:50] # 너무 길면 자름
        except:
            pass
        return None

    def analyze_banner(self, banner, port):
        service = "Unknown"
        version = ""
        is_matched = False
        
        # 1. 정규식 매칭
        for pattern, product_name, category in self.SIGNATURES:
            try:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service = product_name
                    if match.lastindex and match.lastindex >= 1:
                        version = match.group(1)
                    is_matched = True
                    break
            except re.error:
                continue 
        
        #HTTP 서비스인 경우 Title 추출 시도
        extra_info = ""
        if port in [80, 8080, 443] or "HTTP" in service.upper():
            title = self.extract_http_title(banner)
            if title:
                extra_info = f" | Title: {title}"

        # 2. 매칭 실패 시 원본 보존
        if not is_matched:
            raw_info = banner[:40] + "..." if len(banner) > 40 else banner
            common_ports = {21:'FTP', 22:'SSH', 23:'Telnet', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 8080:'HTTP-Proxy'}
            base_service = common_ports.get(port, 'TCP')
            return f"{base_service} ({raw_info}){extra_info}"

        # 3. 매칭 성공 시
        final_info = f"{service}"
        if version:
            final_info += f" {version}"
        
        return final_info + extra_info

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
            
            #Title 추출을 위해 읽는 바이트 수 증가
            raw_data = sock.recv(4096)
            
            # 인코딩 처리 (한글 타이틀 지원)
            try:
                banner_raw = raw_data.decode('utf-8', errors='strict').strip()
            except UnicodeDecodeError:
                banner_raw = raw_data.decode('cp949', errors='ignore').strip()
            
        except: pass
        finally: sock.close()

        if banner_raw:
            return self.analyze_banner(banner_raw, port)
        else:
            return "Unknown (No Banner)"