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

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    def __init__(self):
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
        
        #Service Probes (트리거 패킷)
        self.PROBES = {
            80: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            8080: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            443: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            21: None, 22: None, 23: None, 
            25: b"EHLO z-vulnscan\r\n", 
        }

        #Service Fingerprints (정규식 DB)
        self.SIGNATURES = [
            # SSH
            (r'^SSH-[\d.]+-OpenSSH_([\w.]+)', "OpenSSH", "SSH"),
            (r'^SSH-[\d.]+-([\w.]+)', "Generic SSH", "SSH"),
            # HTTP Server
            (r'Server:\s*Apache/([\d.]+)', "Apache httpd", "HTTP"),
            (r'Server:\s*nginx/([\d.]+)', "Nginx", "HTTP"),
            (r'Server:\s*Microsoft-IIS/([\d.]+)', "Microsoft IIS", "HTTP"),
            (r'Server:\s*([^\r\n]+)', "Generic Web Server", "HTTP"),
            # FTP
            (r'220\s+.*\s+vsFTPd\s+([\d.]+)', "vsftpd", "FTP"),
            (r'220\s+.*\s+FileZilla Server\s+version\s+([\d.]+)', "FileZilla", "FTP"),
            (r'220\s+Microsoft FTP Service', "Microsoft FTP", "FTP"),
            # Database
            (r'.*(\d+\.\d+\.\d+-MariaDB).*', "MariaDB", "MySQL"),
            (r'.*(\d+\.\d+\.\d+).*mysql_native_password', "MySQL", "MySQL"),
            # Email
            (r'220\s+.*ESMTP Postfix', "Postfix", "SMTP"),
            (r'220\s+.*ESMTP Sendmail', "Sendmail", "SMTP"),
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
                    start, end = map(int, part.split('-'))
                    for p in range(start, end + 1):
                        if 1 <= p <= 65535: ports.add(p)
                else:
                    p = int(part)
                    if 1 <= p <= 65535: ports.add(p)
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