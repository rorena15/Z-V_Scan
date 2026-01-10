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
import ssl # HTTPS 배너 그래빙을 위해 추가

# 상위 폴더 모듈
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    def __init__(self):
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
        
        #서비스별 트리거 페이로드 정의
        self.PROBES = {
            80: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            8080: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            443: b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Z-VulnScan\r\n\r\n",
            21: None, # FTP는 접속 시 서버가 먼저 배너 전송
            22: None, # SSH도 서버가 먼저 전송
            23: None, 
            25: b"EHLO z-vulnscan\r\n", 
        }

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
        except Exception as e:
            AppLogger.log_error(f"Port Parse Error: {port_str}", e)
            pass
        return sorted(list(ports))

    def estimate_os_from_ttl(self, ttl):
        if ttl is None: return "Unknown"
        try:
            ttl = int(ttl)
            # 일반적 초기 TTL: Windows(128), Linux(64), Network Device(255)
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            elif ttl > 128: return "Network Device"
            else: return "Unknown"
        except:
            return "Unknown"

    def get_mac_address(self, ip):
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            return "Localhost"
        mac_address = "Unknown"
        try:
            if OSUtils.is_windows():
                cmd = f"arp -a {ip}"
            else:
                cmd = f"arp -n {ip}"
            
            kwargs = OSUtils.get_hidden_kwargs() if OSUtils.is_windows() else {}
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1, shell=True, **kwargs)
            
            if proc.returncode == 0:
                output = proc.stdout
                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if mac_match:
                    mac_address = mac_match.group(0).upper().replace("-", ":")
        except Exception:
            pass
            
        return mac_address

    def host_discovery(self, ip):
        is_alive = False
        detected_os = "Unknown"
        mac_address = "Unknown"
        vendor = "Unknown"
        
        try:
            cmd, kwargs = OSUtils.get_ping_command(ip)
            # capture_output 대신 pipe 사용 (PyInstaller 호환성)
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, **kwargs)
            
            if proc.returncode == 0:
                is_alive = True
                try:
                    output = proc.stdout.decode('cp949', errors='ignore') 
                except:
                    output = proc.stdout.decode('utf-8', errors='ignore')
                
                try:
                    ttl_match = re.search(r'ttl[=< ]?(\d+)', output, re.IGNORECASE)
                    if ttl_match:
                        detected_os = self.estimate_os_from_ttl(int(ttl_match.group(1)))
                    else:
                        detected_os = "Unknown (No TTL)"
                except Exception:
                    detected_os = "Unknown (Parse Error)"
                
                mac_address = self.get_mac_address(ip)
                vendor = OUILookup.lookup(mac_address)
            else:
                is_alive = False

        except subprocess.TimeoutExpired:
            is_alive = False
        except Exception as e:
            AppLogger.log_error(f"{ip} Host Discovery Failed", e)

        return is_alive, detected_os, mac_address, vendor

    def tcp_scan(self, ip, ports=None):
        target_ports = ports if ports else self.default_ports
        open_ports = []
        timeout = 0.2

        for port in target_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception:
                pass
                
        return open_ports

    def grab_banner(self, ip, port):
        #SSL/TLS 지원 및 포트별 맞춤 패킷 전송
        banner = "Unknown Service"
        probe_data = self.PROBES.get(port, b"\r\n") 
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            
            # HTTPS(443) SSL 래핑 시도
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock, server_hostname=ip)
                except:
                    pass 

            sock.connect((ip, port))

            if probe_data:
                sock.send(probe_data)

            raw_data = sock.recv(2048)
            decoded_data = raw_data.decode('utf-8', errors='ignore').strip()
            
            if decoded_data:
                lines = decoded_data.split('\n')
                first_line = lines[0].strip()
                
                if "HTTP/" in first_line or "Server:" in decoded_data:
                    server_match = re.search(r'Server:\s*(.*)', decoded_data, re.IGNORECASE)
                    if server_match:
                        banner = f"HTTP Server: {server_match.group(1).strip()}"
                    else:
                        banner = first_line[:50]
                else:
                    banner = first_line[:50]

        except socket.timeout:
            banner = "No Banner (Timeout)"
        except Exception:
            banner = "Unknown"
        finally:
            sock.close()

        return banner if banner else "Unknown Service"