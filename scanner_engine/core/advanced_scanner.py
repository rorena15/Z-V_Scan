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

# 상위 폴더 모듈
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    def __init__(self):
        # 주요 점검 포트
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]

    @staticmethod
    def parse_ports(port_str):
        #포트 문자열 파싱
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
            #파싱 에러 기록
            AppLogger.log_error(f"Port Parse Error: {port_str}", e)
            pass
        return sorted(list(ports))

    def estimate_os_from_ttl(self, ttl):
        #TTL 값을 기반으로 OS 추정 (Scapy 대체 로직)
        try:
            ttl = int(ttl)
            # 일반적인 초기 TTL 값: Windows(128), Linux(64), Network Device(255)
            # 라우팅 경로에 따라 1~2 정도 감소할 수 있음을 감안하여 범위 설정
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            elif ttl > 128: return "Network Device"
            else: return "Unknown"
        except:
            return "Unknown"

    def get_mac_address(self, ip):
        #ARP 테이블을 조회하여 MAC 주소 추출
        #- Ping 성공 직후 운영체제의 ARP 캐시 테이블(arp -a)을 조회합니다.
        #- Npcap 드라이버 없이 순수 OS 명령어로 작동합니다.
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            return "Localhost"
        mac_address = "Unknown"
        try:
            # 윈도우/리눅스 명령어 분기
            if OSUtils.is_windows():
                cmd = f"arp -a {ip}"
            else:
                cmd = f"arp -n {ip}"
            
            # ARP 조회 실행
            kwargs = OSUtils.get_hidden_kwargs() if OSUtils.is_windows() else {}
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1, shell=True, **kwargs)
            
            if proc.returncode == 0:
                output = proc.stdout
                # 정규식: XX-XX-XX-XX-XX-XX (Win) 또는 XX:XX:XX:XX:XX:XX (Linux)
                # ([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}) 패턴 매칭
                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if mac_match:
                    mac_address = mac_match.group(0).upper().replace("-", ":")
        except Exception as e:
            # ARP 조회 실패는 치명적이지 않으므로 디버그 로그만 남김
            AppLogger.log_error(f"Arp MAC Query Fail {ip}:{mac_match}", e)
            pass
            
        return mac_address

    def host_discovery(self, ip):
        is_alive = False
        detected_os = "Unknown"
        mac_address = "Unknown"
        vendor = "Unknown"
        
        try:
            # Native Ping을 이용한 생존 확인 + OS 탐지 + MAC/Vendor 식별
            # Returns: (is_alive, detected_os, mac_address, vendor)
            cmd, kwargs = OSUtils.get_ping_command(ip)
            # capture_output=True로 설정하여 결과 텍스트를 받아옴
            # kwargs에 hidden window 설정이 포함되어 있음
            proc = subprocess.run(cmd, capture_output=True, timeout=2, **kwargs)
            
            if proc.returncode == 0:
                is_alive = True
                
                # 출력 결과 디코딩 (Windows 한글 CP949 대응)
                try:
                    output = proc.stdout.decode('cp949') 
                except:
                    output = proc.stdout.decode('utf-8', errors='ignore')
                
                try:
                    # TTL, ttl, Ttl 모두 대응
                    ttl_match = re.search(r'ttl[=< ]?(\d+)', output, re.IGNORECASE)
                    if ttl_match:
                        ttl_value = int(ttl_match.group(1))
                        detected_os = self.estimate_os_from_ttl(ttl_value)
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
        #TCP Connect Scan (안전한 소켓 관리 적용)
        target_ports = ports if ports else self.default_ports
        open_ports = []
        
        # 타임아웃: 로컬망 0.1~0.2, 외부망 0.5 (설정값)
        timeout = 0.2

        for port in target_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception as e:
                #타임아웃이 아닌 실제 에러만 로그 기록 (로그 폭주 방지)
                if not isinstance(e, socket.timeout):
                    AppLogger.log_error(f"Scan Error {ip}:{port}", e)
                pass
                
        return open_ports

    def grab_banner(self, ip, port):
        #서비스 배너 수집 (안전한 소켓 관리 적용)
        banner = "Unknown Service"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0) 
                s.connect((ip, port))
                
                if port in [80, 8080, 443]:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                
                # 데이터 수신
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except Exception as e:
            # 배너 수집 실패는 빈번하므로 디버그 용도로만 남김
            AppLogger.log_error(f"Banner grab failed {ip}:{port}", e)
            pass
        return banner if banner else "Unknown Service"