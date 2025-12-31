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
from utils.db_connector import DBConnector # [유지] 기존 의존성 유지
from utils.os_utils import OSUtils

class AdvancedScanner:
    def __init__(self):
        # 주요 점검 포트
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]

    @staticmethod
    def parse_ports(port_str):
        """포트 문자열 파싱"""
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
        except:
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

    def host_discovery(self, ip):
        #Native Ping을 이용한 생존 확인 및 OS 탐지 (터미널 팝업 없음)
        is_alive = False
        detected_os = "Unknown"
        
        try:
            # OSUtils에서 명령어와 Hidden Window 옵션을 받아옴
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
                
                # 정규식으로 TTL 값 추출 (대소문자 무시)
                # Windows: "TTL=128", Linux: "ttl=64"
                ttl_match = re.search(r'ttl[=< ]?(\d+)', output, re.IGNORECASE)
                
                if ttl_match:
                    ttl_value = int(ttl_match.group(1))
                    detected_os = self.estimate_os_from_ttl(ttl_value)
                else:
                    detected_os = "Unknown (No TTL)"
            else:
                is_alive = False

        except subprocess.TimeoutExpired:
            is_alive = False
        except Exception as e:
            print(f"[Error] {ip} Host Discovery Failed: {e}")

        return is_alive, detected_os

    def syn_scan(self, ip, ports=None):
        #TCP Connect Scan (이름은 호환성을 위해 syn_scan 유지)
        #Scapy 제거 -> 순수 소켓 연결 방식으로 변경 (관리자 권한 불필요)
        target_ports = ports if ports else self.default_ports
        open_ports = []
        
        # 타임아웃: 로컬망이면 0.1~0.2초 충분, 외부망이면 0.5초 권장
        timeout = 0.2 

        for port in target_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                # connect_ex는 성공 시 0 반환
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except:
                pass
        return open_ports

    def grab_banner(self, ip, port):
        """서비스 배너 수집 (기존 로직 유지, 터미널과 무관)"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, port))
            
            if port in [80, 8080, 443]:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner if banner else "Unknown Service"
        except:
            return "Unknown Service"