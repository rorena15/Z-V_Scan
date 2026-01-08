# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import socket
import concurrent.futures
from utils.logger import AppLogger

class HostDiscovery:
    def __init__(self):
        # 생존 확인용 주요 포트 (Windows/Linux 공통)
        # 135(RPC), 445(SMB), 80(Web), 22(SSH) 중 하나라도 열려있거나 거부(RST)되면 살아있는 것임
        self.check_ports = [135, 445, 80, 22] 
        self.timeout = 0.5 # 0.5초 안에 응답 없으면 죽은 걸로 간주 (빠른 속도 위주)

    def check_host(self, ip):
        """단일 호스트 생존 확인 (TCP Connect 방식 - Non-Root 가능)"""
        for port in self.check_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    
                    # 0: Open (확실히 살아있음)
                    # 10061: Connection Refused (방화벽이 있지만 호스트는 켜져 있음 -> 살아있음!)
                    if result == 0 or result == 10061:
                        return ip
            except:
                pass
        return None

    def scan_network(self, ip_list):
        """멀티스레드로 대역 전체 생존 확인"""
        active_hosts = []
        AppLogger.log_info(f"🔍 Starting Host Discovery for {len(ip_list)} IPs...")
        
        # 스레드 50~100개로 동시에 찔러봄 (매우 빠름)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # futures 딕셔너리 생성
            future_to_ip = {executor.submit(self.check_host, ip): ip for ip in ip_list}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    active_hosts.append(result)
        
        # IP 주소 정렬 후 반환
        # (문자열 정렬 문제를 피하기 위해 ip_address 객체 변환 후 정렬 추천하지만, 여기선 간단히)
        try:
            active_hosts.sort(key=lambda ip: int(ip.split('.')[-1]))
        except:
            pass
            
        AppLogger.log_info(f"✅ Host Discovery Complete. Found {len(active_hosts)} active hosts.")
        return active_hosts