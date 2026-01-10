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
        # TCP SYN/ACK 스캔을 흉내내어 가장 흔한 포트만 빠르게 찌릅니다.
        # 우선순위 변경: 445(Win) -> 22(Linux) -> 80(Web) -> 135(RPC)
        # 이유: 445/22번이 열려있을 확률이 가장 높으므로 먼저 확인하여 루프 탈출 유도
        self.check_ports = [445, 22, 80, 135] 
        self.timeout = 0.3 # 0.3초 (Local Network 최적화)

    def check_host(self, ip):
        #단일 호스트 생존 확인 (TCP Connect 방식 - Non-Root 가능)
        for port in self.check_ports:
            try:
                # Context Manager(with) 사용으로 소켓 자동 닫기 보장
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    
                    # [Optimized] SO_LINGER 옵션: 소켓 close 시 대기 시간 0으로 설정
                    # 대량 스캔 시 TIME_WAIT 상태의 좀비 소켓이 쌓이는 것을 방지
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 0) 
                    
                    result = s.connect_ex((ip, port))
                    
                    # 0: Open (확실히 살아있음)
                    # 10061: Connection Refused (방화벽이 포트는 막았으나 호스트는 켜져 있음!)
                    if result == 0 or result == 10061:
                        return ip
            except:
                pass
        return None

    def scan_network(self, ip_list):
        #멀티스레드로 대역 전체 생존 확인
        active_hosts = []
        # 로그 간소화 (너무 많은 로그 방지)
        AppLogger.log_info(f"Starting Host Discovery for {len(ip_list)} IPs...")
        
        # 스레드 풀: I/O Bound 작업이므로 50개 유지
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # futures 딕셔너리 생성
            future_to_ip = {executor.submit(self.check_host, ip): ip for ip in ip_list}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    active_hosts.append(result)
        
        # IP 주소 정렬 (문자열 정렬 보정: 10이 2보다 뒤에 오도록)
        try:
            active_hosts.sort(key=lambda ip: int(ip.split('.')[-1]))
        except:
            active_hosts.sort()
            
        AppLogger.log_info(f"Host Discovery Complete. Found {len(active_hosts)} active hosts.")
        return active_hosts