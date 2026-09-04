# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import errno
import socket
import concurrent.futures
from utils.logger import AppLogger

class HostDiscovery:
    def __init__(self, max_workers=50, stop_check=None):
        # TCP SYN/ACK 스캔을 흉내내어 가장 흔한 포트만 빠르게 찌릅니다.
        # 우선순위 변경: 445(Win) -> 22(Linux) -> 80(Web) -> 135(RPC)
        # 이유: 445/22번이 열려있을 확률이 가장 높으므로 먼저 확인하여 루프 탈출 유도
        self.check_ports = [445, 22, 80, 135]
        self.timeout = 1
        # [OT 모드 연동] 생존 확인 단계도 동시성을 낮출 수 있도록 외부에서 지정 가능
        self.max_workers = max_workers
        # [Stop 버그 수정, 2026-09] 예전엔 scan_network()이 대상 IP 전부(예: /24
        # 스캔이면 254개)를 스레드풀에 한꺼번에 제출하고 as_completed()로 전부 끝날
        # 때까지 기다리기만 해서, 이 단계(스캔의 맨 처음 - 생존 호스트 찾기) 자체가
        # ScanWorker.stop_flag와 아예 연결돼 있지 않았다 - Stop을 눌러도 대상 범위가
        # 크면 전체 IP를 다 확인할 때까지 아무 반응이 없었다. worker.py가
        # lambda: self.stop_flag를 넘겨주면 스캔network()이 즉시 남은 작업을
        # 취소하고, check_host()도 포트 루프 중간에 바로 빠져나간다.
        self.stop_check = stop_check

    def check_host(self, ip):
        #단일 호스트 생존 확인 (TCP Connect 방식 - Non-Root 가능)
        for port in self.check_ports:
            if self.stop_check and self.stop_check():
                return None
            try:
                # Context Manager(with) 사용으로 소켓 자동 닫기 보장
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    
                    # [Optimized] SO_LINGER 옵션: 소켓 close 시 대기 시간 0으로 설정
                    # 대량 스캔 시 TIME_WAIT 상태의 좀비 소켓이 쌓이는 것을 방지
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 0) 
                    
                    result = s.connect_ex((ip, port))

                    # 0: Open (확실히 살아있음)
                    # ECONNREFUSED: Connection Refused (방화벽이 포트는 막았으나 호스트는 켜져 있음!)
                    # [버그 수정] 이전엔 10061(Windows WSAECONNREFUSED)을 하드코딩했는데, 이 값은
                    # 스캔 "실행 PC"가 Windows일 때만 맞다(Linux는 111, macOS는 61). errno 모듈이
                    # 각 OS에서 자동으로 올바른 값을 주므로 여기서는 그걸 쓴다.
                    if result == 0 or result == errno.ECONNREFUSED:
                        return ip
            except:
                pass
        return None

    def scan_network(self, ip_list):
        #멀티스레드로 대역 전체 생존 확인
        active_hosts = []
        # 로그 간소화 (너무 많은 로그 방지)
        AppLogger.log_info(f"Starting Host Discovery for {len(ip_list)} IPs...")
        
        # 스레드 풀: I/O Bound 작업 (OT 모드에서는 max_workers를 낮춰 동시 연결 시도를 최소화)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # futures 딕셔너리 생성
            future_to_ip = {executor.submit(self.check_host, ip): ip for ip in ip_list}

            for future in concurrent.futures.as_completed(future_to_ip):
                # [Stop 버그 수정] 아직 시작 안 한 나머지 작업은 즉시 취소, 지금 막
                # 끝난 것까지만 반영하고 루프를 빠져나온다(worker.py run()의
                # executor.shutdown(wait=False, cancel_futures=True) 패턴과 동일).
                if self.stop_check and self.stop_check():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                result = future.result()
                if result:
                    active_hosts.append(result)
        
        # IP 주소 정렬 (문자열 정렬 보정: 10이 2보다 뒤에 오도록)
        # [버그 수정] 마지막 옥텟만으로 정렬하면 대상이 여러 서브넷에 걸칠 때
        # (예: /23 CIDR 하나에 .0.x와 .1.x가 섞이는 경우) 서로 다른 대역의 IP가
        # 마지막 옥텟 값만으로 뒤섞여 정렬된다 - 4옥텟을 모두 비교해야 한다.
        try:
            active_hosts.sort(key=lambda ip: tuple(int(part) for part in ip.split('.')))
        except:
            active_hosts.sort()
            
        AppLogger.log_info(f"Host Discovery Complete. Found {len(active_hosts)} active hosts.")
        return active_hosts