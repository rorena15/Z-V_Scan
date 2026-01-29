# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import ipaddress
import logging
import subprocess
import concurrent.futures
import sys
import os

# 상위 폴더 모듈 참조 (필요 시)
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.os_utils import OSUtils
from utils.logger import AppLogger

class ICMPScanner:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger("ICMP_Scanner")
        self.max_threads = 50

    def _ping_host(self, ip):
        """개별 호스트 Ping 수행 (좀비 프로세스 방지 적용)"""
        ip_str = str(ip)
        try:
            cmd, kwargs = OSUtils.get_ping_command(ip_str)
            
            # [수정] subprocess.run 사용 + timeout 명시
            # timeout을 주어 무한 대기 방지 (OSUtils 설정보다 약간 넉넉하게 2초)
            proc = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL, 
                timeout=2, 
                **kwargs
            )
            
            if proc.returncode == 0:
                return ip_str
                
        except subprocess.TimeoutExpired:
            return None
            
        except PermissionError:
            # 권한 문제 명시적 기록
            AppLogger.log_error(f"Permission Denied pinging {ip_str}. (Try Run as Admin)")
            return None
            
        except FileNotFoundError:
            # ping 명령어 없음 기록
            AppLogger.log_error(f"Ping command not found. Check OS PATH.")
            return None
            
        except Exception as e:
            # 기타 에러
            AppLogger.log_error(f"Ping Failed for {ip_str}", e)
            pass
            
        return None

    def scan_network(self, network_cidr):
        #네이티브 Ping을 이용한 고속 병렬 스캔
        live_hosts = []
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            self.logger.error(f"유효하지 않은 네트워크 대역입니다: {network_cidr}")
            return []

        self.logger.info(f"Start Native Ping Sweep on: {network_cidr} (Threads: {self.max_threads})")
        
        # ThreadPoolExecutor를 사용하여 병렬 처리
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Future 객체 리스트 생성
            futures = {executor.submit(self._ping_host, ip): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"[+] Live Host Found: {result}")
                    live_hosts.append(result)
        
        self.logger.info(f"Scan Completed. Found {len(live_hosts)} live hosts.")
        return live_hosts

# 테스트 코드
if __name__ == "__main__":
    scanner = ICMPScanner()
    # 로컬 테스트 (주의: 스캔 대역이 너무 크면 오래 걸림)
    print(scanner.scan_network("192.168.0.0/24"))