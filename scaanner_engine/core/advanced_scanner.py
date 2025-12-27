import logging
from scapy.all import IP, ICMP, TCP, sr1, conf
import socket
import sys
import os

# 상위 폴더 모듈 참조를 위한 설정
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector

# Scapy 콘솔 출력 끄기
conf.verb = 0

class AdvancedScanner:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger("AdvancedScanner")
        
        # 자주 쓰이는 주요 포트 목록 (Top Ports)
        self.target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]

    def estimate_os(self, ttl):
        """
        [OS Fingerprinting] TTL 값을 기반으로 운영체제 추측
        """
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl > 128:
            return "Network Device (Cisco/Etc)"
        else:
            return "Unknown"

    def host_discovery(self, ip):
        """
        [호스트 탐지] ICMP/TCP Ping + OS 탐지
        Returns: (is_alive: bool, detected_os: str)
        """
        detected_os = "Unknown"
        
        try:
            # 1-1. ICMP Ping
            icmp_resp = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
            if icmp_resp:
                if IP in icmp_resp:
                    ttl = icmp_resp[IP].ttl
                    detected_os = self.estimate_os(ttl)
                return True, detected_os
            
            # 1-2. TCP ACK Ping (Port 80)
            ack_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="A"), timeout=0.5, verbose=0)
            if ack_resp:
                if IP in ack_resp:
                    ttl = ack_resp[IP].ttl
                    detected_os = self.estimate_os(ttl)
                return True, detected_os

        except Exception as e:
            self.logger.error(f"Host Discovery Error on {ip}: {e}")

        return False, "Unknown"

    def syn_scan(self, ip):
        """
        [스텔스 포트 스캔] SYN 패킷 전송 후 SYN-ACK 확인
        """
        open_ports = []
        # self.logger.info(f"[*] Starting SYN Scan on {ip}...") # 로그가 너무 많으면 주석 처리

        for port in self.target_ports:
            try:
                # SYN 패킷 전송
                syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
                resp = sr1(syn_packet, timeout=0.3, verbose=0) # Timeout을 0.3초로 줄여 속도 향상

                if resp and resp.haslayer(TCP):
                    flags = resp.getlayer(TCP).flags
                    # SYN+ACK (0x12 or 18) 응답이 오면 포트 열림
                    if flags == 0x12:
                        open_ports.append(port)
                        # 연결 끊기 (RST 전송)
                        rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                        sr1(rst_packet, timeout=0, verbose=0)
            except Exception:
                continue
                
        return open_ports

    def grab_banner(self, ip, port):
        """
        [배너 그래빙] 소켓 연결로 서비스 버전 확인
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # 타임아웃 0.5초
            s.connect((ip, port))
            
            # HTTP/HTTPS의 경우 요청을 보내야 배너를 줌
            if port in [80, 8080, 443]:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            if banner:
                return banner
        except Exception:
            pass
        return "Unknown Service"

    def run_full_scan(self, target_ip):
        """
        CLI 테스트용 통합 실행 함수
        """
        print(f"\n--- Scanning Target: {target_ip} ---")
        
        db = DBConnector()
        
        # 1. 생존 확인
        is_alive, detected_os = self.host_discovery(target_ip)
        
        if not is_alive:
            print(f"[-] Host {target_ip} seems down.")
            return

        print(f"[*] Host Up. OS: {detected_os}")
        asset_id = db.save_asset(target_ip, hostname="Detected_Host", os_type=detected_os)

        if asset_id:
            # 2. 포트 스캔
            open_ports = self.syn_scan(target_ip)
            print(f"[*] Open Ports: {open_ports}")
            
            # 3. 배너 그래빙
            for port in open_ports:
                banner = self.grab_banner(target_ip, port)
                print(f"    - Port {port}: {banner}")
                db.save_open_port(asset_id, port, banner)
        
        print("--- Scan & DB Save Completed ---")

# --- 테스트 실행 ---
if __name__ == "__main__":
    scanner = AdvancedScanner()
    # 테스트 IP (본인 환경에 맞게)
    target = "127.0.0.1" 
    scanner.run_full_scan(target)