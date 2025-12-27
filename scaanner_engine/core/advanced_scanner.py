import logging
from scapy.all import IP, ICMP, TCP, sr1, conf
import socket
import sys
import os
# 상위 디렉터리 모듈 import를 위한 경로 설정
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector # DB 커넥터 임포트

def run_full_scan(self, target_ip):
    print(f"\n--- Scanning Target: {target_ip} ---")
    
        # DB 연결 객체 생성
    db = DBConnector()
    
        # 1. 생존 확인
    if not self.host_discovery(target_ip):
        print(f"[-] Host {target_ip} seems down.")
        return

    # [DB 연동] 활성 자산 저장 (일단 OS는 Unknown으로 저장, 추후 OS 탐지 모듈 추가 시 업데이트)
    asset_id = db.save_asset(target_ip, hostname="Detected_Host", os_type="Linux/Unknown")

    if asset_id:
        # 2. 포트 스캔
        open_ports = self.syn_scan(target_ip)
        
            # 3. 배너 그래빙 및 DB 저장
        for port in open_ports:
            banner = self.grab_banner(target_ip, port)
            
            # [DB 연동] 포트 정보 저장
            db.save_open_port(asset_id, port, banner)
        
        print("--- Scan & DB Save Completed ---")

# Scapy 콘솔 출력 끄기
conf.verb = 0

class AdvancedScanner:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger("AdvancedScanner")
        self.target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]

    def estimate_os(self, ttl):
        #[OS Fingerprinting Logic]
        #TTL 값을 기반으로 운영체제를 추측합니다.
        #경로상의 라우터를 거칠 때마다 TTL이 1씩 감소하므로 범위를 지정하여 판단합니다.
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl > 128:
            return "Network Device (Cisco/Etc)"
        else:
            return "Unknown"

    def host_discovery(self, ip):

        #[수정됨] 호스트 생존 확인 및 OS 탐지
        #Returns: (is_alive: bool, detected_os: str)
        detected_os = "Unknown"
        
        # 1-1. ICMP Ping 시도
        icmp_resp = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if icmp_resp:
            # 응답 패킷의 IP 헤더에서 TTL 추출
            ttl = icmp_resp[IP].ttl
            detected_os = self.estimate_os(ttl)
            self.logger.info(f"[Host Up] {ip} (TTL: {ttl} -> {detected_os})")
            return True, detected_os
        
        # 1-2. TCP ACK Ping 시도 (방화벽 우회)
        ack_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="A"), timeout=1, verbose=0)
        if ack_resp:
            # TCP 응답(RST)에서도 TTL 추출 가능
            ttl = ack_resp[IP].ttl
            detected_os = self.estimate_os(ttl)
            self.logger.info(f"[Host Up] {ip} (TTL: {ttl} -> {detected_os}) - TCP ACK")
            return True, detected_os
            
        return False, "Unknown"

    # ... (syn_scan, grab_banner 메서드는 기존과 동일하므로 생략) ...

    def run_full_scan(self, target_ip):
        
        #[수정됨] 전체 로직 실행 함수
        print(f"\n--- Scanning Target: {target_ip} ---")
        
        # DB 연결 객체 생성
        # (상단 import 처리가 되어 있어야 합니다)
        from utils.db_connector import DBConnector 
        db = DBConnector()
        
        # 1. 생존 확인 및 OS 탐지
        is_alive, detected_os = self.host_discovery(target_ip)
        
        if not is_alive:
            print(f"[-] Host {target_ip} seems down.")
            return

        # [DB 연동 Update] 식별된 OS 정보를 함께 저장
        print(f"[*] Saving Asset Info: {target_ip} / {detected_os}")
        asset_id = db.save_asset(target_ip, hostname="Detected_Host", os_type=detected_os)

        if asset_id:
            # 2. 포트 스캔
            open_ports = self.syn_scan(target_ip)
            
            # 3. 배너 그래빙 및 DB 저장
            for port in open_ports:
                banner = self.grab_banner(target_ip, port)
                db.save_open_port(asset_id, port, banner)
        
        print("--- Scan & DB Save Completed ---")

# --- 테스트 실행 ---
if __name__ == "__main__":
    scanner = AdvancedScanner()
    # Windows PC(본인 PC)나 Linux 서버(WSL 등) IP로 테스트해보세요
    target = "192.168.0.10" 
    scanner.run_full_scan(target)