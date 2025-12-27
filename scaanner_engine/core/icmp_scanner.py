import ipaddress
from scapy.all import IP, ICMP, sr1, conf
import logging

# Scapy의 불필요한 콘솔 출력 끄기
conf.verb = 0

class ICMPScanner:
    def __init__(self):
        # 로깅 설정
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger("ICMP_Scanner")

    def scan_network(self, network_cidr):
        """
        지정된 네트워크 대역(CIDR)에 대해 ICMP Ping Sweep을 수행합니다.
        :param network_cidr: 스캔할 네트워크 대역 (예: '192.168.0.0/24')
        :return: 활성 호스트 IP 리스트
        """
        live_hosts = []
        
        # 1. ipaddress 모듈을 사용해 CIDR을 개별 IP로 변환
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            self.logger.error(f"유효하지 않은 네트워크 대역입니다: {network_cidr}")
            return []

        self.logger.info(f"Start ICMP Sweep on: {network_cidr} (Total: {network.num_addresses} hosts)")

        # 2. 모든 IP에 대해 패킷 전송 (브로드캐스트 주소, 네트워크 주소 제외 가능)
        for ip in network.hosts():
            ip_str = str(ip)
            
            # [핵심 로직] Scapy를 이용한 패킷 수동 조립
            # IP Header(목적지) + ICMP Header(Echo Request, Type 8)
            packet = IP(dst=ip_str)/ICMP()
            
            # 패킷 전송 및 응답 대기 (timeout=1초)
            resp = sr1(packet, timeout=1, verbose=0)

            # 3. 응답 분석 (Type 0 == Echo Reply 인지 확인)
            if resp:
                # 응답 패킷이 ICMP 계층을 가지고 있는지 확인
                if resp.haslayer(ICMP):
                    # ICMP 타입이 0 (Echo Reply)이면 살아있는 호스트
                    if resp.getlayer(ICMP).type == 0:
                        self.logger.info(f"[+] Live Host Found: {ip_str}")
                        live_hosts.append(ip_str)
        
        self.logger.info(f"Scan Completed. Found {len(live_hosts)} live hosts.")
        return live_hosts

# --- 테스트 실행 코드 (메인) ---
if __name__ == "__main__":
    scanner = ICMPScanner()
    
    # 테스트할 네트워크 대역 (본인 환경에 맞게 수정하세요)
    # 예: 공유기 환경이라면 192.168.0.0/24 또는 172.30.1.0/24 등
    target_network = "172.30.0.0/16" 
    
    print(f"[*] Scanning {target_network}...")
    active_hosts = scanner.scan_network(target_network)
    
    print("\n[최종 결과 - 활성 호스트 목록]")
    for host in active_hosts:
        print(f" - {host}")