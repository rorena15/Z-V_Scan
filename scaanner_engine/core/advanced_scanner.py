import logging
from scapy.all import IP, ICMP, TCP, sr1, conf
import socket

# Scapy 콘솔 출력 끄기
conf.verb = 0

class AdvancedScanner:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger("AdvancedScanner")
        
        # 자주 쓰이는 주요 포트 목록 (Top Ports)
        self.target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]

    def host_discovery(self, ip):
        #[1단계: 호스트 탐지] 
        #ICMP Ping이 차단될 경우를 대비해 TCP ACK Ping을 병행하여 생존 여부를 확인합니다.
        #is_alive = False
        # 1-1. ICMP Ping 시도
        icmp_resp = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if icmp_resp:
            self.logger.info(f"[Host Up] {ip} (Reason: ICMP Reply)")
            return True
        
        # 1-2. TCP ACK Ping 시도 (방화벽 우회)
        # 80번 포트로 ACK 패킷 전송 -> 살아있다면 RST(Reset) 응답이 옴
        ack_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="A"), timeout=1, verbose=0)
        if ack_resp:
            self.logger.info(f"[Host Up] {ip} (Reason: TCP ACK Response)")
            return True
            
        return False

    def syn_scan(self, ip):
        #[2단계: 스텔스 포트 스캔]
        #TCP 3-Way Handshake를 맺지 않고 SYN 패킷만 보내 포트 개방 여부를 확인합니다.
        #로그를 남기지 않기 위해 연결 수립 전 RST를 보냅니다.
        open_ports = []
        self.logger.info(f"[*] Starting SYN Scan on {ip}...")

        for port in self.target_ports:
            # SYN 패킷 전송
            syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
            resp = sr1(syn_packet, timeout=1, verbose=0)

            if resp:
                # 응답 플래그 확인 (SYN+ACK = 0x12 or 18)
                if resp.haslayer(TCP):
                    flags = resp.getlayer(TCP).flags
                    if flags == 0x12: # SYN/ACK
                        self.logger.info(f"   [+] Open Port: {port}/tcp")
                        open_ports.append(port)
                        # 연결을 끊기 위해 RST 전송 (Stealth)
                        rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                        sr1(rst_packet, timeout=1, verbose=0)
        return open_ports

    def grab_banner(self, ip, port):
        #[3단계: 서비스 버전 식별]
        #열린 포트에 실제 소켓 연결을 시도하여 배너(Server Header)를 가져옵니다.
        #이 정보는 추후 CVE 취약점 매핑에 사용됩니다.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            
            # 일부 서비스(FTP, SSH 등)는 연결 즉시 배너를 보냄
            # HTTP의 경우 요청을 보내야 함
            if port in [80, 8080, 443]:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            if banner:
                self.logger.info(f"   [i] Banner ({port}): {banner[:50]}...") # 너무 길면 자름
                return banner
        except Exception:
            pass
        return "Unknown Service"

    def run_full_scan(self, target_ip):
        #전체 로직 실행 함수
        print(f"\n--- Scanning Target: {target_ip} ---")
        
        # 1. 생존 확인
        if not self.host_discovery(target_ip):
            print(f"[-] Host {target_ip} seems down.")
            return

        # 2. 포트 스캔
        open_ports = self.syn_scan(target_ip)
        
        # 3. 배너 그래빙 (열린 포트에 대해서만 수행)
        for port in open_ports:
            banner = self.grab_banner(target_ip, port)
            # (추후 이 정보를 DB에 저장합니다)

# --- 테스트 실행 ---
if __name__ == "__main__":
    scanner = AdvancedScanner()
    
    # 테스트할 타겟 IP (허가된 자산에 대해서만 수행하세요)
    target = "192.168.0.1" 
    scanner.run_full_scan(target)