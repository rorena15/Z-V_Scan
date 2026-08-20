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
import ssl
import json
import struct # UDP 패킷 구조체 생성용
import time
from concurrent.futures import ThreadPoolExecutor

# 상위 디렉토리(프로젝트 루트)를 시스템 경로에 추가
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from utils.os_utils import OSUtils
from utils.logger import AppLogger
from utils.oui_lookup import OUILookup

class AdvancedScanner:
    #[Z-VulnScan Pro Advanced Scanner Engine]
    #Features:
    #1. TCP Connect Scan & Service Fingerprinting
    #2. UDP Payload Scan (Nmap -sU Style)
    #3. HTTP Title Extraction (Asset Identification)
    #4. Passive OS Fingerprinting (TTL)

    # [최적화] worker.py의 discover_target()이 호스트마다 AdvancedScanner()를 새로
    # 생성하므로 인스턴스 속성 캐시는 소용없다 - 클래스 변수로 스캔 세션 전체에서
    # 로컬 IP 조회 결과를 공유한다(대상 IP가 바뀌어도 "내 PC의 IP" 자체는 안 바뀜).
    _local_ip_cache = None

    def __init__(self):
        # 기본 스캔 대상 포트
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 8080]
        
        # [Strategy 1] TCP Service Probes
        # [Update v4.4] HTTP Title 수집을 위해 HEAD -> GET 변경
        # [버그 수정] 80/8080/443은 예전엔 여기서 "Host: 127.0.0.1"로 고정된 정적 바이트를
        # 썼는데, 이름 기반 가상 호스트(Apache/Nginx의 흔한 기본 구성)를 쓰는 서버는
        # Host 헤더로 응답할 사이트를 결정한다 - 실제 대상 IP가 아니라 127.0.0.1을 보내면
        # 엉뚱한 기본/에러 페이지가 오거나 400이 나서 Title/서비스 정보가 잘못 수집된다.
        # 그래서 HTTP 계열은 여기 정적으로 안 두고 grab_banner()에서 실제 ip로 매번
        # 새로 만든다 - 이 dict에는 더 이상 80/8080/443을 넣지 않는다.
        self.HTTP_PORTS = (80, 8080, 443)
        self.PROBES = {
            21: None,
            22: None,
            23: None,
            25: b"EHLO z-vulnscan\r\n", 
        }

        # [Strategy 3] UDP Payloads
        self.UDP_PROBES = {
            53:  b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01", 
            123: b"\xe3\x00\x06\xec" + b"\x00"*44, 
            137: b"\x80\x96\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01", 
            161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 
            1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n" 
        }

        self.SIGNATURES = [] 
        self.load_signatures()
    
    def get_system_vendor(self):
        try:
            # 윈도우가 아니면 실행 안 함
            if not OSUtils.is_windows():
                return None

            # creationflags=0x08000000 : CMD 창 깜빡임 방지
            cmd = "wmic csproduct get vendor"
            output = subprocess.check_output(cmd, shell=True, creationflags=0x08000000).decode('utf-8', errors='ignore')
            
            lines = output.strip().splitlines()
            for line in lines:
                cleaned = line.strip()
                if not cleaned or "Vendor" in cleaned:
                    continue
                return cleaned # 진짜 벤더 이름 반환 (예: innotek GmbH)
                
        except:
            pass
        return None

    def load_signatures(self):
        #[Hybrid Loader] 외부 JSON 룰 우선, 없으면 내부 기본값
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        external_path = os.path.join(base_dir, 'rules', 'signatures.json')
        
        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', 'signatures.json')
        else:
            internal_path = external_path

        target_path = external_path if os.path.exists(external_path) else internal_path
        
        if target_path and os.path.exists(target_path):
            try:
                with open(target_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        if 'pattern' in item and 'service' in item:
                            self.SIGNATURES.append((
                                item['pattern'], 
                                item['service'], 
                                item.get('category', 'General')
                            ))
                AppLogger.log_info(f"[Config] Loaded {len(self.SIGNATURES)} signatures.")
            except Exception as e:
                AppLogger.log_error(f"[Config] Failed to parse signatures.json", e)
                self._load_hardcoded_defaults()
        else:
            self._load_hardcoded_defaults()

    def _load_hardcoded_defaults(self):
        self.SIGNATURES = [
            (r'^SSH-[\d.]+-OpenSSH_([\w.]+)', "OpenSSH", "SSH"),
            (r'Server:\s*Apache/([\d.]+)', "Apache httpd", "HTTP"),
            (r'Server:\s*nginx/([\d.]+)', "Nginx", "HTTP"),
            (r'Server:\s*Microsoft-IIS/([\d.]+)', "Microsoft IIS", "HTTP"),
            (r'.*(\d+\.\d+\.\d+-MariaDB).*', "MariaDB", "MySQL"),
        ]
    
    @staticmethod
    def parse_ports(port_str):
        if not re.match(r'^[\d,-]+$', port_str): return []
        ports = set()
        try:
            parts = port_str.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    s, e = map(int, part.split('-'))
                    for p in range(s, e + 1): ports.add(p)
                else:
                    ports.add(int(part))
        except: pass
        return sorted(list(ports))

    def estimate_os_from_ttl(self, ttl):
        if ttl is None: return "Unknown"
        try:
            ttl = int(ttl)
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            elif ttl > 128: return "Network Device"
            else: return "Unknown"
        except: return "Unknown"

    def get_mac_address(self, ip):
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]: return "Localhost"
        if not OSUtils.is_safe_host(ip): return "Unknown"
        mac_address = "Unknown"
        try:
            # [수정] "arp -a <ip>" 식 IP 필터링은 일부 Windows 환경에서 같은 서브넷
            # 대상조차 "No ARP Entries Found"로 잘못 응답하는 경우가 있어(직전 ping으로
            # 커널 ARP 캐시엔 실제로 항목이 생겼는데도), 필터 없이 전체 ARP 테이블을
            # 받아와 대상 IP가 포함된 줄에서 직접 MAC을 찾는 방식으로 바꿨다.
            cmd = ["arp", "-a"] if OSUtils.is_windows() else ["arp", "-n"]
            kwargs = OSUtils.get_subprocess_kwargs() if OSUtils.is_windows() else {}

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2, **kwargs)
            if proc.returncode == 0:
                # IP가 다른 IP의 앞부분과 겹치는 경우(예: "10.0.0.1"이 "10.0.0.100"에 포함)를
                # 피하기 위해 앞뒤로 숫자가 이어지지 않는 정확한 위치에서만 매칭한다.
                ip_pattern = re.compile(rf'(?<!\d){re.escape(ip)}(?!\d)')
                for line in proc.stdout.splitlines():
                    if ip_pattern.search(line):
                        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line)
                        if mac_match:
                            mac_address = mac_match.group(0).upper().replace("-", ":")
                            break
        except: pass
        return mac_address

    @classmethod
    def _get_local_ip(cls):
        """스캔을 실행 중인 이 PC 자신의 IP - 클래스 변수에 캐시해 매 호스트마다
        다시 조회하지 않는다(값이 스캔 도중 바뀔 일이 없음)."""
        if cls._local_ip_cache is None:
            try:
                cls._local_ip_cache = socket.gethostbyname(socket.gethostname())
            except OSError:
                cls._local_ip_cache = ""
        return cls._local_ip_cache

    def resolve_hostname(self, ip):
        """[Discovery 단계 hostname] 인증 정보 없이도 역DNS(PTR)로 hostname을 얻어본다.
        실패해도 예외를 던지지 않고 None만 반환 - 호출부(worker.py)가 기존 vendor 기반
        placeholder로 폴백한다. socket.gethostbyaddr()는 타임아웃 인자를 받지 않으므로
        전역 기본 타임아웃을 짧게 걸었다가 반드시 원복한다."""
        if ip in ["127.0.0.1", "localhost", "0.0.0.0"]: return None
        if not OSUtils.is_safe_host(ip): return None
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(1.0)
            name, _, _ = socket.gethostbyaddr(ip)
            return name or None
        except (socket.herror, socket.gaierror, OSError):
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)

    def host_discovery(self, ip):
        is_alive = False
        detected_os = "Unknown"
        mac_address = "Unknown"
        vendor = "Unknown"
        try:
            cmd, kwargs = OSUtils.get_ping_command(ip)
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, **kwargs)
            if proc.returncode == 0:
                is_alive = True
                try: output = proc.stdout.decode('cp949', errors='ignore') 
                except: output = proc.stdout.decode('utf-8', errors='ignore')
                
                ttl_match = re.search(r'ttl[=< ]?(\d+)', output, re.IGNORECASE)
                if ttl_match: detected_os = self.estimate_os_from_ttl(int(ttl_match.group(1)))
                
                mac_address = self.get_mac_address(ip)
                vendor = OUILookup.lookup(mac_address)

                # [수정] OUILookup.lookup()은 MAC 조회 실패 시 "Unknown"이 아니라
                # "Unknown Vendor"를 반환하므로, 예전 "vendor == 'Unknown'" 비교는 항상
                # 거짓이 되어 아래 wmic 폴백이 죽어 있었다. MAC 자체가 안 잡혔는지로 직접 판단한다.
                #만약 MAC으로 벤더를 못 찾았고, 내 로컬 PC(localhost)를 스캔 중이라면 wmic 시도
                if mac_address == "Unknown" and ip in ["127.0.0.1", "localhost", self._get_local_ip()]:
                    wmic_vendor = self.get_system_vendor()
                    if wmic_vendor:
                        vendor = wmic_vendor

        except: pass
        return is_alive, detected_os, mac_address, vendor

    # [성능 개선] 포트 단위 병렬 스캔 시 동시 소켓 수 상한 - 무제한 병렬은 로컬
    # 소켓/파일디스크립터 고갈이나 상대측에 SYN 폭주로 보일 수 있어 상한을 둔다.
    _PORT_SCAN_MAX_WORKERS = 50

    def tcp_scan(self, ip, ports=None, delay=0):
        target_ports = ports if ports else self.default_ports
        timeout = 1

        def _check(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return port
            except: pass
            return None

        # [OT/저속 모드] delay가 있으면(=OT 모드) 순차 + 딜레이를 그대로 유지한다 -
        # delay 자체가 "연결 시도 폭주를 의도적으로 줄인다"는 안전장치라, 여기서
        # 병렬화하면 그 취지가 무력화된다. delay가 없을 때(일반 모드)만 병렬화해
        # 대용량 커스텀 포트 범위의 스캔 시간을 줄인다.
        # [버그 수정] "if result"/"if p"는 파이썬에서 0을 falsy로 취급해서, 포트 0이
        # 열려있어도(커스텀 범위에 0이 포함된 경우) 결과에서 조용히 빠졌다.
        # _check()는 실패 시 None, 성공 시 포트 번호(0 포함)를 반환하므로
        # "is not None"으로 명확히 구분한다.
        if delay:
            open_ports = []
            for port in target_ports:
                result = _check(port)
                if result is not None:
                    open_ports.append(result)
                time.sleep(delay)
            return open_ports

        if not target_ports:
            return []
        with ThreadPoolExecutor(max_workers=min(self._PORT_SCAN_MAX_WORKERS, len(target_ports))) as executor:
            return [p for p in executor.map(_check, target_ports) if p is not None]

    def udp_scan(self, ip, ports=None, delay=0):
        target_ports = ports if ports else [53, 123, 137, 161, 1900]
        timeout = 1.0

        def _check(port):
            payload = self.UDP_PROBES.get(port, b"")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(payload, (ip, port))
                    try:
                        data, _ = s.recvfrom(1024)
                        return (port, "UDP-Open", len(data))
                    except (socket.timeout, ConnectionResetError):
                        pass
            except:
                pass
            return None

        # [OT/저속 모드] tcp_scan과 동일한 원칙 - delay 있으면 순차 유지, 없으면 병렬화
        if delay:
            open_ports = []
            for port in target_ports:
                result = _check(port)
                if result:
                    open_ports.append(result)
                time.sleep(delay)
            return open_ports

        if not target_ports:
            return []
        with ThreadPoolExecutor(max_workers=min(self._PORT_SCAN_MAX_WORKERS, len(target_ports))) as executor:
            return [r for r in executor.map(_check, target_ports) if r]

    def extract_http_title(self, banner):
        #HTML 본문에서 <title> 태그 내용 추출
        try:
            # 정규식: <title>...</title> (대소문자 무시, 줄바꿈 포함)
            match = re.search(r'<title[^>]*>(.*?)</title>', banner, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # HTML 엔티티 제거 및 길이 제한
                title = re.sub(r'<[^>]+>', '', title) # 태그 제거
                title = title.replace("\n", "").replace("\r", "")
                return title[:50] # 너무 길면 자름
        except:
            pass
        return None

    def analyze_banner(self, banner, port):
        service = "Unknown"
        version = ""
        is_matched = False
        
        # 1. 정규식 매칭
        for pattern, product_name, category in self.SIGNATURES:
            try:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service = product_name
                    if match.lastindex and match.lastindex >= 1:
                        version = match.group(1)
                    is_matched = True
                    break
            except re.error:
                continue 
        
        #HTTP 서비스인 경우 Title 추출 시도
        extra_info = ""
        if port in [80, 8080, 443] or "HTTP" in service.upper():
            title = self.extract_http_title(banner)
            if title:
                extra_info = f" | Title: {title}"

        # 2. 매칭 실패 시 원본 보존
        if not is_matched:
            raw_info = banner[:40] + "..." if len(banner) > 40 else banner
            common_ports = {21:'FTP', 22:'SSH', 23:'Telnet', 80:'HTTP', 443:'HTTPS', 3306:'MySQL', 8080:'HTTP-Proxy'}
            base_service = common_ports.get(port, 'TCP')
            return f"{base_service} ({raw_info}){extra_info}"

        # 3. 매칭 성공 시
        final_info = f"{service}"
        if version:
            final_info += f" {version}"
        
        return final_info + extra_info

    def grab_banner(self, ip, port):
        banner_raw = ""
        if port in self.HTTP_PORTS:
            # [버그 수정] Host 헤더를 실제 대상 ip로 채운다(위 __init__ 주석 참고) -
            # 가상 호스트 서버에서 정확한 사이트의 Title/배너를 받기 위함.
            probe_data = (
                f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Z-VulnScan\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
        else:
            probe_data = self.PROBES.get(port, b"\r\n")
        # [버그 수정] 예전엔 sock = socket.socket(...)이 try 블록 "안"에 있으면서
        # finally에서 sock.close()를 호출했다. socket.socket() 생성 자체가 실패하면
        # (예: 대량 동시 스캔 중 파일 디스크립터 고갈, "Too many open files") sock 변수가
        # 아예 할당되지 못한 채로 finally가 실행되어 UnboundLocalError가 발생하고, 그
        # 예외는 바깥 except에도 안 잡혀 그대로 전파된다(실측 확인됨) - 스캔 부하가
        # 가장 높을 때, 즉 이 실패가 가장 잘 나는 바로 그 순간에 해당 호스트의 나머지
        # 포트/배너/UDP 스캔이 통째로 중단되는 결과로 이어진다. sock=None으로 미리
        # 초기화하고 finally에서 존재할 때만 닫는다.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)

            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try: sock = context.wrap_socket(sock, server_hostname=ip)
                except: pass

            sock.connect((ip, port))
            if probe_data: sock.send(probe_data)

            #Title 추출을 위해 읽는 바이트 수 증가
            raw_data = sock.recv(4096)

            # 인코딩 처리 (한글 타이틀 지원)
            try:
                banner_raw = raw_data.decode('utf-8', errors='strict').strip()
            except UnicodeDecodeError:
                banner_raw = raw_data.decode('cp949', errors='ignore').strip()

        except: pass
        finally:
            if sock is not None:
                sock.close()

        if banner_raw:
            return self.analyze_banner(banner_raw, port)
        else:
            return "Unknown (No Banner)"