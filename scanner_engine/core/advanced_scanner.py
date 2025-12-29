# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import socket
import time
import sys
import os
import subprocess
import threading
from scapy.all import IP, ICMP, sr1, conf

# 상위 폴더 모듈 참조
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.db_connector import DBConnector

# Scapy 설정 (OS 탐지용으로만 제한적 사용)
conf.verb = 0
if os.name == 'nt':
    conf.use_pcap = True

# Scapy 충돌 방지용 락
scapy_lock = threading.Lock()

class AdvancedScanner:
    def __init__(self):
        # 주요 포트 리스트
        self.target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]

    @staticmethod
    def parse_ports(port_str):
        """포트 문자열 파싱 (예: '80,443' 또는 '1-100')"""
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
    
    def estimate_os(self, ttl):
        """TTL 기반 OS 추정"""
        if ttl <= 64: return "Linux/Unix"
        elif ttl <= 128: return "Windows"
        elif ttl > 128: return "Network Device"
        else: return "Unknown"

    def host_discovery(self, ip):
        """
        [고속 모드] Windows 시스템 Ping 명령어 사용
        Scapy보다 10배 빠르고, 스레드 충돌이 없음
        """
        is_alive = False
        detected_os = "Unknown"

        try:
            # 1. 시스템 Ping으로 생존 확인 (-n 1: 1회, -w 200: 타임아웃 200ms)
            # 윈도우는 'ping', 리눅스는 'ping -c 1'
            cmd = ['ping', '-n', '1', '-w', '200', ip] if os.name == 'nt' else ['ping', '-c', '1', '-W', '1', ip]
            startupinfo = None
            creationflags = 0
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW
                
            # subprocess를 이용해 백그라운드 실행
            ret = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,      # 창 숨김
                creationflags=creationflags   # 창 숨김 (PyInstaller 호환)
            )
            
            if ret.returncode == 0:
                is_alive = True
                
                # 2. 살아있다면 OS 탐지를 위해 딱 한 번만 Scapy 사용 (락 적용)
                # 여기가 병목이 되지 않도록 타임아웃을 짧게 설정
                try:
                    with scapy_lock:
                        # sr1 호출 전 아주 짧은 대기 (OS 파일 핸들 정리 시간 확보)
                        time.sleep(0.01)
                        ans = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
                    
                    if ans and IP in ans:
                        detected_os = self.estimate_os(ans[IP].ttl)
                    else:
                        detected_os = "Unknown (Firewall)"
                except OSError:
                    # [Errno 22] Invalid argument 발생 시 무시하고 넘어감
                    detected_os = "Unknown (Error)"
                except Exception:
                    detected_os = "Unknown"
        except OSError as e:
                    # 소켓 오류는 흔하므로 경고 레벨
            print(f"[Warn] {ip} 스캔 중 소켓 오류: {e}")
        except Exception as e:
            # 그 외 오류는 상세 기록
            import traceback
            print(f"[Error] {ip} 스캔 중 예상치 못한 오류: {e}")
            traceback.print_exc()

        return is_alive, detected_os

    def syn_scan(self, ip, ports=None):
        """
        Socket Connect Scan (TCP)
        :param ports: 스캔할 포트 리스트 (None이면 기본 포트 사용)
        """
        target_ports = ports if ports else self.default_ports
        open_ports = []
        
        # 타임아웃 조절 (포트가 많으면 짧게, 적으면 넉넉하게)
        timeout = 0.1 if len(target_ports) > 1000 else 0.2

        for port in target_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except OSError:
                # [Errno 22] Invalid argument 발생 시 무시하고 넘어감
                detected_os = "Unknown (Error)"
            except Exception:
                detected_os = "Unknown"
            except OSError as e:
                # 소켓 오류는 흔하므로 경고 레벨
                print(f"[Warn] {ip} 스캔 중 소켓 오류: {e}")
            except Exception as e:
                # 그 외 오류는 상세 기록
                import traceback
                print(f"[Error] {ip} 스캔 중 예상치 못한 오류: {e}")
                traceback.print_exc()
        return open_ports

    def grab_banner(self, ip, port):
        """서비스 배너 수집"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            
            # HTTP/HTTPS 등은 요청을 보내야 응답함
            if port in [80, 8080, 443]:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner if banner else "Unknown Service"
        except:
            return "Unknown Service"