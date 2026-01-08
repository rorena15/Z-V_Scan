# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import os
import sys
import json

class VulnMatcher:
    #[Hybrid Loader]
    #1. 외부 'rules/kisa_guide.json' 파일이 있으면 우선 로드 (업데이트 용이성)
    #2. 없으면 내부 하드코딩된 VULN_DB 사용 (안정성)
    
    # [내장 기본 룰] (Fallback용)
    DEFAULT_DB = {
        21: {
            "service": "FTP",
            "cve": "CVE-2011-2523",
            "kisa": "U-20",
            "risk": "High",
            "name": "FTP Service Detected",
            "desc": "암호화되지 않은 FTP 서비스가 활성화되어 있습니다. 계정 정보 탈취 위험이 있습니다.",
            "remediation": "FTP 서비스를 중지하거나, vsftpd.conf에서 anonymous_enable=NO 설정 및 SFTP 사용 권장"
        },
        22: {
            "service": "SSH",
            "cve": "CVE-2006-5051", 
            "kisa": "U-01",
            "risk": "Info",
            "name": "SSH Service Detected",
            "desc": "SSH 서비스가 발견되었습니다. Root 접속 제한 및 패치 버전 확인이 필요합니다.",
            "remediation": "/etc/ssh/sshd_config에서 PermitRootLogin no 설정 후 서비스 재시작"
        },
        23: {
            "service": "Telnet",
            "cve": "CVE-1999-0061",
            "kisa": "U-66",
            "risk": "Critical",
            "name": "Telnet Service Detected",
            "desc": "보안에 매우 취약한 Telnet이 실행 중입니다. 즉시 SSH로 대체해야 합니다.",
            "remediation": "Telnet 서비스 중지 (systemctl stop telnet) 및 비활성화, SSH 서비스로 전환"
        },
        80: {
            "service": "HTTP",
            "cve": "N/A",
            "kisa": "W-57",
            "risk": "Low",
            "name": "HTTP Web Server",
            "desc": "웹 서버가 실행 중입니다. 디렉터리 리스팅 및 불필요한 정보 노출을 점검하십시오.",
            "remediation": "웹 서버 설정(httpd.conf 등)에서 ServerTokens Prod 및 Directory Listing 비활성화"
        },
        443: {
            "service": "HTTPS",
            "cve": "CVE-2014-0160",
            "kisa": "W-58",
            "risk": "Low",
            "name": "HTTPS Web Server",
            "desc": "보안 웹 서버(HTTPS)입니다. SSL/TLS 인증서 만료일 및 취약한 프로토콜 버전을 점검하십시오.",
            "remediation": "SSL/TLS 라이브러리 최신 업데이트 및 취약한 Cipher Suite 비활성화"
        },
        445: {
            "service": "SMB",
            "cve": "CVE-2017-0144", # EternalBlue
            "kisa": "W-08",
            "risk": "Critical",
            "name": "SMB File Sharing",
            "desc": "SMB 프로토콜이 노출되었습니다. 랜섬웨어 및 웜 바이러스 공격에 매우 취약합니다.",
            "remediation": "필요 없는 경우 SMB 서비스 비활성화, 방화벽에서 445 포트 차단, MS17-010 보안 패치 적용"
        },
        3306: {
            "service": "MySQL",
            "cve": "CVE-2012-2122",
            "kisa": "U-62",
            "risk": "Medium",
            "name": "MySQL Database",
            "desc": "데이터베이스 포트가 외부에 노출되었습니다. 접근 제어(ACL) 설정이 필수입니다.",
            "remediation": "DB 계정의 외부 접속 제한(bind-address=127.0.0.1) 및 강력한 패스워드 정책 적용"
        },
        3389: {
            "service": "RDP",
            "cve": "CVE-2019-0708", # BlueKeep
            "kisa": "W-18",
            "risk": "High",
            "name": "Remote Desktop (RDP)",
            "desc": "원격 데스크톱 연결이 활성화되어 있습니다. 무차별 대입 공격 및 취약점 악용 위험이 큽니다.",
            "remediation": "RDP 포트 변경 고려, 네트워크 수준 인증(NLA) 활성화, 불필요한 원격 접속 비활성화"
        },
        8080: {
            "service": "HTTP-Proxy",
            "cve": "N/A",
            "kisa": "W-57",
            "risk": "Medium",
            "name": "Web Proxy / Admin Console",
            "desc": "관리자 페이지 또는 프록시 서버일 가능성이 높습니다. 외부 접근 제한이 필요합니다.",
            "remediation": "관리자 페이지 외부 접속 차단(IP ACL 설정) 및 기본 패스워드 변경"
        }
    }
    VULN_DB = DEFAULT_DB
    
    @staticmethod
    def load_rules():
        """외부 JSON 룰 파일 로딩 시도"""
        try:
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            rule_path = os.path.join(base_path, 'rules', 'kisa_guide.json')
            
            if os.path.exists(rule_path):
                with open(rule_path, 'r', encoding='utf-8') as f:
                    # JSON 키를 정수형(Port)으로 변환하여 로드
                    external_data = json.load(f)
                    VulnMatcher.VULN_DB = {int(k): v for k, v in external_data.items()}
                    print(f"[Info] External rules loaded from {rule_path}")
                    return True
        except Exception as e:
            print(f"[Warning] Failed to load external rules: {e}")
            VulnMatcher.VULN_DB = VulnMatcher.DEFAULT_DB # 실패 시 기본값 복구
            
        return False
    
    @staticmethod
    def match(port, banner=""):
        _signature = "Made_By_Rorena_2025_Seongnam_KR"
        #포트 번호와 배너 정보를 받아 취약점 상세 정보를 반환
        port = int(port)
        info = VulnMatcher.VULN_DB.get(port)
        
        if info:
            detail = info['desc']
            if banner and len(banner) > 3:
                detail += f"\n[Banner Info] {banner.strip()}"
                
            return {
                "found": True,
                "service": info['service'],
                "cve": info['cve'],
                "kisa": info['kisa'],
                "risk": info['risk'],
                "name": info['name'],
                "desc": detail,
                "remediation": info['remediation'] # <-- [추가됨]
            }
        
        return {"found": False}
    
VulnMatcher.load_rules()