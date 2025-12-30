# scanner_engine/core/vuln_matcher.py

class VulnMatcher:
    """
    포트 및 배너 정보를 기반으로 CVE 및 KISA 진단 코드를 매핑하는 엔진
    (Standalone EXE를 위해 내장 딕셔너리 DB 사용)
    """
    
    # [진단 규칙 데이터베이스]
    # Key: Port 번호
    # Value: {Service, CVE, KISA Code, Risk, Name, Description}
    VULN_DB = {
        21: {
            "service": "FTP",
            "cve": "CVE-2011-2523",
            "kisa": "U-20",  # 익명 FTP 접속 등 불필요한 서비스
            "risk": "High",
            "name": "FTP Service Detected",
            "desc": "암호화되지 않은 FTP 서비스가 활성화되어 있습니다. 계정 정보 탈취 위험이 있습니다."
        },
        22: {
            "service": "SSH",
            "cve": "CVE-2006-5051", 
            "kisa": "U-01",  # root 원격 접속 제한
            "risk": "Info",
            "name": "SSH Service Detected",
            "desc": "SSH 서비스가 발견되었습니다. Root 접속 제한 및 패치 버전 확인이 필요합니다."
        },
        23: {
            "service": "Telnet",
            "cve": "CVE-1999-0061",
            "kisa": "U-66",  # Telnet 등 암호화되지 않은 통신 사용 금지
            "risk": "Critical",
            "name": "Telnet Service Detected",
            "desc": "보안에 매우 취약한 Telnet이 실행 중입니다. 즉시 SSH로 대체해야 합니다."
        },
        80: {
            "service": "HTTP",
            "cve": "N/A",
            "kisa": "W-57",  # 웹 서비스 정보 노출
            "risk": "Low",
            "name": "HTTP Web Server",
            "desc": "웹 서버가 실행 중입니다. 디렉터리 리스팅 및 불필요한 정보 노출을 점검하십시오."
        },
        445: {
            "service": "SMB",
            "cve": "CVE-2017-0144", # EternalBlue (WannaCry)
            "kisa": "W-08",  # 하드디스크 기본 공유 제거
            "risk": "Critical",
            "name": "SMB File Sharing",
            "desc": "SMB 프로토콜이 노출되었습니다. 랜섬웨어 및 웜 바이러스 공격에 매우 취약합니다."
        },
        3306: {
            "service": "MySQL",
            "cve": "CVE-2012-2122",
            "kisa": "U-62",  # DBMS 관리자 계정 취약점
            "risk": "Medium",
            "name": "MySQL Database",
            "desc": "데이터베이스 포트가 외부에 노출되었습니다. 접근 제어(ACL) 설정이 필수입니다."
        },
        3389: {
            "service": "RDP",
            "cve": "CVE-2019-0708", # BlueKeep
            "kisa": "W-18",  # 원격 서비스 접근 통제
            "risk": "High",
            "name": "Remote Desktop (RDP)",
            "desc": "원격 데스크톱 연결이 활성화되어 있습니다. 무차별 대입 공격 및 취약점 악용 위험이 큽니다."
        },
        8080: {
            "service": "HTTP-Proxy",
            "cve": "N/A",
            "kisa": "W-57",
            "risk": "Medium",
            "name": "Web Proxy / Admin Console",
            "desc": "관리자 페이지 또는 프록시 서버일 가능성이 높습니다. 외부 접근 제한이 필요합니다."
        }
    }

    @staticmethod
    def match(port, banner=""):
        """
        포트 번호와 배너 정보를 받아 취약점 상세 정보를 반환
        """
        port = int(port)
        info = VulnMatcher.VULN_DB.get(port)
        
        if info:
            # 배너 정보가 있으면 상세 내용에 추가
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
                "desc": detail
            }
        
        return {"found": False, "service": "Unknown", "desc": "알려지지 않은 서비스"}