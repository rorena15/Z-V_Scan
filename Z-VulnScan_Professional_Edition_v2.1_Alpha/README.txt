[Z-VulnScan Professional Edition_V2.1.0 - User Manual]

1. 제품 개요 (Product Overview)
   Z-VulnScan Professional Edition은 기업 내부망의 자산 식별 및 보안 취약점을
   진단하는 전문 도구입니다. KISA 주요정보통신기반시설 기술적 취약점 분석 가이드를
   준수하며, CVE 기반의 위협 탐지와 OS 설정(Hardening) 진단을 수행합니다.

2. 시스템 요구사항 (System Requirements)
   - OS: Windows 10 / 11 / Server 2016 이상 (64-bit 권장)
   - RAM: 최소 4GB (8GB 권장)
   - 권한: 관리자 권한 (Administrator) 필수 *패킷 제어 목적

3. 보안 아키텍처 (Security Architecture)
   본 제품은 'Secure by Design' 원칙에 따라 설계되었습니다.
   - [자격증명 보호] 입력된 ID/PW는 Windows Credential Manager에 암호화 저장됩니다.
   - [메모리 보호] 인증 정보는 연결 시점에만 호출되며, 사용 즉시 메모리에서 소거됩니다.
   - [오용 방지] 비인가 대역 스캔 및 과부하 유발 행위에 대한 경고 시스템이 탑재되어 있습니다.

4. 실행 및 사용 방법
   (1) 'Z-VulnScan_Professional_Edition_V2.1.0.exe'를 우클릭하여 [관리자 권한으로 실행]합니다.
   (2) 최초 실행 시 표시되는 [Legal Disclaimer] 내용을 숙지 후 동의합니다.
   (3) [Configuration] 패널에서 진단 대상 IP 및 인증 정보를 입력합니다.
       * 팁: 자산 리스트 우클릭 시 RDP/SSH 바로 접속 메뉴를 사용할 수 있습니다.
   (4) [Network Discovery]로 활성 자산을 식별하거나, [Vulnerability Audit]으로 정밀 진단을 수행합니다.
   (5) 진단 완료 후 PDF(요약) 또는 Excel(상세) 리포트를 생성하여 결과를 확인합니다.

5. 문제 해결 (Troubleshooting)
   - 실행 불가: 'MSVCP140.dll' 오류 발생 시, VC++ 재배포 패키지를 설치하십시오.
   - 스캔 실패: 방화벽(Firewall)에서 ICMP 및 진단 포트(WinRM/SSH) 허용 여부를 확인하십시오.
   - 오류 보고: 프로그램 폴더 내 생성된 'error_log.txt'를 첨부하여 문의 바랍니다.

[기술 지원] rorena1586@google.com
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.