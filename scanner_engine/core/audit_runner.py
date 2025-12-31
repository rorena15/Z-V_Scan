# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys
import os

# 상위 폴더 모듈 참조 설정
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from utils.db_connector import DBConnector
from core.ssh_inspector import SSHInspector

def run_server_audit(target_ip, username, password):
    print(f"\n=== Starting Server Audit: {target_ip} ===")
    
    # 1. DB 연결 준비
    db = DBConnector()
    
    # 2. 자산 식별 (기존에 있으면 ID 가져오고, 없으면 생성)
    # 실제 운영에선 OS 정보를 정확히 넣어야 하지만, 여기선 예시로 Linux 고정
    asset_id = db.save_asset(target_ip, hostname="Target-Server", os_type="Linux")
    
    # 3. SSH 접속 시도
    inspector = SSHInspector(target_ip, username=username, password=password)
    
    if inspector.connect():
        print(f"[+] SSH Connected to {target_ip}")
        
        # --- [진단 항목 1] U-01: root 계정 원격 접속 제한 ---
        vuln_code = "U-01"
        status, detail = inspector.check_u01_root_login()
        
        # 결과 출력
        print(f"    > Check {vuln_code}: {status} (Val: {detail})")
        
        # 4. DB에 결과 저장
        db.save_scan_result(asset_id, vuln_code, status, detail)
        
        # (추후 여기에 U-02, U-03 등 추가 가능)
        
        inspector.close()
    else:
        print("[-] SSH Connection Failed. Skipping audit.")

    print("=== Audit Completed ===\n")

if __name__ == "__main__":
    # 테스트 정보 (본인 환경에 맞게 수정)
    TARGET_IP = "192.168.0.10"
    USER = "root"
    PASS = "toor"
    
    run_server_audit(TARGET_IP, USER, PASS)