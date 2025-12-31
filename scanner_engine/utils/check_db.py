# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sqlite3
import os

DB_PATH = "zvuln_scan.db"

def check_data():
    if not os.path.exists(DB_PATH):
        print(f"[!] 오류: DB 파일이 없습니다. ({DB_PATH})")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"--- [DB 진단 시작: {DB_PATH}] ---")

    # 1. 자산(Assets) 확인
    cursor.execute("SELECT count(*) FROM TBL_ASSETS")
    asset_cnt = cursor.fetchone()[0]
    print(f"1. 저장된 자산(IP) 수: {asset_cnt}개")

    # 2. 취약점 정의(Vuln Def) 확인
    cursor.execute("SELECT count(*) FROM TBL_VULN_DEF")
    vuln_def_cnt = cursor.fetchone()[0]
    print(f"2. 취약점 코드 정의 수: {vuln_def_cnt}개 (13개여야 정상)")

    # 3. 스캔 결과(Scan Result) 확인 (가장 중요!)
    cursor.execute("SELECT count(*) FROM TBL_SCAN_RESULT")
    result_cnt = cursor.fetchone()[0]
    print(f"3. 저장된 진단 결과 수: {result_cnt}건")

    if result_cnt > 0:
        print("\n[상세 데이터 샘플 (최근 5건)]")
        cursor.execute("""
            SELECT A.ip_addr, V.code, R.status 
            FROM TBL_SCAN_RESULT R
            LEFT JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
            LEFT JOIN TBL_VULN_DEF V ON R.vuln_id = V.vuln_id
            ORDER BY R.scan_date DESC LIMIT 5
        """)
        for row in cursor.fetchall():
            print(f" - IP: {row[0]} | 코드: {row[1]} | 결과: {row[2]}")
    else:
        print("\n[!] 경고: 스캔 결과 테이블이 비어 있습니다. 스캔 로직(Scanner)이 DB에 저장을 못하고 있습니다.")

    conn.close()

if __name__ == "__main__":
    check_data()