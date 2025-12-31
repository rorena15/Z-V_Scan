# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sqlite3
import os
from datetime import datetime

class DBConnector:
    def __init__(self):
        # DB 파일 경로 설정 (상위 폴더의 zvuln_scan.db)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(os.path.dirname(base_dir), 'zvuln_scan.db')
        _signature = "Made_By_Rorena_2025_Seongnam_KR"
        self._init_db()

    def _init_db(self):
        """DB 테이블 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. 자산 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TBL_ASSETS (
                asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_addr TEXT UNIQUE,
                hostname TEXT,
                os_type TEXT,
                last_seen DATETIME
            )
        ''')

        # 2. 취약점 정의 테이블 (코드가 무엇인지 설명하는 테이블)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TBL_VULN_DEF (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE,
                name TEXT,
                category TEXT,
                remediation TEXT
            )
        ''')

        # 3. 스캔 결과 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TBL_SCAN_RESULT (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                vuln_id INTEGER,
                status TEXT,
                detected_value TEXT,
                scan_date DATETIME,
                FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id),
                FOREIGN KEY(vuln_id) REFERENCES TBL_VULN_DEF(vuln_id)
            )
        ''')
        
        # 4. 오픈 포트 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TBL_OPEN_PORTS (
                port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                port_num INTEGER,
                service_name TEXT,
                banner TEXT,
                scan_date DATETIME,
                FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown"):
        """자산 정보 저장 또는 업데이트"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
            row = cursor.fetchone()
            
            if row:
                asset_id = row[0]
                cursor.execute("""
                    UPDATE TBL_ASSETS 
                    SET last_seen = ?, hostname = ?, os_type = ? 
                    WHERE asset_id = ?
                """, (now, hostname, os_type, asset_id))
            else:
                cursor.execute("""
                    INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, last_seen)
                    VALUES (?, ?, ?, ?)
                """, (ip, hostname, os_type, now))
                asset_id = cursor.lastrowid
                
            conn.commit()
            return asset_id
        except Exception as e:
            print(f"[DB Error] Save Asset: {e}")
            return None
        finally:
            conn.close()

    def save_open_port(self, asset_id, port, banner):
        """오픈 포트 정보 저장"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor.execute("DELETE FROM TBL_OPEN_PORTS WHERE asset_id = ? AND port_num = ?", (asset_id, port))
            cursor.execute("""
                INSERT INTO TBL_OPEN_PORTS (asset_id, port_num, service_name, banner, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (asset_id, port, "Unknown", banner, now))
            conn.commit()
        except Exception as e:
            print(f"[DB Error] Save Port: {e}")
        finally:
            conn.close()

    def _ensure_vuln_def(self, cursor, code, vuln_name=None, remediation=None):
        """
        [핵심] 취약점 정의가 이미 있어도, 최신 내용(이름/조치방안)으로 업데이트(UPDATE) 함
        """
        cursor.execute("SELECT vuln_id FROM TBL_VULN_DEF WHERE code = ?", (code,))
        row = cursor.fetchone()
        
        # 기본값 설정 (호출 쪽에서 None을 보내면 기본값 사용)
        final_name = vuln_name if vuln_name else f"Detected Item ({code})"
        final_rem = remediation if remediation else "관리자 매뉴얼 참조 또는 보안 담당자 문의"

        if row:
            # [기존 데이터 존재 시] 최신 정보로 덮어쓰기 (UPDATE)
            vuln_id = row[0]
            cursor.execute("""
                UPDATE TBL_VULN_DEF 
                SET name = ?, remediation = ? 
                WHERE vuln_id = ?
            """, (final_name, final_rem, vuln_id))
            return vuln_id
        else:
            # [신규 데이터] 새로 등록 (INSERT)
            cursor.execute("""
                INSERT INTO TBL_VULN_DEF (code, name, category, remediation)
                VALUES (?, ?, ?, ?)
            """, (code, final_name, "General", final_rem))
            return cursor.lastrowid

    def save_scan_result(self, asset_id, vuln_code, status, detail, vuln_name=None, remediation=None):
        """[핵심] remediation 인자까지 받아서 저장"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # 조치 방안까지 함께 전달하여 정의 테이블 갱신
            vuln_id = self._ensure_vuln_def(cursor, vuln_code, vuln_name, remediation)
            
            # 기존 결과 삭제 후 재저장
            cursor.execute("DELETE FROM TBL_SCAN_RESULT WHERE asset_id=? AND vuln_id=?", (asset_id, vuln_id))
            
            cursor.execute("""
                INSERT INTO TBL_SCAN_RESULT (asset_id, vuln_id, status, detected_value, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (asset_id, vuln_id, status, detail, now))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"[DB Error] Save Result: {e}")
            return False
        finally:
            conn.close()