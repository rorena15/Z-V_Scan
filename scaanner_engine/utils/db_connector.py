# Copyright (c) 2025 rorena15
# All rights reserved.
import sqlite3
import logging
import os
from datetime import datetime

class DBConnector:
    def __init__(self):
        # 1. DB 설정: 로컬 파일 경로 사용
        self.db_path = 'zvuln_scan.db'
        self.logger = logging.getLogger("DB_Connector")
        
        # 2. 객체 생성 시 테이블이 없으면 자동 생성 (초기화)
        self._init_database()

    def create_connection(self):
        """SQLite DB 연결 객체 반환"""
        try:
            # check_same_thread=False: PyQt5 멀티스레드 환경에서 필수
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            return conn
        except sqlite3.Error as e:
            self.logger.error(f"DB Connection Failed: {e}")
        return None

    def _init_database(self):
        """테이블이 없을 경우 자동으로 생성하는 내부 메서드"""
        conn = self.create_connection()
        if not conn:
            return

        try:
            cursor = conn.cursor()
            # 성능 향상을 위한 WAL 모드 설정 (동시성 처리 유리)
            cursor.execute("PRAGMA journal_mode=WAL;")

            # (1) 자산 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_ASSETS (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_addr TEXT UNIQUE,
                    hostname TEXT,
                    os_type TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # (2) 오픈 포트 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_OPEN_PORTS (
                    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    port_number INTEGER,
                    banner TEXT,
                    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id)
                )
            """)

            # (3) 취약점 정의 테이블 (진단 항목)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_VULN_DEF (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE,  -- 예: U-01
                    name TEXT,
                    category TEXT
                )
            """)

            # (4) 스캔 결과 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_SCAN_RESULT (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    vuln_id INTEGER,
                    status TEXT,
                    detected_value TEXT,
                    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id),
                    FOREIGN KEY(vuln_id) REFERENCES TBL_VULN_DEF(vuln_id)
                )
            """)

            # [중요] 기초 데이터(U-01 ~ U-13) 자동 삽입 (테이블이 비어있을 경우)
            cursor.execute("SELECT count(*) FROM TBL_VULN_DEF")
            if cursor.fetchone()[0] == 0:
                self.logger.info("[DB] Initializing default vulnerability codes (U-01~U-13)...")
                base_vulns = [(f'U-{i:02d}', f'Check Item {i:02d}', 'System') for i in range(1, 14)]
                cursor.executemany("INSERT INTO TBL_VULN_DEF (code, name, category) VALUES (?, ?, ?)", base_vulns)

            conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Database Init Error: {e}")
        finally:
            conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown"):
        """자산 정보를 저장하거나 갱신합니다."""
        conn = self.create_connection()
        asset_id = None
        if conn:
            try:
                cursor = conn.cursor()
                
                # 1. 해당 IP 확인
                check_sql = "SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?"
                cursor.execute(check_sql, (ip,))
                result = cursor.fetchone()

                if result:
                    # 1-1. 업데이트 (SQLite datetime 함수 사용)
                    asset_id = result[0]
                    update_sql = """
                        UPDATE TBL_ASSETS 
                        SET last_seen = datetime('now', 'localtime'), hostname = ?, os_type = ? 
                        WHERE asset_id = ?
                    """
                    cursor.execute(update_sql, (hostname, os_type, asset_id))
                    self.logger.info(f"[DB] Asset Updated: {ip} (ID: {asset_id})")
                else:
                    # 1-2. 신규 등록
                    insert_sql = """
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, first_seen, last_seen) 
                        VALUES (?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'))
                    """
                    cursor.execute(insert_sql, (ip, hostname, os_type))
                    asset_id = cursor.lastrowid
                    self.logger.info(f"[DB] New Asset Registered: {ip} (ID: {asset_id})")
                
                conn.commit()
            except sqlite3.Error as e:
                self.logger.error(f"save_asset Error: {e}")
            finally:
                conn.close()
        return asset_id

    def save_open_port(self, asset_id, port, banner=""):
        """스캔된 포트 정보를 저장합니다."""
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                check_sql = "SELECT port_id FROM TBL_OPEN_PORTS WHERE asset_id = ? AND port_number = ?"
                cursor.execute(check_sql, (asset_id, port))
                result = cursor.fetchone()
                
                if result:
                    # 업데이트
                    update_sql = "UPDATE TBL_OPEN_PORTS SET banner = ?, scan_date = datetime('now', 'localtime') WHERE port_id = ?"
                    cursor.execute(update_sql, (banner, result[0]))
                else:
                    # 신규 삽입
                    insert_sql = """
                        INSERT INTO TBL_OPEN_PORTS (asset_id, port_number, banner, scan_date)
                        VALUES (?, ?, ?, datetime('now', 'localtime'))
                    """
                    cursor.execute(insert_sql, (asset_id, port, banner))
                
                conn.commit()
                # self.logger.info(f"   [DB] Port Saved: {port}") # 로그 너무 많으면 주석 처리
            except sqlite3.Error as e:
                self.logger.error(f"save_open_port Error: {e}")
            finally:
                conn.close()

    def get_vuln_id_by_code(self, code):
        """KISA 코드(예: U-01)로 vuln_id 조회"""
        conn = self.create_connection()
        vuln_id = None
        if conn:
            try:
                cursor = conn.cursor()
                sql = "SELECT vuln_id FROM TBL_VULN_DEF WHERE code = ?"
                cursor.execute(sql, (code,))
                result = cursor.fetchone()
                if result:
                    vuln_id = result[0]
            except sqlite3.Error as e:
                self.logger.error(f"get_vuln_id_by_code Error: {e}")
            finally:
                conn.close()
        return vuln_id

    def save_scan_result(self, asset_id, vuln_code, status, detected_value):
        """진단 결과 저장"""
        vuln_id = self.get_vuln_id_by_code(vuln_code)
        
        # 코드가 DB에 없으면 저장 실패 -> 초기화 로직에서 U-01~13을 넣었으므로 정상 작동함
        if not vuln_id:
            self.logger.error(f"Unknown Vulnerability Code: {vuln_code}")
            return False

        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                sql = """
                    INSERT INTO TBL_SCAN_RESULT (asset_id, vuln_id, status, detected_value, scan_date)
                    VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
                """
                cursor.execute(sql, (asset_id, vuln_id, status, detected_value))
                conn.commit()
                self.logger.info(f"[DB] Result Saved: Asset({asset_id}) - {vuln_code} -> {status}")
                return True
            except sqlite3.Error as e:
                self.logger.error(f"save_scan_result Error: {e}")
            finally:
                conn.close()
        return False