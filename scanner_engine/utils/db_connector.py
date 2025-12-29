# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
# scanner_engine/utils/db_connector.py
import sqlite3
import logging
import os
import json
import sys

class DBConnector:
    def __init__(self):
        # 상위 폴더의 rules 경로 찾기
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_dir = os.path.join(base_dir, 'rules')
        
        self.db_path = 'zvuln_scan.db'
        self.logger = logging.getLogger("DB_Connector")
        self._init_database()
        
        # [NEW] 초기화 시 JSON 규칙을 DB에 동기화
        self._sync_rules_from_json()

    def create_connection(self):
        try:
            return sqlite3.connect(self.db_path, check_same_thread=False)
        except sqlite3.Error as e:
            self.logger.error(f"DB Connection Failed: {e}")
        return None

    def _init_database(self):
        conn = self.create_connection()
        if not conn: return
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            # 테이블 생성 (기존과 동일)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_ASSETS (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_addr TEXT UNIQUE, hostname TEXT, os_type TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_OPEN_PORTS (
                    port_id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER,
                    port_number INTEGER, banner TEXT, scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_VULN_DEF (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE, name TEXT, category TEXT,
                    description TEXT, remediation TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_SCAN_RESULT (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, vuln_id INTEGER,
                    status TEXT, detected_value TEXT, scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id),
                    FOREIGN KEY(vuln_id) REFERENCES TBL_VULN_DEF(vuln_id)
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _sync_rules_from_json(self):
        """JSON 파일들을 읽어 TBL_VULN_DEF 테이블 업데이트 (Rule-Based 핵심)"""
        json_files = ['linux_rules.json', 'windows_rules.json']
        conn = self.create_connection()
        if not conn: return

        try:
            cursor = conn.cursor()
            for jf in json_files:
                path = os.path.join(self.rules_dir, jf)
                if not os.path.exists(path):
                    # 빌드 환경 고려 (PyInstaller)
                    if hasattr(sys, '_MEIPASS'):
                        path = os.path.join(sys._MEIPASS, 'rules', jf)
                
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        rules = json.load(f)
                        for r in rules:
                            # 이미 존재하면 업데이트, 없으면 삽입 (UPSERT 방식)
                            cursor.execute("""
                                INSERT OR REPLACE INTO TBL_VULN_DEF (code, name, category, description, remediation)
                                VALUES (?, ?, ?, ?, ?)
                            """, (r['code'], r['name'], r.get('category','Common'), r.get('description',''), r.get('remediation','')))
            conn.commit()
            # self.logger.info("JSON Rules Synced to DB")
        except Exception as e:
            self.logger.error(f"Rule Sync Error: {e}")
        finally:
            conn.close()

    # --- 기존 메서드 유지 (save_asset, save_open_port, save_scan_result 등) ---
    # save_scan_result 등은 기존 코드 그대로 사용해도 됩니다. 
    # 위에서 _sync_rules_from_json을 했기 때문에 get_vuln_id_by_code가 정상 작동합니다.

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown"):
        conn = self.create_connection()
        asset_id = None
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                result = cursor.fetchone()
                if result:
                    asset_id = result[0]
                    cursor.execute("UPDATE TBL_ASSETS SET last_seen=datetime('now','localtime'), hostname=?, os_type=? WHERE asset_id=?", (hostname, os_type, asset_id))
                else:
                    cursor.execute("INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, first_seen, last_seen) VALUES (?, ?, ?, datetime('now','localtime'), datetime('now','localtime'))", (ip, hostname, os_type))
                    asset_id = cursor.lastrowid
                conn.commit()
            except sqlite3.Error as e:
                self.logger.error(f"save_asset Error: {e}")
            finally:
                conn.close()
        return asset_id

    def save_open_port(self, asset_id, port, banner=""):
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO TBL_OPEN_PORTS (asset_id, port_number, banner) VALUES (?, ?, ?)", (asset_id, port, banner))
                conn.commit()
            except: pass # 중복 등 에러 무시
            finally: conn.close()

    def get_vuln_id_by_code(self, code):
        conn = self.create_connection()
        vuln_id = None
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT vuln_id FROM TBL_VULN_DEF WHERE code = ?", (code,))
                res = cursor.fetchone()
                if res: vuln_id = res[0]
            finally: conn.close()
        return vuln_id

    def save_scan_result(self, asset_id, vuln_code, status, detected_value):
        vuln_id = self.get_vuln_id_by_code(vuln_code)
        if not vuln_id:
            # JSON에 없는 코드가 들어오면 DB 에러 방지를 위해 Skip 혹은 Warning
            self.logger.warning(f"DB Miss: {vuln_code} not found in definitions.")
            return False
        
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO TBL_SCAN_RESULT (asset_id, vuln_id, status, detected_value) VALUES (?, ?, ?, ?)", (asset_id, vuln_id, status, detected_value))
                conn.commit()
                return True
            except Exception as e:
                self.logger.error(f"save result error: {e}")
            finally:
                conn.close()
        return False