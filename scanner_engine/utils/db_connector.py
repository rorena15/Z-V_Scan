# [FINAL COMPLETED] utils/db_connector.py

# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import sqlite3
import os
import sys
import threading
from datetime import datetime
from utils.logger import AppLogger

class DBConnector:
    _db_lock = threading.Lock()

    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

        self.db_path = os.path.join(base_path, 'zvuln_scan.db')
        self._init_db()

    def _init_db(self):
        """DB 테이블 초기화 (WAL 모드 적용)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
        
            # [최적화 적용] WAL 모드 활성화 (읽기/쓰기 동시성 향상)
            try:
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
            except Exception as e:
                AppLogger.log_error("[DB] WAL Mode Init Failed", e)

            # 1. 자산 테이블
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS TBL_ASSETS (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_addr TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    os_type TEXT,
                    open_ports TEXT DEFAULT '', 
                    mac_addr TEXT,
                    last_seen DATETIME,
                    memo TEXT DEFAULT ''
                )
            ''')

            # 2. 취약점 정의 테이블 (Optional)
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
                    vuln_code TEXT,
                    vuln_name TEXT,
                    risk_level TEXT,
                    status TEXT,
                    detected_value TEXT,
                    remediation TEXT,
                    scan_date DATETIME,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id)
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
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN open_ports TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            conn.commit()
            conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown", open_ports="", mac_addr="-"):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                
                if row:
                    asset_id = row[0]
                    # 포트 정보와 시간 갱신
                    if mac_addr and mac_addr not in ["-", "Unknown"]:
                        cursor.execute("""
                            UPDATE TBL_ASSETS 
                            SET last_seen=?, hostname=?, os_type=?, open_ports=?, mac_addr=? 
                            WHERE asset_id=?
                        """, (now, hostname, os_type, open_ports, mac_addr, asset_id))
                    else:
                        cursor.execute("""
                            UPDATE TBL_ASSETS 
                            SET last_seen=?, hostname=?, os_type=?, open_ports=? 
                            WHERE asset_id=?
                        """, (now, hostname, os_type, open_ports, asset_id))
                else:
                    cursor.execute("""
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, open_ports, mac_addr, last_seen, memo)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (ip, hostname, os_type, open_ports, mac_addr, now, ""))
                    asset_id = cursor.lastrowid
                conn.commit()
                return asset_id
            except Exception as e:
                AppLogger.log_error(f"[DB] Save Asset Error: {ip}", e)
                return None
            finally:
                conn.close()

    def get_asset_id(self, ip):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                return row[0] if row else None
            except: return None
            finally: conn.close()

    def save_result(self, asset_id, code, name, risk, status, detail, remediation="-"):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("DELETE FROM TBL_SCAN_RESULT WHERE asset_id=? AND vuln_code=?", (asset_id, code))
                cursor.execute("""
                    INSERT INTO TBL_SCAN_RESULT 
                    (asset_id, vuln_code, vuln_name, risk_level, status, detected_value, remediation, scan_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (asset_id, code, name, risk, status, detail, remediation, now))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Save Result Error", e)
                return False
            finally: conn.close()

    def save_scan_result(self, asset_id, vuln_code, status, detail, vuln_name=None, remediation=None):
        return self.save_result(asset_id, vuln_code, vuln_name or vuln_code, "Info", status, detail, remediation)

    def get_all_assets(self):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ip_addr, os_type, memo, mac_addr FROM TBL_ASSETS ORDER BY last_seen DESC")
                return cursor.fetchall()
            except: return []
            finally: conn.close()

    def get_dashboard_stats(self):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            stats = {"total_assets": 0, "vuln_critical": 0, "last_scan": "-"}
            try:
                cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
                row = cursor.fetchone()
                if row: stats["total_assets"] = row[0]

                cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE risk_level IN ('Critical', 'High')")
                row = cursor.fetchone()
                if row: stats["vuln_critical"] = row[0]

                cursor.execute("SELECT MAX(last_seen) FROM TBL_ASSETS")
                last = cursor.fetchone()[0]
                if last: stats["last_scan"] = last
            except: pass
            finally: conn.close()
            return stats

    def get_memo(self, ip):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT memo FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                return row[0] if row else ""
            except: return ""
            finally: conn.close()

    def update_memo(self, ip, memo_text):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE TBL_ASSETS SET memo = ? WHERE ip_addr = ?", (memo_text, ip))
                conn.commit()
                return True
            except: return False
            finally: conn.close()

    def delete_all_assets(self):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM TBL_SCAN_RESULT")
                cursor.execute("DELETE FROM TBL_OPEN_PORTS")
                cursor.execute("DELETE FROM TBL_ASSETS")
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='TBL_ASSETS'")
                conn.commit()
                return True
            except: return False
            finally: conn.close()
    
    def get_assets_for_manager(self):
        """DB Manager용 전체 데이터 조회 (수정/삭제를 위해 ID 포함)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                # db_manager.py가 기대하는 컬럼 순서: id, ip, host, os, mac, last, memo
                # (주의: db_manager.py의 load_data 메서드 루프 구조와 맞춰야 함)
                # open_ports 컬럼은 매니저 테이블에 표시하지 않는 것 같으니 제외하거나 필요시 추가
                cursor.execute("""
                    SELECT asset_id, ip_addr, hostname, os_type, mac_addr, last_seen, memo 
                    FROM TBL_ASSETS 
                    ORDER BY last_seen DESC
                """)
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Manager Load Failed", e)
                return []
            finally:
                conn.close()

    def update_asset_field(self, asset_id, field_name, new_value):
        """DB Manager에서 셀 수정 시 호출됨"""
        # SQL Injection 방지를 위해 필드명 검증 (허용된 필드만)
        allowed_fields = ["hostname", "os_type", "mac_addr", "memo"]
        if field_name not in allowed_fields:
            return False

        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                # 필드명은 바인딩 변수(?)로 쓸 수 없어서 f-string 사용하되, 위에서 검증함
                sql = f"UPDATE TBL_ASSETS SET {field_name} = ? WHERE asset_id = ?"
                cursor.execute(sql, (new_value, asset_id))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Update Field Error ({field_name})", e)
                return False
            finally:
                conn.close()

    def delete_asset_by_id(self, asset_id):
        """DB Manager에서 삭제 시 호출됨"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                # 연관된 데이터 먼저 삭제 (참조 무결성)
                cursor.execute("DELETE FROM TBL_SCAN_RESULT WHERE asset_id=?", (asset_id,))
                cursor.execute("DELETE FROM TBL_OPEN_PORTS WHERE asset_id=?", (asset_id,))
                
                # 본체 삭제
                cursor.execute("DELETE FROM TBL_ASSETS WHERE asset_id=?", (asset_id,))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Delete Asset {asset_id} Failed", e)
                return False
            finally:
                conn.close()