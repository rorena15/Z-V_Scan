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
        """DB 테이블 초기화 (스키마 동기화 완료)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
        
            # 1. 자산 테이블
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS TBL_ASSETS (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_addr TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    os_type TEXT,
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

            # 3. 스캔 결과 테이블 (Risk Level 및 모든 필드 포함)
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

            conn.commit()
            conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown", mac_addr="-"):
        """자산 정보 저장 또는 업데이트 (Upsert)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # 존재 여부 확인
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                
                if row:
                    # 업데이트
                    asset_id = row[0]
                    # mac_addr가 유효한 경우에만 업데이트
                    if mac_addr and mac_addr not in ["-", "Unknown"]:
                        cursor.execute("""
                            UPDATE TBL_ASSETS 
                            SET last_seen = ?, hostname = ?, os_type = ?, mac_addr = ?
                            WHERE asset_id = ?
                        """, (now, hostname, os_type, mac_addr, asset_id))
                    else:
                        cursor.execute("""
                            UPDATE TBL_ASSETS 
                            SET last_seen = ?, hostname = ?, os_type = ?
                            WHERE asset_id = ?
                        """, (now, hostname, os_type, asset_id))
                else:
                    # 신규 등록
                    cursor.execute("""
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, mac_addr, last_seen, memo)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (ip, hostname, os_type, mac_addr, now, ""))
                    asset_id = cursor.lastrowid
                
                conn.commit()
                return asset_id
            except Exception as e:
                AppLogger.log_error(f"[DB] Save Asset Error: {ip}", e)
                return None
            finally:
                conn.close()

    def get_asset_id(self, ip):
        """[중요] IP로 Asset ID 조회 (Worker에서 필수 사용)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                return row[0] if row else None
            except Exception as e:
                AppLogger.log_error(f"[DB] Get Asset ID Error: {ip}", e)
                return None
            finally:
                conn.close()

    def save_result(self, asset_id, code, name, risk, status, detail, remediation="-"):
        """[중요] Worker와 호환되는 결과 저장 함수 (save_scan_result 대체)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # 중복 결과 방지 (같은 자산, 같은 코드는 덮어쓰기)
                cursor.execute("""
                    DELETE FROM TBL_SCAN_RESULT 
                    WHERE asset_id = ? AND vuln_code = ?
                """, (asset_id, code))

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
            finally:
                conn.close()

    # Alias for compatibility (Audit Runner 등이 쓸 수 있음)
    def save_scan_result(self, asset_id, vuln_code, status, detail, vuln_name=None, remediation=None):
        return self.save_result(asset_id, vuln_code, vuln_name or vuln_code, "Info", status, detail, remediation)

    def get_all_assets(self):
        """전체 자산 목록 조회 (메인 윈도우용)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ip_addr, os_type, memo, mac_addr FROM TBL_ASSETS ORDER BY last_seen DESC")
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get All Assets Error", e)
                return []
            finally:
                conn.close()

    def get_assets_for_manager(self):
        """DB 매니저용 상세 자산 목록 조회"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT asset_id, ip_addr, hostname, os_type, mac_addr, last_seen, memo FROM TBL_ASSETS ORDER BY asset_id ASC")
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Manager Assets Error", e)
                return []
            finally:
                conn.close()

    def update_asset_field(self, asset_id, field, value):
        """자산 정보 단일 필드 수정 (DB 매니저용)"""
        allowed_fields = ["hostname", "os_type", "mac_addr", "memo"]
        if field not in allowed_fields: return False
            
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                query = f"UPDATE TBL_ASSETS SET {field} = ? WHERE asset_id = ?"
                cursor.execute(query, (value, asset_id))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Update {field} Error", e)
                return False
            finally:
                conn.close()

    def update_memo(self, ip, memo_text):
        """IP 기준 메모 업데이트"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE TBL_ASSETS SET memo = ? WHERE ip_addr = ?", (memo_text, ip))
                conn.commit()
                return True
            except: return False
            finally: conn.close()

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

    def delete_asset_by_id(self, asset_id):
        """자산 및 관련 스캔 결과 삭제"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM TBL_SCAN_RESULT WHERE asset_id = ?", (asset_id,))
                cursor.execute("DELETE FROM TBL_OPEN_PORTS WHERE asset_id = ?", (asset_id,))
                cursor.execute("DELETE FROM TBL_ASSETS WHERE asset_id = ?", (asset_id,))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Delete Asset {asset_id} Fail", e)
                return False
            finally:
                conn.close()

    def delete_all_assets(self):
        """모든 데이터 초기화"""
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
            
    def get_dashboard_stats(self):
        """대시보드 통계 데이터"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            stats = {"total_assets": 0, "vuln_critical": 0, "last_scan": "-"}
            try:
                cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
                row = cursor.fetchone()
                if row: stats["total_assets"] = row[0]

                cursor.execute("SELECT COUNT(*) FROM TBL_SCAN_RESULT WHERE status IN ('VULNERABLE', '취약', 'Fail', 'Critical', 'High')")
                row = cursor.fetchone()
                if row: stats["vuln_critical"] = row[0]

                cursor.execute("SELECT MAX(last_seen) FROM TBL_ASSETS")
                last = cursor.fetchone()[0]
                if last: stats["last_scan"] = last
            except: pass
            finally: conn.close()
            return stats