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
from datetime import datetime
from utils.logger import AppLogger

class DBConnector:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

        # zvuln_scan.db 파일을 해당 경로에 지정
        self.db_path = os.path.join(base_path, 'zvuln_scan.db')
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
        # 5. 사용자 추가 MEMO 테이블
        cursor.execute("PRAGMA table_info(TBL_ASSETS)")
        columns = [info[1] for info in cursor.fetchall()]
        if "memo" not in columns:
            # print("[DB] Upgrading schema: Adding 'memo' column to TBL_ASSETS...")
            cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN memo TEXT DEFAULT ''")
        # 6. mac_addr 컬럼 추가 (리포트/벤더 식별용)
        try:
            cursor.execute("SELECT mac_addr FROM TBL_ASSETS LIMIT 1")
        except sqlite3.OperationalError:
            AppLogger.log_info("[DB] Upgrading schema: Adding 'mac_addr' column...")
            cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN mac_addr TEXT DEFAULT ''")
        conn.commit()
        conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown", mac_addr=None):
        # 자산 정보 저장 또는 업데이트
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
            row = cursor.fetchone()
            
            if row:
                asset_id = row[0]
                # 기존 자산 업데이트 (MAC 주소가 있으면 함께 갱신)
                if mac_addr:
                    cursor.execute("""
                        UPDATE TBL_ASSETS 
                        SET last_seen = ?, hostname = ?, os_type = ?, mac_addr = ? 
                        WHERE asset_id = ?
                    """, (now, hostname, os_type, mac_addr, asset_id))
                else:
                    # MAC 정보가 없으면 기존 MAC 유지 (덮어쓰기 방지)
                    cursor.execute("""
                        UPDATE TBL_ASSETS 
                        SET last_seen = ?, hostname = ?, os_type = ?
                        WHERE asset_id = ?
                    """, (now, hostname, os_type, asset_id))
            else:
                # 신규 등록 (mac_addr 포함)
                cursor.execute("""
                    INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, last_seen, memo, mac_addr)
                    VALUES (?, ?, ?, ?, '', ?)
                """, (ip, hostname, os_type, now, mac_addr))
                asset_id = cursor.lastrowid
                
                
                
            conn.commit()
            return asset_id
        except Exception as e:
            AppLogger.log_error(f"[DB Error] Save Asset Failed ({ip})", e)
            return None
        finally:
            conn.close()

    def save_open_port(self, asset_id, port, banner):
        #오픈 포트 정보 저장
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
            AppLogger.log_error(f"[DB Error] Save Port Failed ({port})", e)
        finally:
            conn.close()

    def _ensure_vuln_def(self, cursor, code, vuln_name=None, remediation=None):
        #[핵심] 취약점 정의가 이미 있어도, 최신 내용(이름/조치방안)으로 업데이트(UPDATE) 함
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
        #[핵심] remediation 인자까지 받아서 저장
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
            AppLogger.log_error(f"[DB Error] Save Result Fail", e)
            return False
        finally:
            conn.close()
            
    def update_memo(self, ip, memo_text):
        #자산 메모 업데이트
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE TBL_ASSETS SET memo = ? WHERE ip_addr = ?", (memo_text, ip))
            conn.commit()
            return True
        except Exception as e:
            AppLogger.log_error(f"[DB Error] Update Memo Fail", e)
            return False
        finally:
            conn.close()

    def get_memo(self, ip):
        # 특정 IP의 메모 조회
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT memo FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
            row = cursor.fetchone()
            return row[0] if row else ""
        except:
            return ""
        finally:
            conn.close()

    def get_all_assets(self):
        #저장된 모든 자산 목록 조회 (프로그램 시작 시 로드용)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        assets = []
        try:
            # IP, OS, Memo, LastSeen 가져오기
            cursor.execute("SELECT ip_addr, os_type, memo , mac_addr FROM TBL_ASSETS ORDER BY last_seen DESC")
            assets = cursor.fetchall()
        except Exception as e:
            AppLogger.log_error(f"[DB Error] Assets Load Fail", e)
        finally:
            conn.close()
        return assets
    
    def delete_all_assets(self):
        # 모든 자산 및 관련 스캔 데이터 영구 삭제
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # 1. 자식 테이블(결과, 포트) 먼저 삭제
            cursor.execute("DELETE FROM TBL_SCAN_RESULT")
            cursor.execute("DELETE FROM TBL_OPEN_PORTS")
            
            # 2. 부모 테이블(자산) 삭제
            cursor.execute("DELETE FROM TBL_ASSETS")
            
            # 3. SQLite 시퀀스 초기화 (ID 1부터 다시 시작)
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='TBL_ASSETS'")
            
            conn.commit()
            return True
        except Exception as e:
            AppLogger.log_error(f"[DB Error] All delete Fail", e)
            return False
        finally:
            conn.close()