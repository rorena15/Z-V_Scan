# Copyright (c) 2025 rorena15
# All rights reserved.
# Proprietary License - No redistribution or modification without permission.
import mysql.connector
from mysql.connector import Error
import logging
from dotenv import load_dotenv
import os
load_dotenv()

class DBConnector:
    def __init__(self):
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''), # 비밀번호가 없으면 빈 문자열
            'database': os.getenv('DB_NAME', 'asset_watch_db'),
            'port': int(os.getenv('DB_PORT', 3306))
        }
        self.logger = logging.getLogger("DB_Connector")

    def create_connection(self):
        try:
            conn = mysql.connector.connect(**self.config)
            if conn.is_connected():
                return conn
        except Error as e:
            self.logger.error(f"DB Connection Failed: {e}")
        return None

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown"):
        ##자산 정보를 저장하거나 갱신합니다.
        ##:return: asset_id (DB의 PK)
        conn = self.create_connection()
        asset_id = None
        if conn:
            try:
                cursor = conn.cursor()
                
                # 1. 해당 IP가 이미 있는지 확인
                check_sql = "SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = %s"
                cursor.execute(check_sql, (ip,))
                result = cursor.fetchone()

                if result:
                    # 1-1. 이미 존재하면 Last Seen 시간 업데이트
                    asset_id = result[0]
                    update_sql = """
                        UPDATE TBL_ASSETS 
                        SET last_seen = NOW(), hostname = %s, os_type = %s 
                        WHERE asset_id = %s
                    """
                    cursor.execute(update_sql, (hostname, os_type, asset_id))
                    self.logger.info(f"[DB] Asset Updated: {ip} (ID: {asset_id})")
                else:
                    # 1-2. 없으면 신규 등록
                    insert_sql = """
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, first_seen, last_seen) 
                        VALUES (%s, %s, %s, NOW(), NOW())
                    """
                    cursor.execute(insert_sql, (ip, hostname, os_type))
                    asset_id = cursor.lastrowid
                    self.logger.info(f"[DB] New Asset Registered: {ip} (ID: {asset_id})")
                
                conn.commit()
            except Error as e:
                self.logger.error(f"save_asset Error: {e}")
            finally:
                cursor.close()
                conn.close()
        return asset_id

    def save_open_port(self, asset_id, port, banner=""):
        
        #스캔된 포트 정보를 저장합니다.
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                # 기존에 같은 포트 기록이 있으면 스캔 날짜와 배너만 업데이트할 수도 있으나,
                # 여기서는 이력을 남기기 위해 단순히 Insert 하거나, 중복 방지 로직을 넣습니다.
                # (간소화를 위해 중복 시 Update 처리)
                
                # 해당 자산의 해당 포트가 이미 있는지 확인
                check_sql = "SELECT port_id FROM TBL_OPEN_PORTS WHERE asset_id = %s AND port_number = %s"
                cursor.execute(check_sql, (asset_id, port))
                result = cursor.fetchone()
                
                if result:
                    # 업데이트
                    update_sql = "UPDATE TBL_OPEN_PORTS SET banner = %s, scan_date = NOW() WHERE port_id = %s"
                    cursor.execute(update_sql, (banner, result[0]))
                else:
                    # 신규 삽입
                    insert_sql = """
                        INSERT INTO TBL_OPEN_PORTS (asset_id, port_number, banner, scan_date)
                        VALUES (%s, %s, %s, NOW())
                    """
                    cursor.execute(insert_sql, (asset_id, port, banner))
                
                conn.commit()
                self.logger.info(f"   [DB] Port Saved: {port} (Banner: {banner[:20]}...)")
            except Error as e:
                self.logger.error(f"save_open_port Error: {e}")
            finally:
                cursor.close()
                conn.close()
    def get_vuln_id_by_code(self, code):
        #KISA 코드(예: U-01)로 DB 내부의 vuln_id를 조회합니다.
        conn = self.create_connection()
        vuln_id = None
        if conn:
            try:
                cursor = conn.cursor()
                sql = "SELECT vuln_id FROM TBL_VULN_DEF WHERE code = %s"
                cursor.execute(sql, (code,))
                result = cursor.fetchone()
                if result:
                    vuln_id = result[0]
            except Error as e:
                self.logger.error(f"get_vuln_id_by_code Error: {e}")
            finally:
                cursor.close()
                conn.close()
        return vuln_id

    def save_scan_result(self, asset_id, vuln_code, status, detected_value):
        #[핵심 기능] 진단 결과를 DB에 저장합니다.
        #:param vuln_code: 'U-01' 같은 코드명 (DB에서 ID를 자동 조회함)
        vuln_id = self.get_vuln_id_by_code(vuln_code)
        if not vuln_id:
            self.logger.error(f"Unknown Vulnerability Code: {vuln_code}")
            return False

        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                # 로그 기록을 위해 무조건 INSERT (히스토리 관리)
                # 만약 최신 상태만 유지하고 싶다면 UPDATE 로직으로 변경 가능
                sql = """
                    INSERT INTO TBL_SCAN_RESULT (asset_id, vuln_id, status, detected_value, scan_date)
                    VALUES (%s, %s, %s, %s, NOW())
                """
                cursor.execute(sql, (asset_id, vuln_id, status, detected_value))
                conn.commit()
                self.logger.info(f"[DB] Result Saved: Asset({asset_id}) - {vuln_code} -> {status}")
                return True
            except Error as e:
                self.logger.error(f"save_scan_result Error: {e}")
            finally:
                cursor.close()
                conn.close()
        return False