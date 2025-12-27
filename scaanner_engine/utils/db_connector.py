import mysql.connector
from mysql.connector import Error
import logging

class DBConnector:
    def __init__(self):
        self.config = {
            'host': 'localhost',
            'user': 'zvScan',
            'password': 'tiger',
            'database': 'asset_watch_db'
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