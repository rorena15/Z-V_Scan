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
        """테이블 생성 및 초기 데이터(상세 설명/조치 방안 포함) 적재"""
        conn = self.create_connection()
        if not conn: return

        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")

            # 1. 자산 테이블
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

            # 2. 오픈 포트 테이블
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

            # 3. 취약점 정의 테이블 (컬럼 추가: description, remediation)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS TBL_VULN_DEF (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE,
                    name TEXT,
                    category TEXT,
                    description TEXT,  -- 왜 위험한지?
                    remediation TEXT   -- 어떻게 고치는지?
                )
            """)

            # 4. 스캔 결과 테이블
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

            # [핵심] 기초 데이터 적재 (설명 및 조치방안 포함)
            cursor.execute("SELECT count(*) FROM TBL_VULN_DEF")
            if cursor.fetchone()[0] == 0:
                self.logger.info("[DB] KISA 가이드 상세 데이터 초기화 중...")
                
                # (코드, 항목명, 카테고리, 위험설명, 조치방법)
                vuln_data = [
                    ('U-01', 'root 계정 원격 접속 제한', 'Account', 
                    'root 계정으로 직접 로그인이 허용될 경우, 공격자가 무차별 대입 공격(Brute Force)을 통해 관리자 권한을 획득할 위험이 매우 높습니다.', 
                    '1. /etc/ssh/sshd_config 파일 수정\n2. PermitRootLogin no 설정\n3. SSH 서비스 재시작 (systemctl restart sshd)'),
                    
                    ('U-02', '패스워드 복잡성 설정', 'Account', 
                    '단순한 패스워드는 사전 대입 공격 등에 취약합니다. 영문, 숫자, 특수문자를 조합하여 설정해야 합니다.', 
                    '/etc/security/pwquality.conf 파일에서 minlen=8, minclass=3 이상으로 설정하십시오.'),
                    
                    ('U-03', '계정 잠금 임계값 설정', 'Account', 
                    '로그인 실패 시 계정을 잠그지 않으면 공격자가 비밀번호를 맞출 때까지 무한정 시도할 수 있습니다.', 
                    '/etc/pam.d/system-auth 파일에 auth required pam_tally2.so deny=5 unlock_time=120 설정 추가'),
                    
                    ('U-04', '/etc/shadow 파일 소유자 및 권한 설정', 'Filesystem',
                    'shadow 파일에는 암호화된 패스워드가 저장되어 있어 유출 시 복호화 공격에 노출될 수 있습니다.',
                    '1. 소유자: root로 변경 (chown root /etc/shadow)\n2. 권한: 400으로 변경 (chmod 400 /etc/shadow)'),
                    
                    ('U-05', 'PATH 환경변수 점검', 'System',
                    'PATH에 ".(현재 디렉토리)"가 포함되면, 공격자가 악의적인 파일을 실행하도록 유도할 수 있습니다.',
                    '/etc/profile 등 설정 파일에서 PATH 변수에 "." 또는 "::" 제거'),
                    
                    ('U-06', '소유자 없는 파일 및 디렉터리 관리', 'Filesystem',
                    '소유자가 존재하지 않는 파일은 관리가 되지 않아 공격자가 이를 악용하거나 변조할 수 있습니다.',
                    'find / -nouser -o -nogroup 명령으로 파일 식별 후 삭제하거나 소유자 지정'),
                    
                    ('U-07', '/etc/passwd 파일 소유자 및 권한 설정', 'Filesystem',
                    'passwd 파일의 권한이 개방되어 있으면 계정 정보를 탈취당할 수 있습니다.',
                    'chmod 644 /etc/passwd 및 chown root /etc/passwd 수행'),
                    
                    ('U-08', '/etc/shadow 파일 소유자 및 권한 설정', 'Filesystem',
                    '(중복 항목) shadow 파일 보호는 필수적입니다.',
                    'chmod 400 /etc/shadow 수행'),
                    
                    ('U-09', '/etc/hosts 파일 소유자 및 권한 설정', 'Filesystem',
                    'hosts 파일 변조 시 피싱 사이트로 유도되는 파밍 공격에 노출될 수 있습니다.',
                    'chmod 600 /etc/hosts 및 소유자 root 확인'),
                    
                    ('U-10', '/etc/xinetd.conf 파일 소유자 및 권한 설정', 'Service',
                    '서비스 설정 파일이 변조되면 백도어 포트가 열릴 수 있습니다.',
                    'chmod 600 /etc/xinetd.conf 수행'),
                    
                    ('U-11', '/etc/rsyslog.conf 파일 소유자 및 권한 설정', 'Log',
                    '로그 설정이 변조되면 침해 사고 발생 시 추적이 불가능해집니다.',
                    'chmod 644 /etc/rsyslog.conf 수행'),
                    
                    ('U-12', '/etc/services 파일 소유자 및 권한 설정', 'Service',
                    '포트와 서비스 매핑 정보가 변조되면 정상 서비스가 방해받을 수 있습니다.',
                    'chmod 644 /etc/services 수행'),
                    
                    ('U-13', 'SetUID, SetGID, Sticky Bit 설정 파일 점검', 'Filesystem',
                    '불필요한 SetUID 파일은 권한 상승 공격의 주요 타겟이 됩니다.',
                    '주요 실행 파일 외 불필요한 SetUID 비트 제거 (chmod -s 파일명)')
                    # --- Windows Server 진단 항목 (W-Type) ---
                    ('W-01', 'Administrator 계정 이름 변경', 'Account', 
                    '기본 관리자 계정(Administrator)을 그대로 사용할 경우, 공격자가 계정명을 이미 알고 있어 무차별 대입 공격(Brute Force)에 취약해집니다.', 
                    '1. 제어판 > 관리 도구 > 로컬 보안 정책\n2. 로컬 정책 > 보안 옵션\n3. "계정: Administrator 계정 이름 바꾸기" 정책에서 추측하기 어려운 이름으로 변경'),

                    ('W-02', 'Guest 계정 비활성화', 'Account', 
                    'Guest 계정은 불특정 다수의 접근을 허용할 수 있어 보안상 매우 위험합니다. 사용하지 않는다면 반드시 비활성화해야 합니다.', 
                    '1. 컴퓨터 관리(compmgmt.msc) > 로컬 사용자 및 그룹 > 사용자\n2. Guest 계정 우클릭 > 속성\n3. "계정 사용 안 함" 체크'),

                    ('W-03', '불필요한 서비스 제거 (Telnet)', 'Service', 
                    'Telnet은 데이터를 평문으로 전송하므로 패킷 스니핑 공격을 통해 계정 정보가 유출될 수 있습니다.', 
                    '1. 서비스 관리자(services.msc) 실행\n2. Telnet 서비스 중지 및 시작 유형을 "사용 안 함"으로 설정\n3. 가급적 SSH 등 암호화된 프로토콜 사용 권장')
                ]
                
                cursor.executemany("""
                    INSERT INTO TBL_VULN_DEF (code, name, category, description, remediation) 
                    VALUES (?, ?, ?, ?, ?)
                """, vuln_data)

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