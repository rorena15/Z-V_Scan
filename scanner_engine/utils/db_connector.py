# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
# [FINAL FIXED] utils/db_connector.py
# get_asset_id 메서드 복구 및 KISA 증적 저장 기능 통합 버전

import sqlite3
import os
import sys
import threading
import time
from datetime import datetime
from utils.logger import AppLogger
from utils import rule_crypto
# [버그 수정] RULE_FILES/IMPORTANCE_WEIGHT가 이 파일/text_report.py/excel_report.py
# 세 곳에 따로 복사돼 있어 하나만 안 고치면 조용히 어긋났다 - 공용으로 통합
# (새 파일을 만들지 않고 rule_crypto.py에 합침 - PyArmor 트라이얼 파일 수 제약).
from utils.rule_crypto import RULE_FILES, IMPORTANCE_WEIGHT

# [hostname 우선순위 - 2026-08-06 추가] 여러 경로로 hostname이 식별됐을 때, 신뢰도
# 낮은 출처가 이미 확보된 신뢰도 높은 hostname을 조용히 덮어쓰지 않게 순위를 정한다
# (숫자가 작을수록 우선순위 높음). 실측(인증 접속으로 확인)/수동입력(사람이 직접
# 입력)은 자동 추정(역DNS/매핑/vendor 추정)보다 항상 우선한다. 알 수 없는/빈 출처는
# 가장 낮은 우선순위로 둬서 항상 새 값으로 덮어써질 수 있게 한다(기존 호출부 호환).
HOSTNAME_SOURCE_PRIORITY = {"실측": 1, "수동입력": 2, "역DNS": 3, "매핑": 4, "추정": 5}


def _hostname_source_rank(source):
    return HOSTNAME_SOURCE_PRIORITY.get(source, 99)

class DBConnector:
    _db_lock = threading.Lock()

    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))

        self.db_path = os.path.join(base_path, 'zvuln_scan.db')
        self._rule_importance_cache = None
        self._rule_defs_cache = None
        self._init_db()

    def _init_db(self):
        """DB 테이블 초기화 (Schema V3.0 - Evidence & Waiver Support)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
        
            # [최적화 적용] WAL 모드 활성화
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
                    vendor TEXT,
                    last_seen DATETIME,
                    description TEXT DEFAULT '',
                    hostname_source TEXT DEFAULT ''
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

            # 3. 스캔 결과 테이블 (증적 및 KISA 코드 컬럼 추가됨)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS TBL_SCAN_RESULT (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    vuln_code TEXT,
                    kisa_code TEXT,         -- [NEW] KISA 주요정보통신기반시설 코드 (예: U-01)
                    vuln_name TEXT,
                    risk_level TEXT,
                    status TEXT,
                    detected_value TEXT,
                    raw_output TEXT,        -- [NEW] 상세 증적 데이터 (헌법 2조 준수)
                    remediation TEXT,
                    waiver_status INTEGER DEFAULT 0, -- [NEW] 예외처리 여부 (0:미처리, 1:예외)
                    waiver_reason TEXT,              -- [NEW] 예외처리 사유
                    scan_date DATETIME,
                    FOREIGN KEY(asset_id) REFERENCES TBL_ASSETS(asset_id)
                )
            ''')
            
            # [마이그레이션] 기존 DB에 컬럼이 없을 경우 추가
            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN kisa_code TEXT")
            except sqlite3.OperationalError: pass
            
            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN raw_output TEXT")
            except sqlite3.OperationalError: pass

            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN waiver_status INTEGER DEFAULT 0")
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN waiver_reason TEXT")
            except sqlite3.OperationalError: pass

            # [Phase 2: 스캔 이력 보존] 삭제-후-삽입 대신 회차(scan_round)별로 누적 저장
            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN session_id TEXT")
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN scan_round INTEGER DEFAULT 1")
            except sqlite3.OperationalError: pass

            # [Phase 2: Waiver 승인자 필드] 예외처리 시 누가/언제 승인했는지 기록
            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN waiver_approver TEXT")
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN waiver_date TEXT")
            except sqlite3.OperationalError: pass

            # [Phase 2: 운영자 태깅] 어떤 운영자가 수행한 스캔인지 결과에 함께 기록
            try:
                cursor.execute("ALTER TABLE TBL_SCAN_RESULT ADD COLUMN operator TEXT")
            except sqlite3.OperationalError: pass

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

            # 5. [대시보드 - 최근 활동 개편] 세션(스캔 1회 실행)당 어떤 대상 문자열
            # (IP/범위/CIDR)을 어떤 모드(Discovery/Audit)로 스캔했는지 기록. 예전엔
            # TBL_SCAN_RESULT에 session_id는 남아도 "무슨 대역을 스캔했는지"는 어디에도
            # 저장되지 않아서 대시보드에서 보여줄 수가 없었다 - worker.py.run()이 스캔
            # 시작 시점에 한 번 기록한다(대상이 하나도 안 살아있어도 시도한 사실은 남게).
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS TBL_SCAN_SESSIONS (
                    session_id TEXT PRIMARY KEY,
                    target_input TEXT,
                    mode TEXT,
                    started_at DATETIME
                )
            ''')
            
            # 자산 테이블 컬럼 보정
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN open_ports TEXT DEFAULT ''")
            except sqlite3.OperationalError: pass

            # [버그 수정 - 실사용 중 확인] vendor는 CREATE TABLE 문에만 있고 이 마이그레이션이
            # 빠져있었다 - vendor 컬럼이 스키마에 추가되기 전에 이미 만들어진 DB 파일에는
            # 컬럼 자체가 없어서 "table TBL_ASSETS has no column named vendor" 오류로
            # save_asset()의 INSERT/UPDATE가 계속 실패하고 있었다.
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN vendor TEXT")
            except sqlite3.OperationalError: pass

            # [자산 태그/그룹 관리] 구역별(DMZ, 제어망 A 등) 분류/필터용 태그
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN zone_tag TEXT DEFAULT ''")
            except sqlite3.OperationalError: pass

            # [자산평가] Excel 리포트의 컨설턴트 스타일 자산평가(C/I/A -> 등급)를 위한 컬럼.
            # 스캔이 채우는 값이 아니라 사람이 입력하는 값이라 save_asset()이 아닌
            # update_asset_assessment()로만 갱신한다.
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN asset_purpose TEXT DEFAULT ''")
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN department TEXT DEFAULT ''")
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN owner_name TEXT DEFAULT ''")
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN conf_score INTEGER")
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN integ_score INTEGER")
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN avail_score INTEGER")
            except sqlite3.OperationalError: pass

            # [Phase 3: memo -> description 리네임] 기존 배포 DB는 이미 memo 컬럼으로
            # 생성돼 있으므로, RENAME COLUMN으로 데이터를 유실 없이 옮긴다. 이 저장소
            # 최초의 RENAME COLUMN 마이그레이션 - 지금까지는 전부 ADD COLUMN(추가)만
            # 있었다. 신규 DB는 위 CREATE TABLE에서 이미 description으로 만들어지므로
            # memo 컬럼이 없어 매번 예외로 조용히 스킵된다(멱등).
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS RENAME COLUMN memo TO description")
            except sqlite3.OperationalError: pass

            # [UI/UX 개선 - hostname 출처 배지] hostname이 어느 경로(역DNS/매핑/실측/추정)로
            # 채워졌는지 자산 목록에 표시하기 위한 컬럼. worker.py.discover_target()/
            # _save_hostname_update_to_db()가 채운다.
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN hostname_source TEXT DEFAULT ''")
            except sqlite3.OperationalError: pass

            conn.commit()
            conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown", open_ports="", mac_addr="-", vendor="", hostname_source=""):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("SELECT asset_id, hostname_source FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()

                if row:
                    asset_id, existing_source = row
                    # [hostname 우선순위] 새로 들어온 출처가 기존보다 신뢰도가 낮으면(예:
                    # 실측으로 이미 확보된 hostname을 나중 스캔의 역DNS 결과가 덮어쓰려는
                    # 경우) hostname/hostname_source는 그대로 두고 나머지 필드만 갱신한다.
                    update_hostname = _hostname_source_rank(hostname_source) <= _hostname_source_rank(existing_source)

                    if update_hostname:
                        if mac_addr and mac_addr not in ["-", "Unknown"]:
                            cursor.execute("""
                                UPDATE TBL_ASSETS
                                SET last_seen=?, hostname=?, os_type=?, open_ports=?, mac_addr=?, hostname_source=?
                                WHERE asset_id=?
                            """, (now, hostname, os_type, open_ports, mac_addr, hostname_source, asset_id))
                        else:
                            cursor.execute("""
                                UPDATE TBL_ASSETS
                                SET last_seen=?, hostname=?, os_type=?, open_ports=?, hostname_source=?
                                WHERE asset_id=?
                            """, (now, hostname, os_type, open_ports, hostname_source, asset_id))
                    else:
                        if mac_addr and mac_addr not in ["-", "Unknown"]:
                            cursor.execute("""
                                UPDATE TBL_ASSETS
                                SET last_seen=?, os_type=?, open_ports=?, mac_addr=?
                                WHERE asset_id=?
                            """, (now, os_type, open_ports, mac_addr, asset_id))
                        else:
                            cursor.execute("""
                                UPDATE TBL_ASSETS
                                SET last_seen=?, os_type=?, open_ports=?
                                WHERE asset_id=?
                            """, (now, os_type, open_ports, asset_id))
                    # [수정] vendor는 지금까지 어떤 경로로도 DB에 저장되지 않고 있었다(누락 버그).
                    # mac_addr과 같은 규칙으로, 이번에 못 얻었으면("Unknown"/"Unknown Vendor") 이전에
                    # 알아낸 값을 덮어쓰지 않는다.
                    if vendor and vendor not in ["Unknown", "Unknown Vendor", "-"]:
                        cursor.execute("UPDATE TBL_ASSETS SET vendor=? WHERE asset_id=?", (vendor, asset_id))
                else:
                    cursor.execute("""
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, open_ports, mac_addr, vendor, last_seen, description, hostname_source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (ip, hostname, os_type, open_ports, mac_addr, vendor, now, "", hostname_source))
                    asset_id = cursor.lastrowid
                conn.commit()
                return asset_id
            except Exception as e:
                AppLogger.log_error(f"[DB] Save Asset Error: {ip}", e)
                return None
            finally:
                conn.close()

    @staticmethod
    def compute_asset_grade(c, i, a):
        """C/I/A(각 1~3점) 합산으로 자산등급을 계산한다: 합산 <=2는 "-", >=7은 "상",
        >=5는 "중", 그 외는 "하". 값이 하나라도 없으면(미평가) "-"를 반환한다."""
        if c is None or i is None or a is None:
            return "-"
        total = c + i + a
        if total <= 2:
            return "-"
        if total >= 7:
            return "상"
        if total >= 5:
            return "중"
        return "하"

    def update_asset_assessment(self, asset_id, purpose="", department="", owner="", c=None, i=None, a=None):
        """[자산평가] 스캔이 채우는 값이 아니라 사람이 입력하는 값이라 save_asset()과
        분리한다 - 스캔 재실행/재발견 시 이 값들이 덮어써지면 안 된다."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE TBL_ASSETS
                    SET asset_purpose=?, department=?, owner_name=?, conf_score=?, integ_score=?, avail_score=?
                    WHERE asset_id=?
                """, (purpose, department, owner, c, i, a, asset_id))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Update Asset Assessment Error: {asset_id}", e)
                return False
            finally:
                conn.close()

    def get_asset_assessment_list(self):
        """[자산평가 다이얼로그 / Excel 리포트 공용] 자산평가 컬럼을 포함한 자산 목록."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT asset_id, ip_addr, hostname, asset_purpose, department, owner_name,
                           conf_score, integ_score, avail_score
                    FROM TBL_ASSETS ORDER BY ip_addr ASC
                """)
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Asset Assessment List Error", e)
                return []
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

    def get_discovery_info(self, ip):
        """Audit이 재스캔 없이 재사용할 이전 Discovery 결과 (os_type/open_ports)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT os_type, open_ports FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                if not row or not row[1]:
                    return None
                os_type, ports_str = row
                open_ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
                return {"os_type": os_type or "Unknown", "open_ports": open_ports}
            except Exception as e:
                AppLogger.log_error(f"[DB] Get Discovery Info Failed ({ip})", e)
                return None
            finally: conn.close()

    # [Phase 2: 스캔 이력 보존] 삭제-후-삽입(덮어쓰기) 대신, 자산+코드별 회차(scan_round)를 증가시켜
    # 이전 회차 결과를 보존한 채 새 회차를 누적한다. 리포트/조회는 항상 최신 회차만 보도록
    # get_latest_round_filter()가 만드는 서브쿼리 조건을 함께 사용해야 한다.
    def save_result(self, asset_id, code, name, risk, status, detail, remediation="-", raw_output="", kisa_code="",
                     session_id=None, operator=""):
        # [버그 수정] 예전엔 MAX(scan_round)+1 조회와 INSERT 사이를 파이썬
        # threading.Lock(_db_lock)으로만 직렬화했다 - 이건 "같은 프로세스 안의
        # 여러 스레드"만 막아주고, 같은 zvuln_scan.db를 가리키는 별도 프로세스
        # 두 개(예: 공유/네트워크 경로에 DB를 두고 두 PC에서 동시 실행)가 동시에
        # 같은 MAX값을 읽어버리면 동일 scan_round로 중복 INSERT될 수 있었다.
        # BEGIN IMMEDIATE로 SQLite 파일 잠금 자체를 트랜잭션 시작 시점에 걸어,
        # 프로세스 경계와 무관하게 조회+삽입을 원자적으로 만든다. 다른 프로세스가
        # 이미 쓰기 잠금을 쥐고 있으면 "database is locked"가 날 수 있어 짧게
        # 재시도한다.
        with self._db_lock:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            max_attempts = 5
            for attempt in range(1, max_attempts + 1):
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
                conn.isolation_level = None  # autocommit off - BEGIN/COMMIT을 직접 제어
                cursor = conn.cursor()
                try:
                    cursor.execute("BEGIN IMMEDIATE")
                    cursor.execute(
                        "SELECT COALESCE(MAX(scan_round), 0) + 1 FROM TBL_SCAN_RESULT WHERE asset_id=? AND vuln_code=?",
                        (asset_id, code)
                    )
                    next_round = cursor.fetchone()[0]

                    cursor.execute("""
                        INSERT INTO TBL_SCAN_RESULT
                        (asset_id, vuln_code, kisa_code, vuln_name, risk_level, status, detected_value, raw_output,
                         remediation, scan_date, session_id, scan_round, operator)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (asset_id, code, kisa_code, name, risk, status, detail, raw_output, remediation,
                          now, session_id, next_round, operator))
                    cursor.execute("COMMIT")
                    return True
                except sqlite3.OperationalError as e:
                    try:
                        cursor.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    if "locked" in str(e).lower() and attempt < max_attempts:
                        time.sleep(0.2 * attempt)
                        continue
                    AppLogger.log_error(f"[DB] Save Result Error", e)
                    return False
                except Exception as e:
                    try:
                        cursor.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    AppLogger.log_error(f"[DB] Save Result Error", e)
                    return False
                finally:
                    conn.close()
            return False

    @staticmethod
    def latest_round_condition(table_alias="R"):
        """
        [Phase 2] 스캔 이력이 누적되므로, "현재 상태"를 보여줘야 하는 모든 조회(리포트/대시보드/
        미들웨어 연동 등)는 자산+코드별 최신 회차(scan_round)만 걸러내야 한다. 공용 서브쿼리 조건을
        여기서 한 곳에 모아 SQL 문자열마다 따로 작성하다 실수하는 것을 방지한다.
        """
        return (
            f"{table_alias}.scan_round = ("
            f"SELECT MAX(R2.scan_round) FROM TBL_SCAN_RESULT R2 "
            f"WHERE R2.asset_id = {table_alias}.asset_id AND R2.vuln_code = {table_alias}.vuln_code)"
        )

    def get_round_comparison(self):
        """[Phase 5: Diff 리포트] 자산별로 '최신 회차'와 '그 직전 회차'를 비교해
        점수 변화(개선율)를 계산한다. scan_round는 (asset_id, vuln_code) 단위로
        따로 올라가므로(전문가 모드로 이번엔 뺀 코드가 있으면 코드마다 회차가
        어긋날 수 있음), 자산 전체가 아니라 코드 하나하나의 '그 코드의 최신
        회차'/'그 코드의 직전 회차'를 비교해서 합산하는 방식으로 계산한다.
        2회 이상 스캔된 코드가 하나도 없는 자산은 비교 대상에서 제외한다."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT DISTINCT A.asset_id, A.ip_addr, A.hostname
                    FROM TBL_ASSETS A
                    JOIN TBL_SCAN_RESULT R ON R.asset_id = A.asset_id
                    WHERE R.vuln_code NOT LIKE 'SYS-%'
                    GROUP BY A.asset_id, R.vuln_code
                    HAVING MAX(R.scan_round) >= 2
                """)
                candidate_assets = {}
                for asset_id, ip, hostname in cursor.fetchall():
                    candidate_assets[asset_id] = (ip, hostname)

                def _score(vh, vm, ph, pm):
                    deduction = vh * 5 + vm * 2 + ph * 2.5 + pm * 1
                    return max(0, round(100 - deduction))

                def _counts_for(asset_id, round_map):
                    vh = vm = ph = pm = 0
                    for code, rnd in round_map.items():
                        cursor.execute("""
                            SELECT status, risk_level, waiver_status FROM TBL_SCAN_RESULT
                            WHERE asset_id=? AND vuln_code=? AND scan_round=?
                        """, (asset_id, code, rnd))
                        row = cursor.fetchone()
                        if not row:
                            continue
                        status, risk, waived = row
                        if waived == 1:
                            continue
                        if status == "VULNERABLE":
                            if risk in ("Critical", "High"): vh += 1
                            else: vm += 1
                        elif status == "PARTIAL":
                            if risk in ("Critical", "High"): ph += 1
                            else: pm += 1
                    return vh, vm, ph, pm

                results = []
                for asset_id, (ip, hostname) in candidate_assets.items():
                    cursor.execute("""
                        SELECT vuln_code, MAX(scan_round) FROM TBL_SCAN_RESULT
                        WHERE asset_id=? AND vuln_code NOT LIKE 'SYS-%'
                        GROUP BY vuln_code
                    """, (asset_id,))
                    current_map = {code: rnd for code, rnd in cursor.fetchall()}
                    previous_map = {code: rnd - 1 for code, rnd in current_map.items() if rnd >= 2}

                    cur_vh, cur_vm, cur_ph, cur_pm = _counts_for(asset_id, current_map)
                    prev_vh, prev_vm, prev_ph, prev_pm = _counts_for(asset_id, previous_map)
                    cur_score = _score(cur_vh, cur_vm, cur_ph, cur_pm)
                    prev_score = _score(prev_vh, prev_vm, prev_ph, prev_pm)

                    results.append({
                        "ip": ip, "hostname": hostname,
                        "prev_score": prev_score, "current_score": cur_score,
                        "improvement": cur_score - prev_score,
                        "prev_vuln_total": prev_vh + prev_vm, "current_vuln_total": cur_vh + cur_vm,
                        "prev_partial_total": prev_ph + prev_pm, "current_partial_total": cur_ph + cur_pm,
                    })
                return results
            except Exception as e:
                AppLogger.log_error("[DB] Round Comparison Error", e)
                return []
            finally:
                conn.close()

    # 하위 호환성 유지용 (기존 코드가 이 메서드를 호출할 경우 대비)
    def save_scan_result(self, asset_id, vuln_code, status, detail, vuln_name=None, remediation=None):
        return self.save_result(asset_id, vuln_code, vuln_name or vuln_code, "Info", status, detail, remediation)

    def get_all_assets(self):
        """반환: [(ip_addr, os_type, description, mac_addr, hostname, hostname_source), ...]
        [버그 수정] hostname은 원래 이 쿼리로 조회되지 않아 앱 재시작/새로고침 때마다
        자산 목록의 Host 칸이 항상 빈칸으로 표시되던 문제가 있었다 - 실측으로 확인됨.
        hostname_source는 UI/UX 개선(hostname 출처 배지)을 위해 함께 추가."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT ip_addr, os_type, description, mac_addr, hostname, hostname_source
                    FROM TBL_ASSETS ORDER BY last_seen DESC
                """)
                return cursor.fetchall()
            except: return []
            finally: conn.close()

    def get_all_assets_for_export(self):
        """[자산 export - 2026-08-06 신규] 자산 목록 CSV/Excel 내보내기 전용 - 화면
        테이블보다 많은 컬럼(vendor/구역태그/부서/담당자/설명/용도)까지 전부 포함한다.
        반환: [(ip_addr, hostname, hostname_source, os_type, mac_addr, vendor,
                zone_tag, department, owner_name, description, asset_purpose, last_seen), ...]"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT ip_addr, hostname, hostname_source, os_type, mac_addr, vendor,
                           zone_tag, department, owner_name, description, asset_purpose, last_seen
                    FROM TBL_ASSETS ORDER BY ip_addr ASC
                """)
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get All Assets For Export Failed", e)
                return []
            finally:
                conn.close()

    # [Phase 3: 대시보드] ---------------------------------------------------
    def get_dashboard_metrics(self):
        """
        대시보드 요약 지표 4개: 점검 자산 수 / Critical 발견 수 / 부분만족 수 / 접속 실패 수.
        전부 최신 회차(latest_round_condition) 기준이며, 예외처리(waiver)된 항목은 제외한다.
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            metrics = {"assets_scanned": 0, "critical_findings": 0, "partial_compliance": 0, "connection_errors": 0}
            try:
                cursor.execute("SELECT COUNT(*) FROM TBL_ASSETS")
                row = cursor.fetchone()
                if row: metrics["assets_scanned"] = row[0]

                cursor.execute(f"""
                    SELECT COUNT(*) FROM TBL_SCAN_RESULT R
                    WHERE status = 'VULNERABLE' AND risk_level IN ('Critical', 'High') AND waiver_status = 0
                    AND {self.latest_round_condition('R')}
                """)
                row = cursor.fetchone()
                if row: metrics["critical_findings"] = row[0]

                cursor.execute(f"""
                    SELECT COUNT(*) FROM TBL_SCAN_RESULT R
                    WHERE status = 'PARTIAL' AND waiver_status = 0
                    AND {self.latest_round_condition('R')}
                """)
                row = cursor.fetchone()
                if row: metrics["partial_compliance"] = row[0]

                cursor.execute(f"""
                    SELECT COUNT(*) FROM TBL_SCAN_RESULT R
                    WHERE vuln_code LIKE 'CONN-%'
                    AND {self.latest_round_condition('R')}
                """)
                row = cursor.fetchone()
                if row: metrics["connection_errors"] = row[0]
            except Exception as e:
                AppLogger.log_error("[DB] Get Dashboard Metrics Failed", e)
            finally:
                conn.close()
            return metrics

    def _final_status_label(self, status, waived):
        """output/excel_report.py._final_status()와 동일 매핑 - 보안수준 계산에서
        같은 상태 문자열을 써야 채점 분기(취약/부분만족/양호/그외)가 일치한다."""
        if waived == 1: return "예외"
        if status == "VULNERABLE": return "취약"
        if status == "PARTIAL": return "부분만족"
        if status == "NA": return "해당없음"
        if status == "MANUAL": return "검토필요"
        if status == "ERROR": return "점검불가"
        return "양호"

    def _load_rule_defs(self):
        """vuln_code(엔진 접두어 포함) -> rule dict 전체. 프로세스 생애주기 동안 1회만
        로드해 캐시한다(rules/*.json은 실행 중 안 바뀜) - importance/category 등 여러
        조회가 이 캐시 하나를 공유해서 파일을 중복으로 읽지 않는다."""
        if self._rule_defs_cache is not None:
            return self._rule_defs_cache
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_path, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')

        defs = {}
        for filename, prefix in RULE_FILES.items():
            path = os.path.join(rules_dir, filename)
            if not os.path.exists(path) and not os.path.exists(rule_crypto.get_enc_path(path)):
                continue
            try:
                data = rule_crypto.load_ruleset(path)
                for rule in data:
                    defs[f"{prefix}{rule['code']}"] = rule
            except Exception as e:
                AppLogger.log_error(f"[DB] Failed to load {filename} rule defs", e)
        self._rule_defs_cache = defs
        return defs

    def _load_rule_importance_lookup(self):
        """vuln_code(엔진 접두어 포함) -> importance(상/중/하)."""
        if self._rule_importance_cache is not None:
            return self._rule_importance_cache
        lookup = {code: rule.get("importance", "중") for code, rule in self._load_rule_defs().items()}
        self._rule_importance_cache = lookup
        return lookup

    def _score_at_round(self, by_key, rule_lookup, round_picker):
        """get_dashboard_trend()(최신 vs 직전)와 get_security_level_history()(회차별
        시계열)가 공유하는 채점 로직. by_key: {(asset_id, vuln_code): {round: (status,
        risk, waived)}}. round_picker(rounds)가 각 코드마다 어떤 회차를 볼지 고른다
        (None이면 그 코드는 이번 집계에서 제외)."""
        full = 0.0
        vuln = 0.0
        counted = False
        crit = 0
        partial = 0
        has_any_round = False
        for (asset_id, vuln_code), rounds in by_key.items():
            rnd = round_picker(rounds)
            if rnd is None:
                continue
            has_any_round = True
            status, risk, waived = rounds[rnd]
            label = self._final_status_label(status, waived)

            # get_dashboard_metrics()와 동일 정의 - 코드 종류 무관하게 전부 집계
            if label == "취약" and risk in ("Critical", "High"):
                crit += 1
            if label == "부분만족":
                partial += 1

            # 보안수준 - rules/*.json에 실제 정의된 코드만 채점(excel_report.py와 동일 범위)
            if vuln_code in rule_lookup:
                weight = IMPORTANCE_WEIGHT.get(rule_lookup[vuln_code], 8)
                if label == "취약":
                    full += weight; vuln += weight; counted = True
                elif label == "부분만족":
                    full += weight; vuln += weight / 2; counted = True
                elif label == "양호":
                    full += weight; counted = True
        security = None if (not counted or full == 0) else round((full - vuln) / full * 100, 1)
        return security, crit, partial, has_any_round

    def get_dashboard_trend(self):
        """[대시보드 KPI] '보안수준' 게이지 + KPI 카드별 '전 회차 대비' 추이를 한 번의
        조회로 함께 계산한다. scan_round는 (asset_id, vuln_code) 단위로 따로 올라가므로
        (get_round_comparison()과 동일 이유) 코드 하나하나의 최신/직전 회차를 비교하는
        방식으로 계산한다 - 실측 데이터 기반이며 가짜 수치를 넣지 않는다.
        보안수준 산식은 output/excel_report.py._score_group()과 동일(중요도 가중치,
        부분만족=0.5가중, 예외/해당없음 제외)해서 Excel 리포트 표지의 보안수준과 일치한다.
        보안수준 채점 대상은 rule_lookup에 실제 정의된 코드만이다(SYS-/CONN- 같은 메타
        항목은 애초에 rules/*.json에 없어 자동으로 빠진다 - excel_report.py도 rule_lookup
        기반 코드만 채점하므로 동일한 제외 효과).
        critical_findings/partial_compliance current 값은 get_dashboard_metrics()와
        완전히 같은 정의(코드 종류 무관, 최신 회차, waiver 제외)로 세서 그 카드 값과
        정확히 일치한다 - [버그 수정] 처음엔 보안수준용 코드 필터(SYS-/CONN- 등 제외)를
        crit/partial 집계에도 그대로 썼다가 get_dashboard_metrics()보다 적게 세는
        불일치가 실측 확인됨(예: 21 vs 19) - 두 집계를 분리해서 고쳤다.
        반환: {
          "security_level": {"current": float|None, "previous": float|None, "delta": float|None},
          "critical_findings": {"current": int, "previous": int|None, "delta": int|None},
          "partial_compliance": {"current": int, "previous": int|None, "delta": int|None},
        } (2회 이상 스캔된 코드가 하나도 없으면 previous/delta는 None)"""
        empty = {
            "security_level": {"current": None, "previous": None, "delta": None},
            "critical_findings": {"current": 0, "previous": None, "delta": None},
            "partial_compliance": {"current": 0, "previous": None, "delta": None},
        }
        rule_lookup = self._load_rule_importance_lookup()
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT asset_id, vuln_code, scan_round, status, risk_level, waiver_status
                    FROM TBL_SCAN_RESULT
                """)
                rows = cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Dashboard Trend Failed", e)
                return empty
            finally:
                conn.close()

        by_key = {}
        for asset_id, vuln_code, rnd, status, risk, waived in rows:
            by_key.setdefault((asset_id, vuln_code), {})[rnd] = (status, risk, waived)

        def _previous_round(rounds):
            latest = max(rounds)
            return latest - 1 if latest >= 2 and (latest - 1) in rounds else None

        cur_security, cur_crit, cur_partial, _ = self._score_at_round(by_key, rule_lookup, lambda rounds: max(rounds))
        prev_security, prev_crit, prev_partial, prev_has_any = self._score_at_round(by_key, rule_lookup, _previous_round)

        def _delta(cur, prev):
            return None if (cur is None or prev is None) else round(cur - prev, 1)

        return {
            "security_level": {
                "current": cur_security, "previous": prev_security,
                "delta": _delta(cur_security, prev_security),
            },
            "critical_findings": {
                "current": cur_crit,
                "previous": prev_crit if prev_has_any else None,
                "delta": (cur_crit - prev_crit) if prev_has_any else None,
            },
            "partial_compliance": {
                "current": cur_partial,
                "previous": prev_partial if prev_has_any else None,
                "delta": (cur_partial - prev_partial) if prev_has_any else None,
            },
        }

    def get_security_level_history(self, max_points=12):
        """[대시보드 - 보안수준 추이 라인차트] 회차(scan_round)별 보안수준을 시계열로
        반환한다. scan_round는 (asset_id, vuln_code) 단위 독립 카운터라(전문가 모드로
        코드마다 이번엔 뺐다 다시 넣었다 하면 회차가 어긋날 수 있음) 진짜 "동시각"
        타임라인은 아니지만, get_dashboard_trend()/get_round_comparison()과 동일하게
        "그 회차 번호에 도달한 코드들의 그 시점 값"을 모아 근사한다 - 완벽하진 않아도
        가짜 수치를 넣지 않는 실측 기반 근사치다(_score_at_round() 재사용).
        반환: [{"round": int, "security_level": float|None}, ...] (오래된 순, 최대
        max_points개 - 회차가 아주 많이 쌓이면 그래프가 읽기 힘들어지는 것 방지).
        회차 자체가 없으면(스캔 이력 없음) 빈 리스트."""
        rule_lookup = self._load_rule_importance_lookup()
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT asset_id, vuln_code, scan_round, status, risk_level, waiver_status
                    FROM TBL_SCAN_RESULT
                """)
                rows = cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Security Level History Failed", e)
                return []
            finally:
                conn.close()

        by_key = {}
        max_round = 0
        for asset_id, vuln_code, rnd, status, risk, waived in rows:
            by_key.setdefault((asset_id, vuln_code), {})[rnd] = (status, risk, waived)
            max_round = max(max_round, rnd)

        if max_round == 0:
            return []

        history = []
        for n in range(1, max_round + 1):
            security, _, _, has_any = self._score_at_round(
                by_key, rule_lookup, lambda rounds, n=n: n if n in rounds else None
            )
            if has_any:
                history.append({"round": n, "security_level": security})

        return history[-max_points:]

    def get_latest_findings(self):
        """[대시보드 웹뷰 - 원본 데이터] 위험도 분포/카테고리별 현황/Top 취약자산/
        Top 다발항목/드릴다운 테이블까지 전부 이 원본 리스트 하나에서 JS가
        계산한다(gui/web/dashboard.js) - Python이 화면마다 따로 집계 쿼리를 만드는
        대신, 최신 회차 findings를 통째로 넘기고 집계/필터/드릴다운은 클라이언트에서
        처리한다. 자산 수 x 룰(~250개) 규모라 한 번에 넘겨도 무리 없다.

        예전엔 get_status_distribution()/get_category_breakdown()으로 따로
        집계해서 반환했는데("정보가 너무 부족하다"는 피드백으로 확인됨), 집계된
        숫자만 있으면 "그 뒤에 어떤 자산/항목이 있는지" 드릴다운이 안 됐다 -
        원본을 넘기는 쪽으로 교체했다.

        최신 회차, rules/*.json에 실제 정의된 코드(SYS-/CONN- 등 메타 항목 제외)만,
        waiver 처리된 항목은 제외(KPI 카드와 동일 모집단).
        반환: [{"ip":str, "hostname":str, "os_type":str, "code":str, "name":str,
                "category":str, "importance":str, "status":str, "risk":str}, ...]
        (os_type은 대시보드 웹뷰 JS는 안 쓰고, main_window.py의 자산 탭 드릴다운
        테이블 표시용으로 2026-09에 추가됨)"""
        rule_defs = self._load_rule_defs()
        findings = []
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(f"""
                    SELECT A.ip_addr, A.hostname, A.os_type, R.vuln_code, R.status, R.risk_level
                    FROM TBL_SCAN_RESULT R
                    JOIN TBL_ASSETS A ON A.asset_id = R.asset_id
                    WHERE R.waiver_status = 0 AND {self.latest_round_condition('R')}
                """)
                rows = cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Latest Findings Failed", e)
                return []
            finally:
                conn.close()

        for ip, hostname, os_type, code, status, risk in rows:
            rule = rule_defs.get(code)
            if not rule:
                continue
            findings.append({
                "ip": ip,
                "os_type": os_type or "",
                "hostname": hostname or ip,
                "code": code,
                "name": rule.get("name", code),
                "category": rule.get("category", "기타"),
                "importance": rule.get("importance", "중"),
                "status": status,
                "risk": risk or "",
            })
        return findings

    def save_scan_session(self, session_id, target_input, mode):
        """[대시보드 - 최근 활동 개편] 스캔 1회 실행이 시작될 때 worker.py가 한 번
        호출한다 - "무슨 대역/대상을 어떤 모드로 스캔했는지"를 기록해서 대시보드
        최근 활동에 표시할 수 있게 한다. session_id가 PK라 같은 세션이 여러 번
        호출해도(재시도 등) 마지막 값으로 덮어쓰기만 될 뿐 중복 행은 안 생긴다."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO TBL_SCAN_SESSIONS (session_id, target_input, mode, started_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        target_input=excluded.target_input, mode=excluded.mode
                """, (session_id, target_input, mode, now))
                conn.commit()
            except Exception as e:
                AppLogger.log_error("[DB] Save Scan Session Failed", e)
            finally:
                conn.close()

    def get_recent_sessions(self, days=1):
        """[대시보드 - 최근 활동] session_id별로 묶어 언제/누가/몇 대를, 무슨 대역을
        어떤 모드로 스캔했는지 최신순으로 반환한다. session_id가 없는(구버전 데이터
        등) 결과는 제외한다. days=None이면 기간 제한 없이 전체를 반환한다(페이지네이션은
        호출부 - dashboard_widgets.RecentActivityCard - 가 담당).
        반환: [(session_id, operator, started_at, asset_count, target_input, mode,
                is_discovery_only), ...]"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                date_filter = "AND R.scan_date >= datetime('now', ?)" if days is not None else ""
                params = (f'-{int(days)} days',) if days is not None else ()
                cursor.execute(f"""
                    SELECT R.session_id, MAX(R.operator), MIN(R.scan_date), COUNT(DISTINCT R.asset_id),
                           MAX(S.target_input), MAX(S.mode),
                           SUM(CASE WHEN R.vuln_code NOT LIKE 'SYS-%' AND R.vuln_code NOT LIKE 'TCP-%'
                                    AND R.vuln_code NOT LIKE 'UDP-%' AND R.vuln_code NOT LIKE 'INFO-%'
                                    AND R.vuln_code NOT LIKE 'CONN-%' THEN 1 ELSE 0 END)
                    FROM TBL_SCAN_RESULT R
                    LEFT JOIN TBL_SCAN_SESSIONS S ON S.session_id = R.session_id
                    WHERE R.session_id IS NOT NULL AND R.session_id != ''
                    {date_filter}
                    GROUP BY R.session_id
                    ORDER BY MIN(R.scan_date) DESC
                """, params)
                rows = cursor.fetchall()
                return [
                    (session_id, operator, started_at, asset_count, target_input, mode, real_findings == 0)
                    for session_id, operator, started_at, asset_count, target_input, mode, real_findings in rows
                ]
            except Exception as e:
                AppLogger.log_error("[DB] Get Recent Sessions Failed", e)
                return []
            finally:
                conn.close()

    def get_unresolved_assets(self):
        """[커버리지 추적] 자산은 등록돼 있지만(TBL_ASSETS) 최신 회차에 실제 KISA 판정
        코드(U-/W-/D-/WEB-/PC- 등)가 단 하나도 없는 자산을 반환한다. Discovery 메타
        항목(SYS-/TCP-/UDP-/INFO-/CONN-)만 있는 경우도 "판정이 없다"로 취급한다 -
        포트가 열려있었다는 사실만으로는 KISA 감사 완결성을 충족하지 못한다.
        반환: [(ip_addr, hostname), ...]"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(f"""
                    SELECT A.ip_addr, A.hostname FROM TBL_ASSETS A
                    WHERE NOT EXISTS (
                        SELECT 1 FROM TBL_SCAN_RESULT R
                        WHERE R.asset_id = A.asset_id
                        AND {self.latest_round_condition('R')}
                        AND R.vuln_code NOT LIKE 'SYS-%' AND R.vuln_code NOT LIKE 'TCP-%'
                        AND R.vuln_code NOT LIKE 'UDP-%' AND R.vuln_code NOT LIKE 'INFO-%'
                        AND R.vuln_code NOT LIKE 'CONN-%'
                    )
                    ORDER BY A.ip_addr ASC
                """)
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Unresolved Assets Failed", e)
                return []
            finally:
                conn.close()

    def get_all_latest_findings(self):
        """
        대시보드 결과 테이블용: 모든 자산의 최신 회차 진단 결과 (SYS-/CONN-/TCP- 메타 항목 제외)를
        Host/OS/KISA 코드/Status/Risk 형태로 반환한다. TCP-*는 KISA 룰 판정이 아니라
        단순 포트 감지 결과(worker.py의 배너/서비스 탐지)라 실제 취약점 목록에서 제외한다.
        """
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(f"""
                    SELECT A.ip_addr, A.hostname, A.os_type,
                           CASE WHEN R.kisa_code IS NOT NULL AND R.kisa_code != '' THEN R.kisa_code ELSE R.vuln_code END,
                           R.vuln_name, R.status, R.risk_level, R.waiver_status
                    FROM TBL_SCAN_RESULT R
                    JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                    WHERE R.vuln_code NOT LIKE 'SYS-%' AND R.vuln_code NOT LIKE 'CONN-%' AND R.vuln_code NOT LIKE 'TCP-%'
                    AND {self.latest_round_condition('R')}
                    ORDER BY A.ip_addr ASC, R.vuln_code ASC
                """)
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get All Latest Findings Failed", e)
                return []
            finally:
                conn.close()

    def get_findings_by_session(self, session_id):
        """[UI/UX 개선 - 최근 활동 드릴다운] 대시보드 '최근 활동'의 세션 하나를 클릭했을 때
        그 세션이 실제로 남긴 결과만 보여주기 위한 조회. get_all_latest_findings()와 달리
        '최신 회차' 기준이 아니라 session_id로 직접 필터링한다 - 이후 재스캔으로 더 최신
        회차가 생겨도 그 세션 시점에 어떤 결과가 나왔는지 그대로 볼 수 있어야 하기 때문."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT A.ip_addr, A.hostname, A.os_type,
                           CASE WHEN R.kisa_code IS NOT NULL AND R.kisa_code != '' THEN R.kisa_code ELSE R.vuln_code END,
                           R.vuln_name, R.status, R.risk_level, R.waiver_status
                    FROM TBL_SCAN_RESULT R
                    JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                    WHERE R.session_id = ?
                    AND R.vuln_code NOT LIKE 'SYS-%' AND R.vuln_code NOT LIKE 'CONN-%' AND R.vuln_code NOT LIKE 'TCP-%'
                    ORDER BY A.ip_addr ASC, R.vuln_code ASC
                """, (session_id,))
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error("[DB] Get Findings By Session Failed", e)
                return []
            finally:
                conn.close()

    def get_vuln_count(self, ip):
        """미들웨어 연동 등에 사용할, 특정 자산의 실제 취약(VULNERABLE) 항목 수 (예외처리 제외)"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(f"""
                    SELECT COUNT(*) FROM TBL_SCAN_RESULT R
                    JOIN TBL_ASSETS A ON R.asset_id = A.asset_id
                    WHERE A.ip_addr = ? AND R.status = 'VULNERABLE' AND R.waiver_status = 0
                    AND {self.latest_round_condition('R')}
                """, (ip,))
                row = cursor.fetchone()
                return row[0] if row else 0
            except Exception as e:
                AppLogger.log_error(f"[DB] Vuln Count Query Failed ({ip})", e)
                return 0
            finally:
                conn.close()

    # [Phase 3: Waiver 관리] ------------------------------------------------
    def get_latest_results_for_asset(self, asset_id):
        """자산의 최신 회차 진단 결과 (SYSTEM Detail 제외) - Waiver 관리 UI용"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(f"""
                    SELECT result_id, vuln_code, kisa_code, vuln_name, risk_level, status,
                           waiver_status, waiver_reason, waiver_approver, waiver_date
                    FROM TBL_SCAN_RESULT R
                    WHERE asset_id = ? AND vuln_code NOT LIKE 'SYS-%' AND vuln_code NOT LIKE 'CONN-%'
                    AND {self.latest_round_condition('R')}
                    ORDER BY vuln_code ASC
                """, (asset_id,))
                return cursor.fetchall()
            except Exception as e:
                AppLogger.log_error(f"[DB] Get Latest Results Failed ({asset_id})", e)
                return []
            finally: conn.close()

    def set_waiver(self, result_id, waived, reason="", approver=""):
        """
        result_id(TBL_SCAN_RESULT.result_id) 단위로 예외처리를 설정/해제한다.
        [Phase 2/3] 예외처리 시 사유(reason)와 승인자(approver)를 함께 기록한다.

        [버그 수정] "사유+승인자 필수" 감사 요건이 지금까지 WaiverInputDialog(UI)
        에서만 강제되고 있었다 - 이 메서드를 다른 경로(일괄처리 기능, 스크립트,
        또 다른 다이얼로그 등)에서 그 다이얼로그를 거치지 않고 직접 호출하면
        빈 사유/승인자로도 예외처리가 그냥 걸렸다. 데이터 계층에서도 동일 요건을
        강제해 "다이얼로그가 유일한 관문"인 상태를 없앤다.
        """
        if waived and (not (reason or "").strip() or not (approver or "").strip()):
            AppLogger.log_error(
                f"[DB] Set Waiver rejected (result_id={result_id}): "
                "예외처리는 사유와 승인자가 모두 필요합니다."
            )
            return False

        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S") if waived else None
                cursor.execute("""
                    UPDATE TBL_SCAN_RESULT
                    SET waiver_status=?, waiver_reason=?, waiver_approver=?, waiver_date=?
                    WHERE result_id=?
                """, (1 if waived else 0, reason if waived else "", approver if waived else "", now, result_id))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Set Waiver Failed (result_id={result_id})", e)
                return False
            finally: conn.close()

    def get_description(self, ip):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT description FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()
                return row[0] if row else ""
            except: return ""
            finally: conn.close()

    def update_description(self, ip, description_text):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE TBL_ASSETS SET description = ? WHERE ip_addr = ?", (description_text, ip))
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
            
    def purge_old_results(self, days):
        """[Phase 3: 설정 페이지] scan_date 기준 days일보다 오래된 이력을 정리한다."""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "DELETE FROM TBL_SCAN_RESULT WHERE scan_date < datetime('now', ?)",
                    (f'-{int(days)} days',)
                )
                deleted = cursor.rowcount
                conn.commit()
                return deleted
            except Exception as e:
                AppLogger.log_error(f"[DB] Purge Old Results Failed", e)
                return -1
            finally: conn.close()

    def get_assets_for_manager(self):
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT asset_id, ip_addr, hostname, os_type, mac_addr, open_ports, last_seen, description, zone_tag
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
        # [자산 import 강화] department/owner_name 추가 - 정보자산목록 파일에 있는
        # 부서/담당자 컬럼을 import 시점에 바로 반영하기 위함. update_asset_assessment()는
        # C/I/A 점수까지 한 번에 덮어써서 이미 입력된 평가값을 날릴 위험이 있어(import
        # 파일엔 보통 C/I/A가 없음), 그 필드들만 건드리지 않는 이 경로를 쓴다.
        allowed_fields = ["hostname", "os_type", "mac_addr", "description", "zone_tag",
                           "hostname_source", "department", "owner_name"]
        if field_name not in allowed_fields: return False

        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
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
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM TBL_SCAN_RESULT WHERE asset_id=?", (asset_id,))
                cursor.execute("DELETE FROM TBL_OPEN_PORTS WHERE asset_id=?", (asset_id,))
                cursor.execute("DELETE FROM TBL_ASSETS WHERE asset_id=?", (asset_id,))
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Delete Asset {asset_id} Failed", e)
                return False
            finally:
                conn.close()