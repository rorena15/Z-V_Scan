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
from datetime import datetime
from utils.logger import AppLogger
from utils import rule_crypto

# [보안수준 계산] output/excel_report.py의 RULE_FILES/IMPORTANCE_WEIGHT와 동일 규칙
# (엔진 접두어, 중요도 가중치) - 대시보드 KPI가 Excel 리포트 표지의 "보안수준"과
# 같은 값을 내야 하므로 산식을 그대로 복제한다. rules/*.json이 바뀌면 이 둘을
# 같이 봐야 한다(기존에도 text_report.py/excel_report.py 두 곳에 이미 중복돼 있던
# 패턴이라 세 번째 사본을 추가하는 것- 공용 모듈로 뽑는 건 이번 범위 밖).
RULE_FILES = {
    "linux_rules.json": "",
    "windows_rules.json": "",
    "pc_rules.json": "",
    "mysql_rules.json": "MYSQL-",
    "postgresql_rules.json": "POSTGRESQL-",
    "mssql_rules.json": "MSSQL-",
    "oracle_rules.json": "ORACLE-",
    "web_rules.json": "",
}
IMPORTANCE_WEIGHT = {"상": 10, "중": 8, "하": 6}

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
            
            # 자산 테이블 컬럼 보정
            try:
                cursor.execute("ALTER TABLE TBL_ASSETS ADD COLUMN open_ports TEXT DEFAULT ''")
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
                cursor.execute("SELECT asset_id FROM TBL_ASSETS WHERE ip_addr = ?", (ip,))
                row = cursor.fetchone()

                if row:
                    asset_id = row[0]
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
        """C/I/A(각 1~3점) 합산으로 자산등급을 계산한다. 컨설턴트 엑셀 서식(별첨07 '점검대상'
        시트)의 실제 수식 `=IF(H+I+J<=2,"-",IF(sum>=7,"상",IF(sum>=5,"중","하")))`을 그대로
        옮긴 것 - 값이 하나라도 없으면(미평가) "-"를 반환한다."""
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
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                conn.commit()
                return True
            except Exception as e:
                AppLogger.log_error(f"[DB] Save Result Error", e)
                return False
            finally: conn.close()

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

    def _load_rule_importance_lookup(self):
        """vuln_code(엔진 접두어 포함) -> importance(상/중/하). 프로세스 생애주기 동안
        1회만 로드해 캐시한다(rules/*.json은 실행 중 안 바뀜)."""
        if self._rule_importance_cache is not None:
            return self._rule_importance_cache
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_path, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')

        lookup = {}
        for filename, prefix in RULE_FILES.items():
            path = os.path.join(rules_dir, filename)
            if not os.path.exists(path) and not os.path.exists(rule_crypto.get_enc_path(path)):
                continue
            try:
                data = rule_crypto.load_ruleset(path)
                for rule in data:
                    lookup[f"{prefix}{rule['code']}"] = rule.get("importance", "중")
            except Exception as e:
                AppLogger.log_error(f"[DB] Failed to load {filename} for security level", e)
        self._rule_importance_cache = lookup
        return lookup

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

        def _tally(round_picker):
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

        cur_security, cur_crit, cur_partial, _ = _tally(lambda rounds: max(rounds))
        prev_security, prev_crit, prev_partial, prev_has_any = _tally(_previous_round)

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

    def get_recent_sessions(self, limit=5):
        """[대시보드 - 최근 활동] session_id별로 묶어 언제/누가/몇 대를 스캔했는지
        최신순으로 반환한다. session_id가 없는(구버전 데이터 등) 결과는 제외한다.
        반환: [(session_id, operator, started_at, asset_count), ...]"""
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT session_id, MAX(operator), MIN(scan_date), COUNT(DISTINCT asset_id)
                    FROM TBL_SCAN_RESULT
                    WHERE session_id IS NOT NULL AND session_id != ''
                    GROUP BY session_id
                    ORDER BY MIN(scan_date) DESC
                    LIMIT ?
                """, (limit,))
                return cursor.fetchall()
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
        """
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
        allowed_fields = ["hostname", "os_type", "mac_addr", "description", "zone_tag", "hostname_source"]
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