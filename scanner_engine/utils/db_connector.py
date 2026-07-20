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

            conn.commit()
            conn.close()

    def save_asset(self, ip, hostname="Unknown", os_type="Unknown", open_ports="", mac_addr="-", vendor=""):
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
                            SET last_seen=?, hostname=?, os_type=?, open_ports=?, mac_addr=?
                            WHERE asset_id=?
                        """, (now, hostname, os_type, open_ports, mac_addr, asset_id))
                    else:
                        cursor.execute("""
                            UPDATE TBL_ASSETS
                            SET last_seen=?, hostname=?, os_type=?, open_ports=?
                            WHERE asset_id=?
                        """, (now, hostname, os_type, open_ports, asset_id))
                    # [수정] vendor는 지금까지 어떤 경로로도 DB에 저장되지 않고 있었다(누락 버그).
                    # mac_addr과 같은 규칙으로, 이번에 못 얻었으면("Unknown"/"Unknown Vendor") 이전에
                    # 알아낸 값을 덮어쓰지 않는다.
                    if vendor and vendor not in ["Unknown", "Unknown Vendor", "-"]:
                        cursor.execute("UPDATE TBL_ASSETS SET vendor=? WHERE asset_id=?", (vendor, asset_id))
                else:
                    cursor.execute("""
                        INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, open_ports, mac_addr, vendor, last_seen, memo)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (ip, hostname, os_type, open_ports, mac_addr, vendor, now, ""))
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
        with self._db_lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ip_addr, os_type, memo, mac_addr FROM TBL_ASSETS ORDER BY last_seen DESC")
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
                    SELECT asset_id, ip_addr, hostname, os_type, mac_addr, open_ports, last_seen, memo, zone_tag
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
        allowed_fields = ["hostname", "os_type", "mac_addr", "memo", "zone_tag"]
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