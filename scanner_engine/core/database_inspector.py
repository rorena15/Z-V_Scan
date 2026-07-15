# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import json
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from utils.secure_storage import SecureStorage
from utils.logger import AppLogger
from utils.throttle import AdaptiveThrottle
from utils.rule_judge import judge_rule
from utils.expert_profile import get_excluded_codes

DEFAULT_PORTS = {"mysql": 3306, "postgresql": 5432}


class DatabaseInspector:
    """MySQL / PostgreSQL 대상 KISA D-xx 항목 점검 (SSHInspector와 동일한 규칙 엔진 사용)"""

    def __init__(self, ip, username, engine, port=None, throttle=False, demo_mode=False):
        self.ip = ip
        self.username = username
        self.engine = engine  # "mysql" or "postgresql"
        self.port = port or DEFAULT_PORTS.get(engine)
        self.conn = None
        self.is_simulation = False
        self.throttle = throttle  # OT/저속 모드: 응답이 느려지면 자동으로 쿼리 간격을 늘림
        # [실전 안전장치] True일 때만 데모 IP를 가상 데이터로 처리한다. 기본값 False.
        self.demo_mode = demo_mode
        self.rules_path = self._get_rules_path()

    def _get_rules_path(self):
        filename = f"{self.engine}_rules.json"
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        external_path = os.path.join(base_dir, 'rules', filename)

        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
        else:
            internal_path = external_path

        if os.path.exists(external_path):
            return external_path
        elif internal_path and os.path.exists(internal_path):
            return internal_path
        return external_path

    def connect(self):
        if self.demo_mode and self.ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            self.is_simulation = True
            return True

        password = SecureStorage.get_credential(self.ip, self.username)
        if not password:
            AppLogger.log_error(f"[DB] Credentials not found for {self.ip}")
            return False

        try:
            if self.engine == "mysql":
                import pymysql
                self.conn = pymysql.connect(
                    host=self.ip, port=self.port, user=self.username,
                    password=password, connect_timeout=10
                )
            elif self.engine == "postgresql":
                import psycopg2
                self.conn = psycopg2.connect(
                    host=self.ip, port=self.port, user=self.username,
                    password=password, dbname="postgres", connect_timeout=10
                )
            else:
                return False
            del password
            return True
        except Exception as e:
            AppLogger.log_error(f"[DB] Connect failed for {self.ip} ({self.engine})", e)
            return False

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def execute_query(self, sql, timeout=15):
        if self.is_simulation:
            return self.get_mock_data(sql)
        if not self.conn:
            return ""
        try:
            cur = self.conn.cursor()
            if self.engine == "postgresql":
                cur.execute(f"SET statement_timeout = {timeout * 1000};")
            cur.execute(sql)
            rows = cur.fetchall()
            cur.close()
            return "\n".join(str(row) for row in rows)
        except Exception:
            return ""

    def get_mock_data(self, sql):
        # 데모/시연용 가짜 데이터 (실제 DB 미접속 상태에서도 결과를 보여주기 위함)
        s = sql.lower()
        if "empty_pw" in s:
            return "('EMPTY_PW:root@%',)"  # D-01: 데모 취약 사례 하나 노출

        if "anyhost" in s:
            return "('ANYHOST:root@%',)"  # D-10: 데모 취약 사례 하나 노출

        # D-08: 중요정보(주민번호/전화번호 등) 후보 컬럼 스캔 - MySQL/PostgreSQL 문법 차이로 구분
        if "sensitive_plaintext_candidate" in s:
            if "character varying" in s:
                return ""  # PostgreSQL 데모: 후보 컬럼 없음 -> 양호
            return "('SENSITIVE_PLAINTEXT_CANDIDATE:appdb.customers.ssn',)"  # MySQL 데모: 후보 컬럼 발견 -> 취약

        # D-20 (MySQL): 고아(orphan) DEFINER 존재 여부
        if "orphan_definer" in s:
            return "('ORPHAN_DEFINER:old_app@%',)"  # 데모: 취약 사례 하나 노출

        # D-20 (PostgreSQL): 비시스템 스키마 오브젝트 소유자 목록 (참고용, 판정에는 영향 없음 - MANUAL 고정)
        if "relowner" in s:
            return "('app_owner',)\n('postgres',)"

        # D-03 / D-05 (MySQL): criteria용 숫자 비교 sentinel 쿼리 (IF(... ) 형태)
        if "cast(variable_value as unsigned)" in s:
            if "default_password_lifetime" in s:
                return "('OK',)"  # 유효기간 설정됨 -> 해당 세부기준 충족
            if "validate_password.length" in s:
                return "('FAIL',)"  # 길이 미달 -> 해당 세부기준 미충족 (D-03 데모: 부분만족)
            if "password_history" in s:
                return "('FAIL',)"  # password_history=0 -> 미충족 (D-05 데모: 취약)
            if "password_reuse_interval" in s:
                return "('FAIL',)"

        # D-03 / D-05 (MySQL): 상단 표시용 원본 조회 (판정에는 영향 없음, criteria가 우선)
        if "global_variables" in s and "default_password_lifetime" in s:
            return "('default_password_lifetime', '90')\n('validate_password.length', '4')"
        if "global_variables" in s and "password_history" in s:
            return "('password_history', '0')\n('password_reuse_interval', '0')"

        # D-09 (MySQL/MariaDB): 로그인 실패 잠금 임계값 (connection_control 또는 MariaDB max_password_errors)
        if "connection_control_failed_connections_threshold" in s or "max_password_errors" in s:
            return "('OK',)"  # 데모: 1~5 사이로 설정됨 -> 양호

        # D-03 / D-05 / D-09 (PostgreSQL): shared_preload_libraries 로드 여부 (passwordcheck/auth_delay)
        if "shared_preload_libraries" in s:
            return "('passwordcheck,auth_delay',)"  # 데모: 둘 다 로드됨 -> 양호

        # D-21 (MySQL/PostgreSQL): GRANT OPTION 보유 현황 (판정은 MANUAL 고정, 증적만 제공)
        if "is_grantable" in s:
            return "('GRANTABLE:app_user',)"

        if "validate_password" in s:
            return ""
        if "have_ssl" in s:
            return "('have_ssl', 'YES')"
        if "ssl" in s:
            return "('ssl', 'on')"
        return ""

    def run_all_checks(self):
        """
        Return: {code: (status, detail, name, remediation, raw_output, kisa_code, importance)}
        """
        results = {}
        rules = []

        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception as e:
                AppLogger.log_error(f"Failed to load {self.engine} rules: {e}")
        else:
            AppLogger.log_error(f"{self.engine} rules file not found: {self.rules_path}")

        throttle = AdaptiveThrottle(enabled=self.throttle, base_delay=0.3)
        # [Phase 3: 전문가 모드] 사용자가 이 룰셋에서 제외한 코드는 아예 실행하지 않는다
        excluded_codes = get_excluded_codes(f"{self.engine}_rules.json")

        for rule in rules:
            if rule['code'] in excluded_codes:
                continue
            # [주의] MySQL/PostgreSQL 룰셋이 동일한 "D-xx" 코드를 공유하므로,
            # 한 호스트에 두 DB가 동시에 열려 있을 때 DB 저장 시 서로 덮어쓰지 않도록
            # 내부 키(code)는 엔진명을 붙여 구분하고, 화면 표시용 KISA 코드는 원본 그대로 둔다.
            code = f"{self.engine.upper()}-{rule['code']}"
            kisa_code = rule.get('kisa_code', rule.get('code', ''))
            cmd = rule['command']
            t0 = time.time()
            full_output = self.execute_query(cmd)
            # [OT/저속 모드] 응답이 느려질수록 다음 쿼리 전 대기시간을 자동으로 늘림
            throttle.wait(time.time() - t0)

            # 판정 로직 (단일조건: 취약/양호/수동검토, 다중조건(criteria): 취약/부분만족/양호, 공통: 해당없음)
            status, detail = judge_rule(rule, full_output, execute_fn=self.execute_query)

            results[code] = (
                status,
                detail,
                rule.get('name', code),
                rule.get('remediation', ''),
                full_output,
                kisa_code,
                rule.get('importance', '중')
            )

        return results
