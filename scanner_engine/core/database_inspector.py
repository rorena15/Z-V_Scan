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
            return "('EMPTY_PW:root@%',)"  # 데모: 취약 사례 하나 노출
        if "anyhost" in s:
            return "('ANYHOST:root@%',)"
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

        for rule in rules:
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
